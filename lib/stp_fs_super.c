#include <stdlib.h>
#include <semaphore.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>

#include "stp_fs.h"
#include "stp_error.h"
#include "slab.h"
#include "list.h"
#include "stp.h"
#include "rb_tree.h"

static umem_cache_t *fs_inode_slab = NULL; //size 32
static umem_cache_t *fs_inode_item_slab = NULL; //size 128

static struct stp_inode * __get_stp_inode(struct stp_fs_info *sb);

#define FS_ITEM_ENTRY (1<<0)


static void __set_fs_header(struct stp_header *dest,const struct stp_header *src);

static void init_root(struct stp_fs_info *sb,struct stp_inode_item *_inode)
{
    struct stp_inode *inode;
    
    if(!(inode = __get_stp_inode(sb))) return;
    
    inode->item = _inode;
    
    if(!inode->item->ino) inode->item->ino = 1;
    
    //location for root inode
    inode->item->location.offset = sizeof(struct stp_fs_super) - sizeof(struct stp_inode_item);
    inode->item->location.count = sizeof(struct stp_inode_item);
    inode->item->location.flags = 0;
    inode->item->location.nritems = 0;
    
    init_rb_node(&inode->node,inode->item->ino);
    inode->ops->init(inode);
    inode->item->mode |= S_IFDIR;
    rb_tree_insert(&sb->root,&inode->node);
    list_move(&sb->inode_list,&inode->list);
}


static int do_fs_super_init(struct stp_fs_info * super) 
{
    super->transid = 0;
    super->active = 0;
    sem_init(&super->sem,0,1);
    pthread_mutex_init(&super->mutex,NULL);
    list_init(&super->inode_list);
    list_init(&super->inode_lru);
    list_init(&super->dirty_list);
    list_init(&super->inode_list);
    init_rb_root(&super->root,NULL);

    if((fs_inode_slab = umem_cache_create("stp_inode_slab",\
        sizeof(struct stp_inode),ALIGN4,SLAB_NOSLEEP,NULL,NULL)) == NULL)    
        goto fail;
    
    if((fs_inode_item_slab = umem_cache_create("stp_inode_item_slab",\
                                               sizeof(struct stp_inode_item),ALIGN4,SLAB_NOSLEEP,NULL,NULL)) == NULL) {
        umem_cache_destroy(fs_inode_slab);
        goto fail;
    }


    if(super->mode & STP_FS_CREAT) {
        super->super->magic = STP_FS_MAGIC;
        super->super->flags = 0;
        super->super->total_bytes = FS_SUPER_SIZE;
        super->super->bytes_used = FS_SUPER_SIZE;
        super->super->bytes_hole  = 0;
        super->super->nritems = 1;
        super->super->ino = 1;
        super->super->nrdelete = 0;
        memset(&super->super->root,0,sizeof(struct stp_inode_item));
    }

    init_root(super,&super->super->root);
    
    super->offset = lseek(super->fd,0,SEEK_END);
    
    printf("magic:%x,stp_inode size:%u,stp_inode_item size:%u,dir_item:%u\n",\
           super->super->magic,sizeof(struct stp_inode),sizeof(struct stp_inode_item),sizeof(struct stp_dir_item));
    
    return 0;
 fail:
    {
        stp_errno = STP_MALLOC_ERROR;
        sem_destroy(&super->sem);
        pthread_mutex_destroy(&super->mutex);
        return -1;
    }

}

static struct stp_inode * __get_stp_inode(struct stp_fs_info *super)
{
    struct stp_inode * inode = NULL;
    
    if(!(inode = umem_cache_alloc(fs_inode_slab)))
    {    
        stp_errno = STP_MALLOC_ERROR;
        return NULL;
    }
    
    memset(inode,0,sizeof(*inode));
    
    inode->flags = 0;
    inode->ref = 0;
    pthread_mutex_init(&inode->lock,NULL);
    list_init(&inode->lru);
    list_init(&inode->dirty);
    list_init(&inode->list);
    //init_rb_node(&inode->node,1);
    inode->fs = super;
    inode->ops = &inode_operations;

    return inode;
}


static struct stp_inode * do_fs_super_allocate(struct stp_fs_info * super,off_t offset)
{
    struct stp_inode * inode = NULL;

    assert(offset >= 0);

    if((inode = __get_stp_inode(super)) == NULL) 
        return NULL;

    if(offset)
    {    
        if(super->ops->read(super,inode,offset)) {   
            umem_cache_free(fs_inode_slab,inode);
            return NULL;
        }
    }
    else {
    if(!(inode->item = umem_cache_alloc(fs_inode_item_slab))) {
        umem_cache_free(fs_inode_slab,inode);
        stp_errno = STP_INODE_MALLOC_ERROR;
        return NULL;
    }

    off_t offset;
    inode->flags = STP_FS_INODE_DIRTY | STP_FS_INODE_CREAT;
    
    memset(inode->item,0,sizeof(struct inode_item));
    
    pthread_mutex_lock(&super->mutex);
    list_move(&super->dirty_list,&inode->dirty);
    inode->item->ino = super->super->ino++;
    super->super->total_bytes += sizeof(struct stp_inode_item);
    super->super->bytes_used += sizeof(struct stp_inode_item);
    super->super->nritems ++;
    offset = super->offset;
    super->offset += sizeof(struct stp_inode_item);
    pthread_mutex_unlock(&super->mutex);

    inode->item->location.offset = offset;
    inode->item->location.count = sizeof(struct stp_inode_item);
    inode->item->location.flags = 0;
    inode->item->location.nritems = 0;

    }

    init_rb_node(&inode->node,inode->item->ino);
    inode->ops->init(inode);

    pthread_mutex_lock(&super->mutex);

    rb_tree_insert(&super->root,&inode->node);
    super->active++;
    list_move(&super->inode_list,&inode->list);
    //lru replacement in here
    
    pthread_mutex_unlock(&super->mutex);
    
    return inode;
}

/*
 * allocate two pages for dentry
 */
static int do_fs_super_alloc_pages(struct stp_inode *inode)
{
    u32 nrentries = inode->nritem;
    struct stp_header location;
    struct stp_fs_info *sb = inode->fs;
    
    memset(&location,0,sizeof(location));
    
    pthread_mutex_lock(&sb->mutex);
    
    location.offset = sb->offset;
    location.count = 8*1024;
    sb->offset += location.count;
    
    pthread_mutex_unlock(&sb->mutex);
    
    assert(inode->item && inode->item->mode & S_IFDIR);
    //allocate first page
    if(nrentries == 0) {
        __set_fs_header(&inode->entry[0],&location);
        return 0;
    }
    
    
    return -1;
}

static int do_fs_super_release_pages(struct stp_inode *inode)
{
    return -1;
}

static int do_fs_super_free(struct stp_fs_info *super,struct stp_inode *inode)
{
    return -1;
}

static int do_fs_super_read(struct stp_fs_info * sb,struct stp_inode *inode,off_t offset)
{
    int res;
    size_t size;
    
    assert(offset > 0);
    //allcate stp_inode_item,then pread
    if(!(inode->item = umem_cache_alloc(fs_inode_item_slab))) {
        stp_errno = STP_INODE_MALLOC_ERROR;
        return -1;
    }
        
    res = pread(sb->fd,inode->item,sizeof(struct stp_inode_item),offset);
    if(res != sizeof(struct stp_inode_item)) {
        stp_errno = STP_META_READ_ERROR;
        return -1;
    }
        
    inode->flags = STP_FS_INODE_CREAT;
        
    return 0;
}

static int do_fs_super_sync(struct stp_fs_info *super)
{
    return -1;
}

static int do_fs_super_write(struct stp_fs_info *super,struct stp_inode *inode)
{
    int res;

    assert(inode->item != NULL);
    assert(inode->item->location.count > 0);
    assert(inode->item->location.offset > 0);
    
    res = pwrite(super->fd,inode->item,inode->item->location.count,inode->item->location.offset);
    if(res < 0) 
        stp_errno = STP_META_WRITE_ERROR;

    return res;    
}

static int do_fs_super_destroy(struct stp_fs_info *super)
{
    struct stp_inode *inode,*next;

    /* flush dirty inode to disk */
    list_for_each_entry_del(inode,next,&super->dirty_list,dirty) {
        if(inode->item->ino != 1)
            super->ops->write(super,inode);
        list_del_element(&inode->dirty);
    }
    
    /** destroy bnode and flush it into disk*/
    fsync(super->fd);

    /**free all inode in inode_list*/
    list_for_each_entry_del(inode,next,&super->inode_list,list)
    {
        rb_tree_erase(&super->root,&inode->node);
        list_del_element(&inode->list);
        pthread_mutex_destroy(&inode->lock);
        inode->ops->destroy(inode);
        if(inode->flags & STP_FS_INODE_CREAT)
            umem_cache_free(fs_inode_item_slab,inode->item);
        else 
        {
            if(inode->item->ino != 1)
                munmap(inode->item,sizeof(struct stp_inode_item));
        }
        
        umem_cache_free(fs_inode_slab,inode);
    }

    /**destroy cache*/
    umem_cache_destroy(fs_inode_slab);
    umem_cache_destroy(fs_inode_item_slab);
    sem_destroy(&super->sem);
    pthread_mutex_destroy(&super->mutex);
    return 0;
}

static void __set_fs_header(struct stp_header *dest,const struct stp_header *src)
{
    dest->offset = src->offset;
    dest->count = src->offset;
    dest->flags = src->flags;
    dest->nritems = src->nritems;
}


const struct stp_fs_operations stp_fs_super_operations = {
    .init = do_fs_super_init,
    .allocate = do_fs_super_allocate,
    .free = do_fs_super_free,
    .read = do_fs_super_read,
    .sync = do_fs_super_sync,
    .write = do_fs_super_write,
    .destroy = do_fs_super_destroy,
};
