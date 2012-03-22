
#include <stdlib.h>
#include <semaphore.h>
#include <pthread.h>
#include <string.h>

#include "stp_fs.h"
#include "stp_error.h"
#include "slab.h"
#include "list.h"
#include "stp.h"
#include "rb_tree.h"

static umem_cache_t *fs_inode_slab = NULL; //size 32
static umem_cache_t *fs_inode_item_slab = NULL; //size 128

static void init_root(struct stp_fs_info *sb,struct stp_fs_inode_item *inode)
{
    
}


static int do_fs_super_init(struct stp_fs_info * super) 
{
    super->transid = 0;
    sem_init(&super->sem,0,1);
    pthread_mutex_init(&super->mutex,NULL);
    list_init(&super->inode_list);
    list_init(&super->inode_lru);
    list_init(&super->dirty_list);
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
        super->super->nritems = 0;
        super->super->ino = 1;
        super->super->nrdelete = 0;
        memset(&super->super->root,0,sizeof(struct stp_inode_item));
        init_root(super,&super->super->root);
        //fsync(super->fd);
        //    printf("update fs super block.\n");
    }

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

static struct stp_inode * do_fs_super_allocate(struct stp_fs_info * super,off_t offset)
{
    strut stp_inode * inode = NULL;

    if(!(inode = umem_cache_alloc(stp_inode_slab)))
    {    
        stp_errno = STP_MALLOC_ERROR;
        return NULL;
    }
    
    inode->flags = 0;
    inode->ref = 0;
    list_init(&inode->lru);
    list_init(&inode->dirty);
    list_init(&inode->list);
    //init_rb_node(&inode->node,1);
    inode->fs = super;
    inode->ops = &inode_operations;
    
    if(offset && super->read(super,inode,offset)) {   
        umem_cache_free(stp_inode_slab,inode);
        return -1;
    }
    
    if(1 == __sync_fetch_and_add(&super->super->ino,0)) {
        inode->item = &(super->super->root);
    }
    else {
    if(!(inode->item = umem_cache_alloc(fs_inode_item_slab))) {
        umem_cache_free(stp_inode_slab,inode);
        stp_errno = STP_INODE_MALLOC_ERROR;
        return -1;
    }
    }
    
    inode->flags = STP_FS_INODE_CREAT;

    inode->ino = __sync_fetch_and_add(&super->super->ino,1);
    init_rb_node(&inode->node,inode->ino);
    
    pthread_mutex_lock(&super->mutex);

    super->super->total_bytes += sizeof(struct stp_fs_inode_item);
    super->super->bytes_used += sizeof(struct stp_fs_inode_item);
    super->super->nritems ++;

    pthread_mutex_unlock(&super->mutex);

    inode->ops->init(inode);
    
    return inode;
}

static int do_fs_super_alloc_page(struct stp_info *inode,off_t offset)
{
    return -1;
}

static int do_fs_super_release_page(struct stp_inode *inode)
{
    return -1;
}

static int do_fs_super_free(struct stp_fs_info *super,struct stp_inode *inode)
{
    return -1;
}

static struct stp_inode* do_fs_super_read(struct stp_fs_info * super,off_t offset)
{
    return NULL;
}

static int do_fs_super_sync(struct stp_fs_info *super)
{
    return -1;
}

static int do_fs_super_write(struct stp_fs_info *super,struct stp_inode *inode)
{
    return -1;
}

static int do_fs_super_destroy(struct stp_fs_info *super)
{
    
    /**destroy inode and flush it into disk*/
    
    /**free all inode in inode_list*/

    /* destroy cache*/
    umem_cache_destroy(fs_inode_slab);
    umem_cache_destroy(fs_inode_item_slab);
    sem_destroy(&super->sem);
    pthread_mutex_destroy(&super->mutex);
    return 0;
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

    
