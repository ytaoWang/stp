#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "stp_fs.h"
#include "stp_error.h"
#include "slab.h"
#include "list.h"
#include "bitmap.h"


static umem_cache_t *btree_bnode_slab = NULL; //size:32,stp_inode_item:128,stp_inode:68
static umem_cache_t *btree_bnode_item_slab = NULL; //size:2048,dir_item:140

static struct stp_bnode * __get_btree_bnode(struct stp_btree_info * sb)
{
    struct stp_bnode *bnode = NULL;
    
    if(!(bnode = (struct stp_bnode *)umem_cache_alloc(btree_bnode_slab))) {
        stp_errno = STP_MALLOC_ERROR;
        return NULL;
    }
    
    memset(bnode,0,sizeof(struct stp_bnode));
    
    bnode->flags = 0;
    bnode->ref = 0;
    list_init(&bnode->lru);
    list_init(&bnode->dirty);
    list_init(&bnode->list);
    bnode->tree = sb;
    bnode->ops = &bnode_operations;
    
    return bnode;
}


static int __btree_init_root(struct stp_btree_info *sb,struct stp_bnode_item *item)
{
    struct stp_bnode *bnode;
    
    if(!(bnode = __get_btree_bnode(sb))) return -1;
    
    bnode->item = item;
    bnode->tree = sb;
    bnode->flags = 0;
    bnode->ref = 0;
    list_init(&bnode->lru);
    list_init(&bnode->dirty);
    list_init(&bnode->list);
    
    list_move(&sb->node_list,&bnode->list);
    
    return 0;
}


static int do_btree_super_init(struct stp_btree_info * super)
{
    super->transid = 0;
    sem_init(&super->sem,0,1);
    pthread_mutex_init(&super->mutex,NULL);
    list_init(&super->node_list);
    list_init(&super->node_lru);
    list_init(&super->dirty_list);
    
    if(super->mode & STP_FS_CREAT) {
        super->super->magic = STP_FS_MAGIC;
        super->super->flags = 0;
        super->super->total_bytes = BTREE_SUPER_SIZE;
        super->super->nritems = 0;
        bitmap_clean(super->super->bitmap,BITMAP_ENTRY * sizeof(u32));
        //set special flag for "satellite"
        bitmap_set(super->super->bitmap,0);
        //must allocate for index file ahead
        if(ftruncate(super->fd,BTREE_TOTAL_SIZE) < 0) {
            stp_errno = STP_INDEX_CREAT_ERROR;
            sem_destroy(&super->sem);
            pthread_mutex_destroy(&super->mutex);
            return -1;
        }

        super->super->total_bytes = BTREE_TOTAL_SIZE;
        memset(&super->super->root,0,sizeof(struct stp_bnode_item));
    }
    
    if((btree_bnode_slab = umem_cache_create("stp_bnode_slab",sizeof(struct stp_bnode),\
                                             ALIGN4,SLAB_NOSLEEP,NULL,NULL)) == NULL)
        goto fail;
    
    if((btree_bnode_item_slab = umem_cache_create("stp_bnode_item_slab",sizeof(struct stp_bnode_item),\
                                                  ALIGN4,SLAB_NOSLEEP,NULL,NULL)) == NULL) {
        umem_cache_destroy(btree_bnode_item_slab);
        goto fail;
    }
    
    __btree_init_root(super,&super->super->root);

    #ifdef DEBUG
    
    printf("stp_bnode size:%u,stp_bnode_item size:%u\n",sizeof(struct stp_bnode),sizeof(struct stp_bnode_item));
    
    #endif

    return 0;
 fail:
    {
        stp_errno = STP_MALLOC_ERROR;
        sem_destroy(&super->sem);
        pthread_mutex_destroy(&super->mutex);
        return -1;
    }
}

static struct stp_bnode *do_btree_super_allocate(struct stp_btree_info *super,off_t offset)
{
    struct stp_bnode *bnode;
    
    if(!(bnode = __get_btree_bnode(super))) return NULL;
    
    assert(offset >= 0);
    
    if(offset) {
        if(super->ops->read(super,bnode,offset)) {
            umem_cache_free(btree_bnode_slab,bnode);
            return NULL;
        }
    } else {
        
        if(super->super->nritems == BITMAP_SIZE) {
            stp_errno = STP_INDEX_NO_SPACE;
            umem_cache_free(btree_bnode_slab,bnode);
            return NULL;
        }
        
        
        if(!(bnode->item = umem_cache_alloc(btree_bnode_item_slab))) {
            umem_cache_free(btree_bnode_slab,bnode);
            stp_errno = STP_BNODE_MALLOC_ERROR;
            return NULL;
        }
        
        bnode->flags = STP_INDEX_BNODE_DIRTY | STP_INDEX_BNODE_CREAT;
        
        pthread_mutex_lock(&super->mutex);
        
        //allocation from bitmap
        u32 off = bitmap_find_first_zero_bit(super->super->bitmap,0,BITMAP_SIZE);
        if(!off) {
            stp_errno = STP_BNODE_MALLOC_ERROR;
            umem_cache_free(btree_bnode_slab,bnode);
            return NULL;
        }
        bitmap_set(super->super->bitmap,off);
        
        super->super->total_bytes += sizeof(struct stp_bnode_item);
        list_move(&super->dirty_list,&bnode->dirty);
        super->super->nritems ++;
        pthread_mutex_unlock(&super->mutex);

        bnode->item->location.start = off * sizeof(struct stp_bnode_item) + BTREE_SUPER_SIZE;
        bnode->item->location.flags = 0;
        bnode->item->location.offset = sizeof(struct stp_bnode_item);
        bnode->item->location.nritems = 0;
    }

    pthread_mutex_lock(&super->mutex);
    super->active++;
    list_move(&super->node_list,&bnode->list);
    //lru replcement policy in here
    pthread_mutex_unlock(&super->mutex);

    return bnode;
}
    

static int do_btree_super_read(struct stp_btree_info *sb,struct stp_bnode * bnode,off_t offset)
{
    return -1;
}

static int do_btree_super_sync(struct stp_btree_info *sb)
{
    return -1;
}

static int do_btree_super_write(struct stp_btree_info * sb,struct stp_bnode * bnode)
{
    return -1;
}

static struct stp_bnode * do_btree_super_search(struct stp_btree_info * sb,u64 ino)
{
    return NULL;
}

static int do_btree_super_insert(struct stp_btree_info *sb,u64 ino,size_t size,off_t offset)
{
    struct stp_bnode * bnode;
    
    return -1;
}

static int do_btree_super_rm(struct stp_btree_info *sb,u64 ino)
{
    return -1;
}

static int do_btree_super_destroy(struct stp_btree_info *sb)
{
    struct stp_bnode *bnode,*next;
    /*destroy bnode and flush it into disk*/
    list_for_each_entry_del(bnode,next,&sb->dirty_list,dirty) {
        sb->ops->write(sb,bnode);
        list_del_element(&bnode->dirty);
    }
    
    /*fsync into index file*/
    fsync(sb->fd);
    /*free all bnode in **/
    list_for_each_entry_del(bnode,next,&sb->node_list,list) {
        list_del_element(&bnode->list);
        bnode->ops->destroy(bnode);
        if(bnode->flags & STP_INDEX_BNODE_CREAT) {
            umem_cache_free(btree_bnode_item_slab,bnode->item);
        }
        
        umem_cache_free(btree_bnode_slab,bnode);
    }
    /*destroy cache*/
    umem_cache_destroy(btree_bnode_slab);
    umem_cache_destroy(btree_bnode_item_slab);
    sem_destroy(&sb->sem);
    pthread_mutex_destroy(&sb->mutex);
    return 0;
}

const struct stp_btree_operations stp_btree_super_operations = {
    .init = do_btree_super_init,
    .read = do_btree_super_read,
    .sync = do_btree_super_sync,
    .write = do_btree_super_write,
    .search = do_btree_super_search,
    .insert = do_btree_super_insert,
    .rm  = do_btree_super_rm,
    .destroy = do_btree_super_destroy,
};



