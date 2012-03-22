#include <stdlib.h>
#include <string.h>

#include "stp_fs.h"
#include "stp_error.h"
#include "slab.h"
#include "list.h"
#include "bitmap.h"

static umem_cache_t *btree_bnode_slab = NULL; //size:32
static umem_cache_t *btree_bnode_item_slab = NULL; //size:2048

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
    
    
    printf("stp_bnode size:%u,stp_bnode_item size:%u\n",sizeof(struct stp_bnode),sizeof(struct stp_bnode_item));

    return 0;
 fail:
    {
        stp_errno = STP_MALLOC_ERROR;
        sem_destroy(&super->sem);
        pthread_mutex_destroy(&super->mutex);
        return -1;
    }
}

static int do_btree_super_read(struct stp_btree_info *super,off_t offset)
{
    return -1;
}

static int do_btree_super_sync(struct stp_btree_info *super)
{
    return -1;
}

static int do_btree_super_write(struct stp_btree_info * super,struct stp_bnode * bnode)
{
    return -1;
}

static struct stp_bnode * do_btree_super_search(struct stp_btree_info * super,u64 ino)
{
    return NULL;
}

static int do_btree_super_insert(struct stp_btree_info *super,u64 ino,size_t size,off_t offset)
{
    return -1;
}

static int do_btree_super_rm(struct stp_btree_info *super,u64 ino)
{
    return -1;
}

static int do_btree_super_destroy(struct stp_btree_info *super)
{
    /*destroy bnode and flush it into disk*/

    /*free all bnode in **/

    /*destroy cache*/
    umem_cache_destroy(btree_bnode_slab);
    umem_cache_destroy(btree_bnode_item_slab);
    sem_destroy(&super->sem);
    pthread_mutex_destroy(&super->mutex);
    
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

    






