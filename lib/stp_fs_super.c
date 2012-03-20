
#include <stdlib.h>
#include <semaphore.h>
#include <pthread.h>
#include <string.h>

#include "stp_fs.h"
#include "stp_error.h"
#include "slab.h"
#include "list.h"
#include "stp.h"

static umem_cache_t *fs_inode_slab = NULL;

static int do_fs_super_init(struct stp_fs_info * super) 
{
    super->transid = 0;
    sem_init(&super->sem,0,1);
    pthread_mutex_init(&super->mutex,NULL);
    list_init(&super->inode_list);
    list_init(&super->inode_lru);
    list_init(&super->dirty_list);
    
    if(super->mode & STP_FS_CREAT) {
        super->super->magic = STP_FS_MAGIC;
        super->super->flags = 0;
        super->super->total_bytes = FS_SUPER_SIZE;
        super->super->bytes_used = FS_SUPER_SIZE;
        super->super->bytes_hole  = 0;
        super->super->nritems = 0;
        super->super->nrdelete = 0;
        memset(&super->super->root,0,sizeof(struct stp_inode_item));
        //fsync(super->fd);
        //    printf("update fs super block.\n");
    }
    printf("magic:%x\n",super->super->magic);
    
    if((fs_inode_slab = umem_cache_create("stp_inode_slab",\
        sizeof(struct stp_inode),ALIGN4,SLAB_NOSLEEP,NULL,NULL)) == NULL)
    {
        stp_errno = STP_MALLOC_ERROR;
        sem_destroy(&super->sem);
        pthread_mutex_destroy(&super->mutex);
        return -1;
    }
    
    return 0;
}

static struct stp_inode * do_fs_super_allocate(struct stp_fs_info * super)
{
    return NULL;
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

    
