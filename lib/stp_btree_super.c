#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>

#include "stp_fs.h"
#include "stp_error.h"
#include "slab.h"
#include "list.h"
#include "bitmap.h"

#define BTREE_OVERLAP (1<<0)

static umem_cache_t *btree_bnode_slab = NULL; //size:32,stp_inode_item:128,stp_inode:68
//can't allocate memory for btree_bnode_item_slab
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
    pthread_mutex_init(&bnode->lock,NULL);
    list_init(&bnode->lru);
    list_init(&bnode->dirty);
    list_init(&bnode->list);
    memset(bnode->ptrs,0,sizeof(struct stp_bnode *)*(CHILD(BTREE_DEGREE)));
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
    sb->root = bnode;
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

    #ifndef DEBUG
    
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
        
        /*
        if(!(bnode->item = umem_cache_alloc(btree_bnode_item_slab))) {
            umem_cache_free(btree_bnode_slab,bnode);
            stp_errno = STP_BNODE_MALLOC_ERROR;
            return NULL;
        }
        */
        if(!(bnode->item = calloc(1,sizeof(struct stp_bnode_item)))) {
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

        bnode->item->location.offset = off * sizeof(struct stp_bnode_item) + BTREE_SUPER_SIZE;
        bnode->item->location.flags = 0;
        bnode->item->location.count = sizeof(struct stp_bnode_item);
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
    //read from disk
    assert(offset > 0);
    
    if((bnode->item = (struct stp_bnode_item *)mmap(NULL,sizeof(struct stp_bnode_item),PROT_READ|PROT_WRITE,MAP_SHARED,sb->fd,0)) == MAP_FAILED) {
        stp_errno = STP_INDEX_READ_ERROR;
        return -1;
    }

    return 0;
}


static int do_btree_super_sync(struct stp_btree_info *sb)
{
    return -1;
}

static int do_btree_super_write(struct stp_btree_info * sb,struct stp_bnode * bnode)
{
    int res;

    assert(bnode->item != NULL);
    assert(bnode->item->location.count > 0);
    assert(bnode->item->location.offset > 0);
    
    res = pwrite(sb->fd,bnode->item,bnode->item->location.count,bnode->item->location.offset);
    if(res < 0) 
        stp_errno = STP_INDEX_WRITE_ERROR;
    return res;
}

/*
 * search the specified ino in item,if not found,return position of subtree inserted;
 * else return position of subtree inserted
 */
static int __binary_search(struct stp_bnode *item,u64 ino)
{
    int i = 0;
    struct stp_bnode *node;

    if(!item) return -1;

    if(item->flags & BTREE_ITEM_HOLE) {
        while((i < BTREE_KEY_MAX) && (item->key[i++] < ino)) 
            ;
        //because of duplicate key,it's found at first key
        if(!item->ptrs[i-1] && item->item->ptrs[i-1].offset) {
            if((node = item->tree->ops->allocate(item->tree,item->item->ptrs[i-1].offset))) 
                item->ptrs[i-1] = node;
            else 
                return -1;
        }

        if(item->ptrs[i-1] && item->ptrs[i-1]->key[BTREE_KEY_MAX-1] == ino) --i;

    } else {
        int l=0,h=item->nrkeys;
        
        while(l <= h)
        {
            i = (l + h)/2;
            if(item->key[i] < ino) l = i+1;
            else if(item->key[i] == ino) break;
            else h = i-1;
        }
        //point to subtree,larger than ino also is palced right subtree
        if(item->item->key[i] == ino) i++;
    }

    return i;
}

/*
 * return leaf node and the ptrs inserted less than ino or position of equal than ino
 */
static struct stp_bnode * __do_btree_search(struct stp_bnode *root,u64 ino,unsigned int *index)
{
    struct stp_bnode *node,*last;
    int i;
    
    node = root;

      
    do{
        i = __binary_search(node,ino);
        
        if(i < 0) return NULL;

        last = node;
        node = node->ptrs[i];
    }while(node && !(node->item->flags & BTREE_ITEM_LEAF));
    
    /*
    while(node && !(node->item->flags & BTREE_ITEM_LEAF)) {
        
        i = __binary_search(node,ino);
        if(i < 0) return NULL;

        node = node->ptrs[i];
    }
    */
    if(last->item->key[i-1] == ino)
        *index = i-1;

    return last;
}


static struct stp_bnode ** do_btree_super_search(struct stp_btree_info * sb,u64 ino)
{
    struct stp_bnode **n;
    struct stp_bnode *node;
    struct stp_bnode *tmp,*last;
    struct stp_bnode *array[MAX];
    int idx,len,i;
    
    
    len = 0;
    i = 0;
    tmp = NULL;
    
    memset(array,'\0',MAX*sizeof(struct stp_bnode *));

    node = __do_btree_search(sb->root,ino,&idx);
    if(!node) return NULL;

    last = node;
    //must be sure that all node associated with ino
    while(last && (idx == (BTREE_KEY_MAX-1)) && (last->item->key[idx]==ino)) {
        tmp = last->ptrs[idx+1];
        if(!tmp) { 
            //offset can't be 0,so it must read from disk
            if(last->item->ptrs[idx+1].offset && !(tmp = sb->ops->allocate(sb,last->item->ptrs[idx+1].offset)))
                return NULL;
        }

        if(tmp && tmp->item && (tmp->item->key[idx] == ino))
            array[len++] = tmp;

        last = tmp;
    }
    
    if(!(n =(struct stp_bnode **)calloc(len+2,sizeof(struct stp_bnode *)))) 
        return NULL;
    
    i = 0;
    n[i++] = node;
    while(i < len)
        n[i++] = array[i-1];
    
    return n;
}

//move from idx backward one place
static void __move_backward(struct stp_btree_item *item,int idx)
{
    int i;
    
    i = idx;
    
    if(item->flags & BTREE_ITEM_HOLE) {
        while(i<BTREE_KEY_MAX && !(item->key[i].flags & BTREE_KEY_DELETE)) i++;
    } else {
        i = item->nrkeys;
    }
    
    item->ptrs[i+1] = item->ptrs[i];
    for(;i!=idx;i--)
    {
        item->key[i] = item->key[i-1];
        item->ptrs[i] = item->ptrs[i-1];
    }
}


static int __do_btree_insert(struct stp_btree_info *sb,struct stp_bnode_off *off)
{
    struct stp_bnode *root = sb->root;
    struct stp_bnode *node;
    int i;
    
    node = __do_btree_search(root,off->ino,&i);
    
    
    //    if(node->item->key[i] == off->ino) { 
        if(node->item->nrkeys != BTREE_KEY_MAX) {
            if(node->item->key[i] == off->ino)
                i++;
            //move backward
            __move_backward(node->item,i+1);
            node->item->key[i+1].ino = off->ino;
            node->item->key[i+1].flags = off->flags;
            node->item->ptrs[i+1].ino = off->ino;
            node->item->ptrs[i+1].flags = off->flags;
            node->item->ptrs[i+1].len = off->len;
            node->item->ptrs[i+1].offset = off->offset;

        } else {
            //split  the node
            //insert key
        }
        
        
        // }
    
    
    
    return 0;
}

/*
 * store a key(ino),value(size,offset) into B+ tree
 *
 */
static int do_btree_super_insert(struct stp_btree_info *sb,u64 ino,size_t size,off_t offset)
{
    struct stp_bnode *root = sb->root;
    struct stp_bnode_off off;
    
    assert(ino !=0 && size >0 && offset > 0);
    
    off.ino = ino;
    off.flags = BTREE_OVERLAP;
    off.len = size;
    off.offset = offset;
    
    return __do_btree_insert(sb,&off);
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
        pthread_mutex_destroy(&bnode->lock);
        bnode->ops->destroy(bnode);
        if(bnode->flags & STP_INDEX_BNODE_CREAT) {
            free(bnode->item);
            // umem_cache_free(btree_bnode_item_slab,bnode->item);
        }
        else
        {
            if((&sb->super->root) != bnode->item) {
                munmap(bnode->item,sizeof(struct stp_bnode_item));
            }
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



