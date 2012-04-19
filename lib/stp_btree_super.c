#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#include "stp_fs.h"
#include "stp_error.h"
#include "slab.h"
#include "list.h"
#include "bitmap.h"

#define BTREE_DEGREE_TEST  2
#define BTREE_LEFT (BTREE_DEGREE_TEST - 1)
#define BTREE_RIGHT (BTREE_DEGREE_TEST)
#define BTREE_KEY_MAX_TEST (KEY(BTREE_DEGREE_TEST))
#define BTREE_CHILD_MAX_TEST (CHILD(BTREE_DEGREE_TEST))
#define BTREE_KEY_MIN_TEST (MIN_KEY(BTREE_DEGREE_TEST))
#define BTREE_CHILD_MIN_TEST (MIN_CHILD(BTREE_DEGREE_TEST))
#define BTREE_MAX_LEVEL 64

static umem_cache_t *btree_bnode_slab = NULL; //size:32,stp_inode_item:128,stp_inode:68
//can't allocate memory for btree_bnode_item_slab
static umem_cache_t *btree_bnode_item_slab = NULL; //size:2048,dir_item:140

static void __btree_node_destroy(struct stp_bnode *node);
static int __btree_delete_entry(struct stp_btree_info *sb,struct stp_bnode **hist,int size,int index);
static inline int is_root(const struct stp_btree_info *sb,const struct stp_bnode *node);
static inline void set_root(struct stp_btree_info *sb,struct stp_bnode *node);


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
    memset(bnode->ptrs,0,sizeof(struct stp_bnode *)*(CHILD(BTREE_DEGREE_TEST)));
    bnode->tree = sb;
    bnode->ops = &bnode_operations;
    bnode->parent = NULL;
    
    return bnode;
}


static int __btree_init_root(struct stp_btree_info *sb,const struct stp_header *location,int creat)
{
    struct stp_bnode *node;
    
    if(!(node = sb->ops->allocate(sb,location->offset))) return -1;
 
    if(creat) {
        node->item->level = 1;
        sb->super->root.offset = node->item->location.offset;
        sb->super->root.count = node->item->location.count;
        sb->super->root.flags = node->item->location.flags;
        sb->super->root.nritems = node->item->location.nritems;
    }
    
    set_root(sb,node);

    //    printf("%s:%d,flags:%d\n",__FUNCTION__,__LINE__,sb->root->item->flags);

    return 0;
}


static int __btree_init_root2(struct stp_btree_info *sb,const struct stp_bnode_item *item,int creat)
{
    struct stp_bnode *bnode;
    
    if(!(bnode = __get_btree_bnode(sb))) return -1;
    
    bnode->tree = sb;
    sb->root = bnode;
    bnode->flags = 0;
    bnode->ref = 0;
    list_init(&bnode->lru);
    list_init(&bnode->dirty);
    list_init(&bnode->list);
    if(creat)
      bnode->item->flags |= BTREE_ITEM_LEAF;
    list_move(&sb->node_list,&bnode->list);
    printf("%s:%d,flags:%d\n",__FUNCTION__,__LINE__,item->flags);
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
    
    //if(!(super->mode & STP_FS_CREAT)) {
      	printf("function:%s,line:%d,super:%p,super->super:%p,flags:%p\n",__FUNCTION__,__LINE__,super,super->super,&super->super->root);
        //}
    
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
        //memset(&super->super->root,0,sizeof(struct stp_bnode_item));
        //printf("function:%s,flags:%d,nrkeys:%llu\n",__FUNCTION__,super->super->root.flags,super->super->root.offset);
        //super->super->root.nrkeys = 1;
        //super->super->root.flags = BTREE_ITEM_LEAF;
        super->super->root.offset = 0;
        super->super->root.count = sizeof(struct stp_bnode_item);
        super->super->root.flags = 0;
        super->super->root.nritems = 0;
        printf("FS_FS_CREAT\n");
    }
    
    //printf("stp_bnode flags:%d\n",super->super->root.flags);
    
    if((btree_bnode_slab = umem_cache_create("stp_bnode_slab",sizeof(struct stp_bnode),\
                                             ALIGN4,SLAB_NOSLEEP,NULL,NULL)) == NULL)
        goto fail;
    
    if((btree_bnode_item_slab = umem_cache_create("stp_bnode_item_slab",sizeof(struct stp_bnode_item),\
                                                  ALIGN4,SLAB_NOSLEEP,NULL,NULL)) == NULL) {
        umem_cache_destroy(btree_bnode_item_slab);
        goto fail;
    }
    
    if(__btree_init_root(super,&super->super->root,super->mode & STP_FS_CREAT)<0)
        goto fail;
    

    #ifndef DEBUG
    
    //printf("stp_bnode size:%u,stp_bnode_item size:%u,super size:%d\n",sizeof(struct stp_bnode),sizeof(struct stp_bnode_item), \
           sizeof(struct stp_btree_super));
    
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
        super->off = off;
        super->super->total_bytes += sizeof(struct stp_bnode_item);
        list_move(&super->dirty_list,&bnode->dirty);
        super->super->nritems ++;
        pthread_mutex_unlock(&super->mutex);

        bnode->item->location.offset = off * sizeof(struct stp_bnode_item) + BTREE_SUPER_SIZE;
        bnode->item->location.flags = 0;
        bnode->item->flags = BTREE_ITEM_LEAF;
        bnode->item->nrkeys = 0;
        bnode->item->nrptrs = 0;
        bnode->item->level = 1;
        bnode->item->location.count = sizeof(struct stp_bnode_item);
        bnode->item->location.nritems = 1;
        memset(&bnode->item->parent,0,sizeof(struct stp_header));
    }

    pthread_mutex_lock(&super->mutex);
    super->active++;
    list_move(&super->node_list,&bnode->list);
    //lru replcement policy in here
    pthread_mutex_unlock(&super->mutex);

    printf("%s:%d,active:%u,offset:%llu,count:%llu,SUPER:%u\n",__FUNCTION__,__LINE__,super->active,\
               bnode->item->location.offset,bnode->item->location.count,BTREE_SUPER_SIZE);
    
    return bnode;
}
    

static int do_btree_super_read(struct stp_btree_info *sb,struct stp_bnode * bnode,off_t offset)
{
    //read from disk
    assert(offset > 0);
    
    //    printf("%s:%d,%lu\n",__FUNCTION__,__LINE__,offset);
    
    //mmap function offset must be multiple of pagesize
    if(!(offset % getpagesize())) {
        if((bnode->item = (struct stp_bnode_item *)mmap(NULL,sizeof(struct stp_bnode_item),PROT_READ|PROT_WRITE,\
                                                        MAP_SHARED,sb->fd,offset)) == MAP_FAILED) {
            stp_errno = STP_INDEX_READ_ERROR;
            fprintf(stderr,"read index node from file error:%s\n",strerror(errno));
            return -1;
        }
        printf("%s:%d,%lu in mmap\n",__FUNCTION__,__LINE__,offset);
    } else {
        if(!(bnode->item = calloc(1,sizeof(struct stp_bnode_item)))) {
            stp_errno = STP_INDEX_READ_ERROR;
            return -1;
        }
        
        if(pread(sb->fd,bnode->item,sizeof(struct stp_bnode_item),offset) != sizeof(struct stp_bnode_item)) {
            stp_errno = STP_INDEX_READ_ERROR;
            free(bnode->item);
            return -1;
        }
        
        printf("%s:%d,%lu,in pread\n",__FUNCTION__,__LINE__,offset);
        bnode->flags = STP_INDEX_BNODE_CREAT;
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

    if(!bnode->item->nrkeys && !is_root(sb,bnode)) {
        fprintf(stderr,"[WARNING]:bnode:%p is empty!\n",bnode);
        return 0;
    }
    
    assert(bnode->item != NULL);
    printf("%s:%d,count:%llu,offset:%llu,ino:%llu,node:%p\n",__FUNCTION__,__LINE__,bnode->item->location.count, \
           bnode->item->location.offset,bnode->item->key[0].ino,bnode);
    assert(bnode->item->location.count > 0);
    assert(bnode->item->location.offset > 0);
    
    res = pwrite(sb->fd,bnode->item,bnode->item->location.count,bnode->item->location.offset);
    if(res < 0) 
        stp_errno = STP_INDEX_WRITE_ERROR;
    
    //    printf("%s:%d,res:%d,count:%llu,offset:%llu\n",__FUNCTION__,__LINE__,res,bnode->item->location.count,bnode->item->location.offset);
    
    return res;
}

/*
 * search the specified ino in item,if not found,return position of subtree inserted;
 * else return position of subtree found
 */
static int __binary_search(struct stp_bnode *item,u64 ino,int *found)
{
    int i = 0;
    struct stp_bnode *node;
    
    *found = 0;
    
    if(!item) return -1;
    if(!item->item->nrkeys) {
        *found = 0;
        return 0;
    }
    
    if(item->item->flags & BTREE_ITEM_HOLE) {
        while((i < BTREE_KEY_MAX_TEST) && ((item->item->key[i].ino != 0) && item->item->key[i].ino < ino)) 
            i++;

        //because of duplicate key,it's found at first key
        if(i > 0 && !item->ptrs[i-1] && item->item->ptrs[i-1].offset) {
            if((node = item->tree->ops->allocate(item->tree,item->item->ptrs[i-1].offset))) 
                item->ptrs[i-1] = node;
            else 
                return -1;
        }

        if(i > 0 && item->ptrs[i-1] && item->ptrs[i-1]->item->key[BTREE_KEY_MAX_TEST-1].ino == ino) {
            --i;
            *found = 1;
        }
 
        if(item->item->key[i].ino == ino) *found = 1;
        //  printf("%s:%d in BTREE_ITEM_HOLE(%d),offset:%d\n",__FUNCTION__,__LINE__,item->flags,i);
        
    } else {
        int l=0,h=item->item->nrkeys-1;

        while(l <= h)
        {
            i = (l + h)/2;
            if(item->item->key[i].ino < ino) l = i+1;
            else if((item->item->key[i].ino == ino) || (item->item->key[i].ino == 0)) break;
            else h = i-1;
        }

        //i = l;
        //point to subtree,larger than ino also is palced right subtree
        if(item->item->key[i].ino != ino) {
            //            if(item->item->key[i].ino < ino) i++;
            *found = 0;
            i = l;
        } else 
            *found = 1;
        //if(i == BTREE_KEY_MAX_TEST) i = BTREE_KEY_MAX_TEST - 1;
        //        printf("%s:%d,pos:%d,nrkey:%d,item[0].ino:%llu,last,item[%d]:%llu,found:%d,search:%llu\n",__FUNCTION__,__LINE__, \
        //        i,item->item->nrkeys,item->item->key[0].ino,i,item->item->key[i==BTREE_KEY_MAX_TEST?i-1:i].ino,*found,ino);
    }
    
    return i;
}

static inline void __read_ptrs(struct stp_bnode * node,int idx)
{
    assert(node);
    if(node->ptrs[idx] ||(!node->item->ptrs[idx].offset) ||(node->item->flags & BTREE_ITEM_LEAF) ) return;
    
    struct stp_bnode * bnode;
    //printf("%s:%d,ptrs[%d]:%llu\n",__FUNCTION__,__LINE__,idx,node->item->ptrs[idx].offset);
    bnode = node->tree->ops->allocate(node->tree,node->item->ptrs[idx].offset);
    
    assert(bnode);
    node->ptrs[idx] = bnode;
    bnode->parent = node;
}


/*
 * return leaf node and the ptrs inserted less than ino or position of equal than ino
 */

static struct stp_bnode * __do_btree_search(struct stp_bnode *root,u64 ino,int *index,int *f)
{
    struct stp_bnode *node,*last;
    int i,found;
    
    node = root;
    *f = 0;
    
    if(!node) return NULL;
    
    do{
      i = __binary_search(node,ino,&found);

      if(i < 0) return NULL;
      if(found && !(node->item->flags & BTREE_ITEM_LEAF)) {
          i++;
          //printf("%s:%d,i,flags:%d\n",__FUNCTION__,__LINE__,node->item->flags);
      }
      
      last = node;
      
      if(node->item->flags & BTREE_ITEM_LEAF) break;

      __read_ptrs(node,i);
      node = node->ptrs[i];
      
      //      printf("%s:i:%d,found:%d,line:%d,node:%p\n",__FUNCTION__,i,found,__LINE__,node);

    }while(node);

    *f = found;
    *index = i;
    //printf("funct:%s,line:%d,index:%d,found:%d,pos:%d\n",__FUNCTION__,__LINE__,*index,*f,i);
    return last;
}


static int do_btree_super_search(struct stp_btree_info * sb,u64 ino,struct stp_bnode_off *off)
{
    struct stp_bnode *node;
    int idx,found;


    node = __do_btree_search(sb->root,ino,&idx,&found);
    if(!found) {
        stp_errno = STP_INDEX_ITEM_NO_FOUND;
        return -1;
    }

    off->ino = node->item->ptrs[idx].ino;
    off->flags = node->item->ptrs[idx].flags;
    off->len = node->item->ptrs[idx].len;
    off->offset = node->item->ptrs[idx].offset;
    
    //sb->ops->debug(node);
    
    return 0;
}

static void __copy_bnode_key(struct stp_bnode_key *,const struct stp_bnode_key*);
static void __copy_bnode_off(struct stp_bnode_off *,const struct stp_bnode_off *);

//move from idx backward one place
static void __move_backward(struct stp_bnode_item *item,int idx)
{
    int i;
    
    i = idx;
    
    if(item->flags & BTREE_ITEM_HOLE) {
        while(i<BTREE_KEY_MAX_TEST && (!(item->key[i].flags & BTREE_KEY_DELETE)) && (item->key[i].ino != 0)) 
            i++;
    } else {
        i = item->nrkeys;
    }
    
    __copy_bnode_off(&item->ptrs[i+1],&item->ptrs[i]);   
    //item->ptrs[i+1] = item->ptrs[i];
    for(;i!=idx;i--)
    {
      	__copy_bnode_key(&item->key[i],&item->key[i-1]);
        __copy_bnode_off(&item->ptrs[i],&item->ptrs[i-1]);
      	//item->key[i] = item->key[i-1];
      	//item->ptrs[i] = item->ptrs[i-1];
    }
    
}

static inline void __move_ptr_backward(struct stp_bnode * node,int idx)
{
    int i = node->item->nrptrs + 1;

    while(i != idx) {
        node->ptrs[i] = node->ptrs[i-1];
        i--;
    }
    
}


static int __do_btree_split_leaf(struct stp_btree_info *,struct stp_bnode *,struct stp_bnode *,int);
static int __do_btree_split_internal(struct stp_btree_info *,struct stp_bnode *,struct stp_bnode *,int);

static inline int is_root(const struct stp_btree_info *sb,const struct stp_bnode *node) 
{
    return ((sb->super->root.offset == node->item->location.offset) && (sb->super->root.count == node->item->location.count) \
            && (sb->super->root.flags == node->item->location.flags) && (sb->super->root.nritems == node->item->location.nritems));
}

static inline void set_root(struct stp_btree_info *sb,struct stp_bnode *node)
{
    sb->root = node;
    if(node) {
    sb->super->root.offset = node->item->location.offset;
    sb->super->root.count = node->item->location.count;
    sb->super->root.flags = node->item->location.flags;
    sb->super->root.nritems = node->item->location.nritems;
    node->parent = NULL;
    } else 
        memset(&sb->super->root,0,sizeof(struct stp_bnode_item));
    
}

static inline void __copy_item(struct stp_btree_info *sb,struct stp_bnode *node,const struct stp_bnode_off *off,int idx)
{
    node->item->key[idx].ino = off->ino;
    node->item->key[idx].flags = off->flags;
    node->item->ptrs[idx].ino = off->ino;
    node->item->ptrs[idx].flags = off->flags;
    node->item->ptrs[idx].len = off->len;
    node->item->ptrs[idx].offset = off->offset;

    list_move(&sb->dirty_list,&node->dirty);
    node->flags |= STP_INDEX_BNODE_DIRTY;
}

static inline void __read_parent(struct stp_bnode *node)
{
    if(node->parent || is_root(node->tree,node)) return;
    
    struct stp_bnode *bnode;
    //    int pos,found;
    
    bnode = node->tree->ops->allocate(node->tree,node->item->parent.offset);
    
    assert(bnode);
    node->parent = bnode;
    //    pos = __binary_search(bnode,node->item->key[0].ino,&found);
}

static void __set_header(struct stp_header *dest,const struct stp_header *src)
{
    dest->offset = src->offset;
    dest->count = src->count;
    dest->flags = src->flags;
    dest->nritems = src->nritems;
}


static void __copy_bnode_key(struct stp_bnode_key *dest,const struct stp_bnode_key *src)
{
  dest->ino = src->ino;
  dest->flags = src->flags;
}

static void __copy_bnode_off(struct stp_bnode_off *dest,const struct stp_bnode_off *src)
{
  dest->ino = src->ino;
  dest->flags = src->flags;
  dest->len = src->len;
  dest->offset = src->offset;
}


/**
  * 
  * split root into two part:root(left t-1),node(parent),_new(right t)
  * insert node position pos
  * split also has two sitution:split leaf and split internal
  * 
  *  18   20
  * /   /    \
  *        20 27 29
  *        /  / /  \ 
  * split 
  * 18 20 27
  * / \  /  \
  *     20  27 29
  *    /  \/  \  \
  
  * split internal node,it's different from leaf node,for example:
  *  18 20
  * /  \  \
  *      20 27 29
  *     /  \ /  \
  * split 
  * 18 20 27
  * / \  /  \
  *     20  29
  *    / \ /  \
  * left(t-1) right(t)  mid(t)
  **/
#define BTREE_INTERNAL_LEFT (BTREE_DEGREE_TEST - 1)
#define BTREE_INTERNAL_RIGHT (BTREE_DEGREE_TEST)
/*
 * reference by an Introduction to Algorithm
 * parent unused!!
 * 
 */
static int __do_btree_split_child(struct stp_btree_info *sb,struct stp_bnode *parent,struct stp_bnode *child,int idx)
{
    struct stp_bnode * node ;
    struct stp_bnode_off off;
    struct stp_bnode_key key;
    int left,right,nr,i;
    
    nr = BTREE_KEY_MAX_TEST;
    assert((child->item->nrkeys == nr));
    if(!(node = sb->ops->allocate(sb,0))) return -1;
    
    if(child->item->flags & BTREE_ITEM_LEAF) { //it's a leaf node
        left = BTREE_LEFT;
        right = BTREE_RIGHT;
    } else { //it's a internal node
        left = BTREE_INTERNAL_LEFT + 1;
        right = BTREE_INTERNAL_RIGHT - 1;
    }
    
    printf("%s:%d,split_child:[0]:%llu-%llu\n",__FUNCTION__,__LINE__,child->item->key[0].ino,child->item->key[child->item->nrkeys-1].ino);
    //record the intermediate key for parent
    __copy_bnode_key(&key,&child->item->key[BTREE_LEFT]);
    
    //copy key and ptr
    i = left;
    while(i < nr) {
        __copy_bnode_key(&node->item->key[i - left],&child->item->key[i]);
        memset(&child->item->key[i],0,sizeof(child->item->key[i]));
        

        __copy_bnode_off(&node->item->ptrs[i - left],&child->item->ptrs[i]);
        memset(&child->item->ptrs[i],0,sizeof(child->item->ptrs[i]));
        node->ptrs[i - left] = child->ptrs[i];
        child->ptrs[i] = NULL;
        
        i++;
    }
    
    //modify the last ptrs
    __copy_bnode_off(&node->item->ptrs[i-left],&child->item->ptrs[i]);
    memset(&child->item->ptrs[i],0,sizeof(child->item->ptrs[i]));
    node->ptrs[i - left] = child->ptrs[i];
    child->ptrs[i] = NULL;
    
    child->item->nrkeys = BTREE_LEFT;
    child->flags |= STP_INDEX_BNODE_DIRTY;
    child->item->nrptrs = child->item->nrkeys + 1;
    
    node->flags |= STP_INDEX_BNODE_DIRTY;
    node->item->nrkeys = right;
    node->item->flags = child->item->flags;
    node->item->level = child->item->level;
    node->item->nrptrs = node->item->nrkeys + 1;
    
    parent->flags |= STP_INDEX_BNODE_DIRTY;
    parent->item->flags &= ~BTREE_ITEM_LEAF;
    //root level is larger than other nodes
    parent->item->level = child->item->level + 1;
    
    __move_backward(parent->item,idx);
    __copy_bnode_key(&parent->item->key[idx],&key);
    parent->item->nrkeys++;
    parent->item->nrptrs = parent->item->nrkeys + 1;

    //move memory ptr backward
    /*
    i = parent->item->nrptrs + 1;
    while(i !=idx) {
        parent->ptrs[i] = parent->ptrs[i-1];
        i--;
    }
    */
    __move_ptr_backward(parent,idx);
    
    parent->ptrs[idx + 1] = node;
    parent->ptrs[idx] = child;
    
    off.ino = node->item->key[0].ino;
    off.flags = node->item->flags;
    off.len = node->item->location.count;
    off.offset = node->item->location.offset;
    __copy_bnode_off(&parent->item->ptrs[idx+1],&off);

    off.ino = child->item->key[0].ino;
    off.flags = child->item->flags;
    off.len = child->item->location.count;
    off.offset = child->item->location.offset;
    __copy_bnode_off(&parent->item->ptrs[idx],&off);
    
    list_move(&sb->dirty_list,&node->dirty);
    list_move(&sb->dirty_list,&child->dirty);
    list_move(&sb->dirty_list,&parent->dirty);

    //link together for two children
    if(child->item->flags & BTREE_ITEM_LEAF) {
        off.ino = node->item->key[0].ino;
        off.flags = node->item->flags;
        off.len = node->item->location.count;
        off.offset = node->item->location.offset;
        __copy_bnode_off(&child->item->ptrs[child->item->nrptrs - 1],&off);
    }
    
    return 0;
}

static int __do_btree_insert_nonfull(struct stp_bnode *root,const struct stp_bnode_off *off,int flag)
{
    struct stp_btree_info *sb;
    struct stp_bnode *node;
    int i,found,idx;
    
    i = root->item->nrkeys - 1;
    sb = root->tree;
    
    if(root->item->flags & BTREE_ITEM_LEAF) {
        __copy_bnode_off(&root->item->ptrs[i+2],&root->item->ptrs[i+1]);
        while(i>=0 && root->item->key[i].ino > off->ino) {
            __copy_bnode_key(&root->item->key[i+1],&root->item->key[i]);
            __copy_bnode_off(&root->item->ptrs[i+1],&root->item->ptrs[i]);
            i--;
        }
        __copy_item(sb,root,off,i+1);
        root->item->nrkeys ++;
        root->item->nrptrs = root->item->nrkeys + 1;
        
        pthread_mutex_lock(&sb->mutex);
        sb->super->nrkeys ++;
        pthread_mutex_unlock(&sb->mutex);
    } else {
        node = root;
        while(i>=0 && node->item->key[i].ino > off->ino)
            i--;
        i++;
        if(!node->ptrs[i]) __read_ptrs(node,i);
        if(node->ptrs[i]->item->nrkeys == BTREE_KEY_MAX_TEST) {
            if(__do_btree_split_child(sb,node,node->ptrs[i],i) < 0)
                return -1;
            if(off->ino > node->item->key[i].ino) i++;
            /*
            printf("%s:%d after split_child ino:%llu-%llu\n",__FUNCTION__,__LINE__,node->ptrs[i]->item->key[0].ino,\
                   node->ptrs[i]->item->key[node->ptrs[i]->item->nrkeys - 1].ino);
            sb->ops->debug_btree(sb);
            printf("---------end-------\n");
            */
        }
        
        return __do_btree_insert_nonfull(node->ptrs[i],off,flag);
    }
}

static int __do_btree_insert(struct stp_btree_info *sb,const struct stp_bnode_off *off,int flag)
{
  struct stp_bnode *root = sb->root;
  struct stp_bnode *node;
  int ret,idx,found;

  if((node = __do_btree_search(root,off->ino,&idx,&found))) {
      if(found) {
          if(!(flag & BTREE_OVERFLAP)) {
              stp_errno = STP_INDEX_EXIST;
              return -1;
          } else {
              fprintf(stderr,"[WARNING]:key:%llu,BTREE_OVERFLAP\n",off->ino);
              __copy_item(sb,node,off,idx);
              return 0;
          }
      }
  }
  
  //split root node
  if(root->item->nrkeys == BTREE_KEY_MAX_TEST) {
    
    if(!(node = sb->ops->allocate(sb,0))) return -1;
    if(root->item->level >= BTREE_MAX_LEVEL) {
        stp_errno = STP_INDEX_MAX_LEVEL;
        return -1;
    }
    
    //copy the last left key and the first right key into node(in split)
    if(__do_btree_split_child(sb,node,root,0)<0)
        return -1;
    set_root(sb,node);
    //    printf("%s:%d root:%p\n",__FUNCTION__,__LINE__,root);
    ret = __do_btree_insert_nonfull(node,off,flag);
    //sb->ops->debug_btree(sb);
    return ret;
   }
  
  ret = __do_btree_insert_nonfull(root,off,flag);
  //  sb->ops->debug_btree(sb);
  return ret;
}


/*
 * store a key(ino),value(size,offset) into B+ tree
 *
 */
static int do_btree_super_insert(struct stp_btree_info *sb,const struct stp_bnode_off *off,u8 flags)
{
    struct stp_bnode *root = sb->root;
    
    assert(off->ino !=0 && off->len >0 && off->offset > 0);
    
    return  __do_btree_insert(sb,off,flags);
}

static struct stp_bnode* __btree_search_hist(const struct stp_btree_info *sb,u64 ino,struct stp_bnode **hist,int *size,int *f,int *idx)
{
    struct stp_bnode *node,*last,*n;
    int i,found,len;
    
    *size = 0;
    *f = 0;
    
    node = sb->root;
    n = NULL;
    
    if(!node) return NULL;

    if(!hist)
        return __do_btree_search(sb->root,ino,idx,f);
    
    do{
        i = __binary_search(node,ino,&found);
        if(found && !(node->item->flags & BTREE_ITEM_LEAF)) {
            n = node;
            len = *size;
            *idx = i;
            i++;
        }
        
        hist[(*size)++] = node;
        last = node;
        if(node->item->flags & BTREE_ITEM_LEAF) break;
        __read_ptrs(node,i);
        node = node->ptrs[i];
    } while(node);
    /*
    if(!found && n) { //find the key in internal node but miss in leaf node
        *size = len;
        found = 1;
        return n;
        } else { */
        *f = found;
        *idx = i;
        //    }
    
    return last;
}

static int do_btree_super_free(struct stp_btree_info *sb,struct stp_bnode *node)
{
    if(!node) return 0;
    
    pthread_mutex_lock(&sb->mutex);
    
    if(!list_empty(&node->dirty)) {
        sb->ops->write(sb,node);
        list_del_element(&node->dirty);
    }
    
    list_del_element(&node->list);
    sb->active--;
    if(node->flags & STP_INDEX_BNODE_CREAT) 
        free(node->item);

    umem_cache_free(btree_bnode_slab,node);
    
    pthread_mutex_unlock(&sb->mutex);
    
    return 0;
}

/*
 * remove entry (idx) from node
 */
static int __remove_entry_from_node(struct stp_btree_info *sb,struct stp_bnode *node,int idx)
{
    int i;
    
    printf("%s(%d) ino:%llu,nrkeys:%d,node:%p,idx:%d,nrkeys:%d\n",__FUNCTION__,__LINE__,
           node->item->key[0].ino,node->item->nrkeys,node,idx,node->item->nrkeys);
    
    //move forward one position for child key
    //problem in here
    for(i = idx + 1;i < node->item->nrkeys;i++) 
        __copy_bnode_key(&node->item->key[i-1],&node->item->key[i]);
    if(!(node->item->flags & BTREE_ITEM_LEAF)) {
        for(i = idx + 2;i<node->item->nrptrs;i++)
        {   
            __copy_bnode_off(&node->item->ptrs[i-1],&node->item->ptrs[i]);
            node->ptrs[i-1] = node->ptrs[i];
        }   
    } else {
        for(i = idx + 1;i < node->item->nrptrs; i++)
            __copy_bnode_off(&node->item->ptrs[i-1],&node->item->ptrs[i]);
    }
    
    
    /*
    __copy_bnode_off(&node->item->ptrs[i-1],&node->item->ptrs[i]);
    node->ptrs[i-1] = node->ptrs[i];
    */
    node->item->nrkeys --;
    node->item->nrptrs = node->item->nrkeys + 1;
    
    list_move(&sb->dirty_list,&node->dirty);
    node->flags |= STP_INDEX_BNODE_DIRTY;
    
    return 0;
}

/*
 * when node's key is too small,merge it with neighbor node
 * hist:parent node pointer array
 * k_prime_index k_prime position in parent
 * k_prime: parent key between neighbor
 * neighbor_index:indicates the position of neighbor(left),if it's -1,which means that the neighbor is right of node.
 * neighbor:node's neighbor
 */
static int colaescence_nodes(struct stp_btree_info *sb,struct stp_bnode *node,struct stp_bnode *neighbor,int neighbor_index,int k_prime_index,const struct stp_bnode_key *k_prime,struct stp_bnode **hist,int size)
{
    int i,j,neighbor_insertion_index,n_start,n_end,idx;
    struct stp_bnode *tmp;
    struct stp_bnode_key new_k_prime;
    int split,ret;

    /*
     * Swap neighbor with node if node is on the extreme left and neighbor is to its right
     */
    
    printf("function:%s,file:%s,node:%p,neighbor:%p,parent:%p\n",__FUNCTION__,__FILE__,node,neighbor,hist[size]);

    if(neighbor_index == -1) {
        tmp = node;
        node = neighbor;
        neighbor = tmp;
    }
    
    ret = 1;
    
    /*
     * Starting point in the neighbor for copying keys and pointers from node
     * Recall that node and neighbor have swapped places in the special case
     * of node being a leftmost child
     */
    
    neighbor_insertion_index = neighbor->item->nrkeys;
    
    /*
     * Nonleaf nodes may sometimes need to remain split,
     * if the insertion of k_prime would cause the resulting
     * single coalesced node to exceed the BTREE_KEY_MAX,
     * The variable split always false for leaf node
     * and only sometimes set true for nonleaf node
     */
    split = 0;
    
    /*
     * Case: nonleaf node.
     * Append k_prime and the following pointer.
     * If there is room in the neighbor,append all pointers
     * and keys from the neighbor.
     * Otherwise,append only MAX-2 keys and MAX - 1 pointers.
     */
    
    if(!(node->item->flags & BTREE_ITEM_LEAF)) {
        
        /*
         * Append k_prime
         */
        __copy_bnode_key(&neighbor->item->key[neighbor_insertion_index],k_prime);
        neighbor->item->nrkeys ++;
        
        //neighbor->item->nrptrs = neighbor->item->nrkeys + 1;
        /*
         * Case (default): there is room for all of n's keys and pointers 
         * in the neighbor after appending k_prime
         */
        n_end = node->item->nrkeys;
        
        /*
         * Case (special): k cannot fit with all the other keys and pointers 
         * into one coalesced node.
         */
        
        n_start = 0;
        if(n_end + neighbor->item->nrkeys > BTREE_KEY_MAX_TEST) {
            split = 1;
            //problem in here?
            n_end = BTREE_KEY_MAX_TEST - neighbor->item->nrkeys;
        }

        for(i = neighbor_insertion_index + 1,j=0;j < n_end;i++,j++)
        {
            __copy_bnode_key(&neighbor->item->key[i],&node->item->key[j]);
            __copy_bnode_off(&neighbor->item->ptrs[i],&node->item->ptrs[j]);
            neighbor->ptrs[i] = node->ptrs[j];
            neighbor->item->nrkeys ++;
            node->item->nrkeys --;
            n_start ++;
        }
        
        /*
         * The number of pointers is always 
         * one more than the number of keys
         */
        __copy_bnode_off(&neighbor->item->ptrs[i],&node->item->ptrs[j]);
        neighbor->ptrs[i] = node->ptrs[j];
        node->item->nrptrs = node->item->nrkeys + 1;
        neighbor->item->nrptrs = neighbor->item->nrkeys + 1;
        
        /*
         * If the nodes are still split ,remove the first key from n
         */
        
        if(split) {
            __copy_bnode_key(&new_k_prime,&node->item->key[n_start]);
            for(i = 0,j = n_start + 1; i < node->item->nrkeys;i++,j++) {
                __copy_bnode_key(&node->item->key[i],&node->item->key[j]);
                __copy_bnode_off(&node->item->ptrs[i],&node->item->ptrs[j]);
                node->ptrs[i] = node->ptrs[j];
            }
            __copy_bnode_off(&node->item->ptrs[i],&node->item->ptrs[j]);
            node->ptrs[i] = node->ptrs[j];
            node->item->nrkeys --;
            node->item->nrptrs = node->item->nrkeys + 1;
        }
        //else {
            //modify parent's ptrs because of split
            
        // }
        
        
        //All children must now point up to the same parent
        
    } else {
        int len;
        
        len = node->item->nrkeys;
        
        for(i = neighbor_insertion_index,j = 0;j < len;i++,j++)
        {
            __copy_bnode_key(&neighbor->item->key[i],&node->item->key[j]);
            __copy_bnode_off(&neighbor->item->ptrs[i],&node->item->ptrs[j]);
            neighbor->ptrs[i] = node->ptrs[j];
            neighbor->item->nrkeys ++;
            node->item->nrkeys --;
        }
        
        // link together with leaf
        __copy_bnode_off(&neighbor->item->ptrs[i],&node->item->ptrs[j]);
        neighbor->item->nrptrs = neighbor->item->nrkeys + 1;
        node->item->nrptrs = node->item->nrkeys + 1;
        
    }
    
    if(!split) {
        ret = __btree_delete_entry(sb,hist,size+1,k_prime_index);
        
        //modify parent's ref move forward one further
        /*
        assert(hist[size]->ptrs[k_prime_index+1]==node);
        for(i = k_prime_index+2; i < hist[size]->item->nrptrs;i++)
        {
            __copy_bnode_off(&hist[size]->item->ptrs[i-1],&hist[size]->item->ptrs[i]);
            hist[size]->ptrs[i] = hist[size]->ptrs[i-1];
        }
        */
        __btree_node_destroy(node);
    } else {
        for(i = 0;i< hist[size]->item->nrkeys;i++)
            if(hist[size]->ptrs[i+1] == node) {
                __copy_bnode_key(&hist[size]->item->key[i],&new_k_prime);
                break;
            }
    }

    return ret;
}

static void __btree_node_destroy(struct stp_bnode *node)
{
    struct stp_btree_info *sb;
    u32 off;
    
    sb = node->tree;
    
    printf("%s(%d):ino[0]:%llu,node:%p,nrkeys:%d\n",__func__,__LINE__,node->item->key[0].ino,node,node->item->nrkeys);
    
    assert(node->item->nrkeys == 0);
    off = (node->item->location.offset - BTREE_SUPER_SIZE)/sizeof(struct stp_bnode_item);
    
    bitmap_clear(sb->super->bitmap,off);
    
    list_del_element(&node->list);
    list_del_element(&node->dirty);
    
    if(node->flags & STP_INDEX_BNODE_CREAT)
        free(node->item);
    else
        munmap(node->item,sizeof(struct stp_bnode_item));
    sb->active--;

    umem_cache_free(btree_bnode_slab,node);
}

/*
 * Redistributes entries between two nodes when one has become too small
 * after deletion but its neighbor is too big to 
 * append the small node's entries without exceeding 
 * the maximum
 */

static int redistribute_nodes(struct stp_btree_info *sb,struct stp_bnode *node,struct stp_bnode *neighbor,int neighbor_index,int k_prime_index,const struct stp_bnode_key *k_prime,struct stp_bnode **hist,int size)
{
    int i;
    
    printf("%s:%d neighbor:%p,neighbor_index:%d,k_prime_index:%d,k_prime:%llu\n",__func__,__LINE__,neighbor,neighbor_index,k_prime_index,k_prime->ino);
    //borrow from sibling
    if(neighbor_index != -1) {
        
        __copy_bnode_off(&node->item->ptrs[node->item->nrptrs],&node->item->ptrs[node->item->nrptrs - 1]);
        node->ptrs[node->item->nrptrs] = node->ptrs[node->item->nrptrs - 1];
        
        for(i = node->item->nrkeys; i > 0;i--) 
        {
            __copy_bnode_key(&node->item->key[i],&node->item->key[i-1]);
            __copy_bnode_off(&node->item->ptrs[i],&node->item->ptrs[i-1]);
            node->ptrs[i] = node->ptrs[i-1];
        }
        
        //move the neighbor's last ptr into node
        //move the node's k_prime into node
        //move the neighbor's last key into parent,and replace k_prime with last key
        if(!(node->item->flags & BTREE_ITEM_LEAF)) {
            node->ptrs[0] = neighbor->ptrs[neighbor->item->nrkeys];
            __copy_bnode_off(&node->item->ptrs[0],&neighbor->item->ptrs[neighbor->item->nrkeys]);
            __copy_bnode_key(&node->item->key[0],k_prime);
            __copy_bnode_key(&hist[size]->item->key[k_prime_index],&neighbor->item->key[neighbor->item->nrkeys - 1]);
        } else {
            //move the neighbor's last key into node and parent
            node->ptrs[0] = neighbor->ptrs[neighbor->item->nrptrs - 1];
            __copy_bnode_off(&node->item->ptrs[0],&neighbor->item->ptrs[neighbor->item->nrptrs - 1]);
            __copy_bnode_key(&node->item->key[0],&neighbor->item->key[neighbor->item->nrkeys - 1]);
            __copy_bnode_key(&hist[size]->item->key[k_prime_index],&node->item->key[0]);
            //link child together
            __copy_bnode_off(&node->item->ptrs[node->item->nrkeys-1],&node->item->ptrs[node->item->nrkeys]);
        }
    } else {
        /*
         * Case: node is the leftmost child.
         * Take a key-pointer pair from the neighbor to the right
         * Move the neighbor's leftmost key-pointer pair
         * to node's rightmost position.
         *
         */
        if(node->item->flags & BTREE_ITEM_LEAF) {
            /*
             *  10 30                  17 30
             * /  \            ==>    /  \
             *5  10 17 19 20        5 10  17 19 20
             */
            __copy_bnode_key(&node->item->key[node->item->nrkeys],&neighbor->item->key[0]);
            //__copy_bnode_off(&node->item->ptrs[node->item->nrptrs],&node->item->ptrs[node->item->nrkeys]);
            __copy_bnode_off(&node->item->ptrs[node->item->nrkeys],&neighbor->item->ptrs[0]);
            __copy_bnode_key(&hist[size]->item->key[k_prime_index],&neighbor->item->key[1]);
            struct stp_bnode_off off;
            off.ino = neighbor->item->key[0].ino;
            off.flags = neighbor->item->location.flags;
            off.len = neighbor->item->location.count;
            off.offset = neighbor->item->location.offset;
            __copy_bnode_off(&node->item->ptrs[node->item->nrptrs],&off);
            
            for(i = 1;i < neighbor->item->nrkeys;i++)
            {
                __copy_bnode_key(&neighbor->item->key[i-1],&neighbor->item->key[i]);
                __copy_bnode_off(&neighbor->item->ptrs[i-1],&neighbor->item->ptrs[i]);
            }
            
            __copy_bnode_off(&neighbor->item->ptrs[i-1],&neighbor->item->ptrs[i]);
            
        } else {
            /*
             *  10 30                     11 30      
             * /  \              ===>     /  \
             *5 11 17 19 20            5 10  17 19 20
             */
            __copy_bnode_key(&node->item->key[node->item->nrkeys],k_prime);
            __copy_bnode_off(&node->item->ptrs[node->item->nrptrs],&neighbor->item->ptrs[0]);
            node->ptrs[node->item->nrptrs] = neighbor->ptrs[0];
            
            __copy_bnode_key(&hist[size]->item->key[k_prime_index],&neighbor->item->key[0]);
            
            for(i = 0; i < neighbor->item->nrkeys;i++) {
                __copy_bnode_key(&neighbor->item->key[i],&neighbor->item->key[i+1]);
                __copy_bnode_off(&neighbor->item->ptrs[i],&neighbor->item->ptrs[i+1]);
                neighbor->ptrs[i] = neighbor->ptrs[i+1];
            }
            
            if(neighbor->item->flags & BTREE_ITEM_LEAF) {
                __copy_bnode_off(&neighbor->item->ptrs[i],&neighbor->item->ptrs[i+1]);
            } else 
                neighbor->ptrs[i] = neighbor->ptrs[i+1];
            
        }
    }
    
    node->item->nrkeys ++;
    node->item->nrptrs = node->item->nrkeys + 1;
    
    neighbor->item->nrkeys --;
    neighbor->item->nrptrs = neighbor->item->nrkeys + 1;
    
    neighbor->flags |= STP_INDEX_BNODE_DIRTY;
    node->flags |= STP_INDEX_BNODE_DIRTY;
    hist[size]->flags |= STP_INDEX_BNODE_DIRTY;
    
    list_move(&sb->dirty_list,&neighbor->dirty);
    list_move(&sb->dirty_list,&hist[size]->dirty);
    list_move(&sb->dirty_list,&node->dirty);
    
    return 0;
}


static int __adjust_root(struct stp_btree_info *sb,struct stp_bnode *node)
{
    struct stp_bnode *root;
    
    //nonempty root
    if(node->item->nrkeys > 0) 
        return 0;
    /*
     * Case:empty root
     */
    // If it has a child,promote the first(only)
    // Child as the new root
    if(!(node->item->flags & BTREE_ITEM_LEAF)) {
        __read_ptrs(node,0);
        root = node->ptrs[0];
    } else {
        root = NULL;
    }
    
    set_root(sb,root);
    __btree_node_destroy(node);
    //    sb->ops->free(sb,node);
    return 0;
}

static int get_neighbor_index(struct stp_bnode *parent,const struct stp_bnode *child,int *idx)
{
    assert(!(parent->item->flags & BTREE_ITEM_LEAF));
    
    for(*idx = 0;*idx<parent->item->nrptrs;(*idx)++)
    {
        __read_ptrs(parent,*idx);
        if(parent->ptrs[*idx] == child) {
            *idx = *idx - 1;
            return 0;
        }
        
    }
    
    fprintf(stderr,"ERROR(%s):can't find neighbor,parent:%p,child:%p\n",__FUNCTION__,parent,child);
    //    exit(-1);
    stp_errno = STP_INDEX_NOT_EXIST;
    return -1;
}

/*
 * delete an entry from node (hist[size-1])
 * Removes the record and its key and pointer
 * from the leaf,and then makes all appropriate
 * changes to preserve the B+ tree properties.
 * 
 */
static int __btree_delete_entry(struct stp_btree_info *sb,struct stp_bnode **hist,int size,int index)
{
    int i,idx;
    int k_prime_index;
    struct stp_bnode_key k_prime;
    struct stp_bnode *node = hist[--size];

    printf("%s:ino:%llu,index:%d,node:%p\n",__func__,node->item->key[index].ino,index,node);

    //Remove key and pointer from node
    if(__remove_entry_from_node(sb,node,index) < 0)
        return -1;
    
    //Case: deletion from the root
    if(node == sb->root)
        return __adjust_root(sb,node);
    /*
     * Case: deletion from a node below the root.
     * (Rest of function body)
     */
    
    /*
     * Determine minimum allowable size of node
     * to be preserved after deletion.
     */
    /*
     * Case: node stays at or above minimum,
     * (The simple case.)
     */
    if(node->item->nrkeys >= BTREE_KEY_MIN_TEST)
        return 0;
    /*
     * Case: node falls below minimum.
     * Either coalescence or redistribution
     * is needed.
     *
     */
    /*
     * Find the appropriate neighbor node with 
     * which to coalesce.
     * Also find the key (k_prime) in the parent
     * between the pointer to node n and the pointer
     * to the neighbor
     */
    printf("%s,node:%p,parent:%p\n",__FUNCTION__,node,hist[size-1]);
    --size;
    if(get_neighbor_index(hist[size],node,&idx) < 0) return -1;
    
    k_prime_index = idx == -1? 0:idx;
    __copy_bnode_key(&k_prime,&hist[size]->item->key[k_prime_index]);
    
    struct stp_bnode *neighbor;
    int neighbor_index;
    
    neighbor_index = idx == -1?1:idx;
    __read_ptrs(hist[size],neighbor_index);
    neighbor = hist[size]->ptrs[neighbor_index];
    
    /*
     * Colaescence
     */
    if(neighbor->item->nrkeys + node->item->nrkeys < BTREE_KEY_MAX_TEST)
        return colaescence_nodes(sb,node,neighbor,idx,k_prime_index,&k_prime,hist,size);
    
    else
        /* Redistribution */
        return redistribute_nodes(sb,node,neighbor,idx,k_prime_index,&k_prime,hist,size);
    
}

/*
 * delete function
 * referenced by Amittai's bpt.c,
 * http://www.amittai.com/prose/bplustree.html
 */
static int __do_btree_super_delete(struct stp_btree_info *sb, u64 ino)
{
    struct stp_bnode *hist[BTREE_MAX_LEVEL];
    struct stp_bnode *node,*prev,*next;
    int found,idx,size,pos;
    
    node = NULL;
    memset(hist,0,sizeof(*hist) * BTREE_MAX_LEVEL);
    
    node = __btree_search_hist(sb,ino,hist,&size,&found,&idx);
    if(!found || !node) {
        stp_errno = STP_INDEX_NOT_EXIST;
        return -1;
    }
    
    assert(node->item->key[idx].ino == ino);
    assert(hist[size - 1] == node);
    return __btree_delete_entry(sb,hist,size,idx);
}


static int do_btree_super_rm(struct stp_btree_info *sb,u64 ino)
{
    if(!ino) {
        stp_errno = STP_INVALID_ARGUMENT;
        return -1;
    }
    
    return __do_btree_super_delete(sb,ino);
}

static int do_btree_super_destroy(struct stp_btree_info *sb)
{
    struct stp_bnode *bnode,*next;
    
    printf("%s:%d,before entry_del,root:%p\n",__func__,__LINE__,sb->root);
    
    /*destroy bnode and flush it into disk*/
    list_for_each_entry_del(bnode,next,&sb->dirty_list,dirty) {
        sb->ops->write(sb,bnode);
        list_del_element(&bnode->dirty);
    }
    
    printf("%s:%d,flags:%d,error:%s\n",__FUNCTION__,__LINE__,sb->super->root.flags,strerror(errno));
    /*free all bnode in **/
    list_for_each_entry_del(bnode,next,&sb->node_list,list) {
        list_del_element(&bnode->list);
        pthread_mutex_destroy(&bnode->lock);
        bnode->ops->destroy(bnode);
        if(bnode->flags & STP_INDEX_BNODE_CREAT) {
            free(bnode->item);
            // umem_cache_free(btree_bnode_item_slab,bnode->item);
        } else
            munmap(bnode->item,sizeof(struct stp_bnode_item));
        
        umem_cache_free(btree_bnode_slab,bnode);
        sb->active --;
    }
    /*destroy cache*/
    umem_cache_destroy(btree_bnode_slab);
    umem_cache_destroy(btree_bnode_item_slab);
    sem_destroy(&sb->sem);
    pthread_mutex_destroy(&sb->mutex);
    return 0;
}

static void do_btree_super_debug(const struct stp_bnode *node)
{
    int i;
    
    printf("nrkeys:%u,ptrs:%u,level:%u,flags:%d,parent:%p\n",node->item->nrkeys,node->item->nrptrs,node->item->level,node->item->flags,node->parent);
    printf("offset:%llu,len:%llu",node->item->location.offset,node->item->location.count);
    for(i = 0;i<node->item->nrkeys;i++)
    {
        printf("ino:%llu,flags:%d\n",node->item->key[i].ino,node->item->key[i].flags);
    }

    for(i = 0;i<node->item->nrptrs;i++)
    {
        printf("ptrs[%d]:%p,offset:%llu,len:%llu,flags:%d\n",i,node->ptrs[i],node->item->ptrs[i].offset,node->item->ptrs[i].len,\
               node->item->ptrs[i].flags);
    }
}

static void do_btree_super_debug_root(const struct stp_btree_info *sb)
{
  	int i,f,b;
    struct stp_bnode *n[sb->super->nritems];
    struct stp_bnode *node;
    
    printf("-----------function:%s,root:%p,active:%u\n",__FUNCTION__,sb->root,sb->active);
    f = 0;
    b = 0;
    node = sb->root;
    while(f <= b && node && node->item->nrkeys !=0 ) 
    {
        printf("node:%p,ptrs:%u,level:%u,flags:%d,parent:%p,parent offset:%llu\n",node,node->item->nrptrs,\
               node->item->level,node->item->flags,node->parent,node->item->parent.offset);
        printf("ino:(%llu - %llu),nrkeys:%u,offset:%llu,len:%llu,ptrs:%d\n",node->item->key[0].ino,node->item->key[node->item->nrkeys-1].ino,\
               node->item->nrkeys,node->item->location.offset,node->item->location.count,node->item->nrptrs);

        for(i = 0;i<node->item->nrptrs;i++)
        {
            if(i < node->item->nrkeys)
                printf("key[%d]:%llu ",i,node->item->key[i].ino,node->item->ptrs[i].offset);
            else 
                printf("no key ");
            
            printf("ptr offset:%llu\n",node->item->ptrs[i].offset);
            if(!node->ptrs[i]) __read_ptrs(node,i);
            if(node->ptrs[i]) {
                n[b++] = node->ptrs[i];
                printf("ptrs[%d]:%p,offset:%llu\n",i,node->ptrs[i],node->ptrs[i]?node->ptrs[i]->item->location.offset:0);
            }
            
            //printf("ptrs[%d]:%p,offset:%llu,len:%llu,flags:%d\n",i,node->ptrs[i],node->item->ptrs[i].offset,node->item->ptrs[i].len, \
                //       node->item->ptrs[i].flags);
        }
        node = n[f++];
    }
    
    printf("-------------------------\n");
}


const struct stp_btree_operations stp_btree_super_operations ={
    .init = do_btree_super_init,
    .read = do_btree_super_read,
    .sync = do_btree_super_sync,
    .write = do_btree_super_write,
    .search = do_btree_super_search,
    .insert = do_btree_super_insert,
    .rm  = do_btree_super_rm,
    .destroy = do_btree_super_destroy,
    .debug = do_btree_super_debug,
    .debug_btree = do_btree_super_debug_root,
    .allocate = do_btree_super_allocate,
    .free = do_btree_super_free,
};
