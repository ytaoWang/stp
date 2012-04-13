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

#define BTREE_DEGREE_TEST  BTREE_DEGREE
#define BTREE_LEFT (BTREE_DEGREE_TEST - 1)
#define BTREE_RIGHT (BTREE_DEGREE_TEST)
#define BTREE_KEY_MAX_TEST (KEY(BTREE_DEGREE_TEST))
#define BTREE_CHILD_MAX_TEST (CHILD(BTREE_DEGREE))

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
    
    sb->root = node;

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
        printf("%s:%d in BTREE_ITEM_HOLE(%d),offset:%d\n",__FUNCTION__,__LINE__,item->flags,i);
        
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
        if(i == BTREE_KEY_MAX_TEST) i = BTREE_KEY_MAX_TEST - 1;
        printf("%s:%d,pos:%d,nrkey:%d,item[0].ino:%llu,item[%d]:%llu,found:%d\n",__FUNCTION__,__LINE__,i,item->item->nrkeys,\
               item->item->key[0].ino,i,item->item->key[i].ino,*found);
    }
    
    return i;
}

static inline void __read_ptrs(struct stp_bnode * node,int idx)
{
    assert(node);
    if(node->ptrs[idx] ||(!node->item->ptrs[idx].offset) ||(node->item->flags & BTREE_ITEM_LEAF) ) return;
    
    struct stp_bnode * bnode;
    printf("%s:%d,ptrs[%d]:%llu\n",__FUNCTION__,__LINE__,idx,node->item->ptrs[idx].offset);
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

      
    do{
      i = __binary_search(node,ino,&found);

      if(i < 0) return NULL;
      if(found && !(node->item->flags & BTREE_ITEM_LEAF)) {
          i++;
          printf("%s:%d,i,flags:%d\n",__FUNCTION__,__LINE__,node->item->flags);
      }
      
      last = node;
      
      if(node->item->flags & BTREE_ITEM_LEAF) break;

      __read_ptrs(node,i);
      node = node->ptrs[i];
      
      printf("%s:i:%d,found:%d,line:%d,node:%p\n",__FUNCTION__,i,found,__LINE__,node);

    }while(node);

    *f = found;
    *index = i;
    printf("funct:%s,line:%d,index:%d,found:%d,i:%d\n",__FUNCTION__,__LINE__,*index,*f,i);
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
    sb->super->root.offset = node->item->location.offset;
    sb->super->root.count = node->item->location.count;
    sb->super->root.flags = node->item->location.flags;
    sb->super->root.nritems = node->item->location.nritems;
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

static int __do_btree_insert2(struct stp_btree_info *sb,const struct stp_bnode_off *off,u8 flags,struct stp_bnode *curr)
{
    struct stp_bnode *root = curr? curr:sb->root;
    struct stp_bnode *node;
    int i,found;
    
    printf("%s:%d,ino:%llu,(HOLE)flag:%d\n",__FUNCTION__,__LINE__,off->ino,root->item->flags);
    
    node = __do_btree_search(root,off->ino,&i,&found);
    
    if(!node) return -1;
    if(found && !(flags & BTREE_OVERFLAP)) {
        stp_errno = STP_INDEX_EXIST;
        return -1;
    }
    
    //    sb->ops->debug(node);
    if((found && (flags & BTREE_OVERFLAP)) || (node->item->nrkeys != BTREE_KEY_MAX_TEST)) {
        printf("insert pos:%d,found:%d,ino:%llu,nrkeys:%u,node:%p,[%llu]\n",i,found,off->ino,node->item->nrkeys,node,node->item->key[0].ino);
        if(!found) {
            //move backward
            __move_backward(node->item,i);
            node->item->nrkeys++;
        
            pthread_mutex_lock(&sb->mutex);
            sb->super->nrkeys ++;
            pthread_mutex_unlock(&sb->mutex);
        }
        __copy_item(sb,node,off,i);
        if(found) {
            printf("[Warning]:BTREE_OVER_FLAPE\n");
        }
        
        return 0;
    } else { 
        //stp_errno = STP_NO_SYSCALL;
        //return -1;
        //split  the node
        //split the leaf is different from internal node
        if(is_root(sb,node)) { //it's root
            struct stp_bnode * bnode;
            if(!(bnode = sb->ops->allocate(sb,0))) return -1;
            
            if( __do_btree_split_leaf(sb,node,bnode,0) < 0)
                return -1;
            //sb->ops->debug_btree(sb);
            return __do_btree_insert2(sb,off,flags,NULL);
        } 
        //problem in here
        //stp_errno = STP_NO_SYSCALL;
        //return -1;
        //it must be considered situation:
        //the node must be leaf,because __do_btree_search must reach the leaf node
        struct stp_bnode *tmp;
        int pos;
        pos = i;
        tmp = node->parent;//fasten search when recording current position
        __read_parent(node);
        //find the proper position from node's parent
        i = __binary_search(node->parent,node->item->key[BTREE_LEFT].ino,&found);
        assert(!found && i>=0);
        node->parent->ptrs[i] = node;
        //split the left node
        if(__do_btree_split_leaf(sb,node,node->parent,i) < 0)
            return -1;        
       
        //insert key
        //Does it's parent is full? !!problem in here
        node = node->parent;
        while(node->item->nrkeys == BTREE_KEY_MAX_TEST) {
            __read_parent(node);
            //find the proper position from node's parent
            i = __binary_search(node->parent,node->item->key[BTREE_LEFT].ino,&found);
            assert(!found && i >= 0);
            node->parent->ptrs[i] = node;
            //split the internal node
            if(__do_btree_split_internal(sb,node,node->parent,i) < 0)
                return -1;
        }
        //insert the key
        return __do_btree_insert2(sb,off,flags,tmp);
    }
    
    //    sb->ops->debug(node);
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
  */
static int __do_btree_split_leaf(struct stp_btree_info *sb,struct stp_bnode *root,struct stp_bnode *node,int pos)
{
  int i;
  struct stp_bnode *_new;
  struct stp_bnode_off off;

  printf("%s:%d,nrkeys:%d,ino:%llu\n",__FUNCTION__,__LINE__,
         root->item->nrkeys,root->item->key[0].ino);
  assert(root->item->nrkeys == BTREE_KEY_MAX_TEST);
  
  if(!(_new = sb->ops->allocate(sb,0))) return -1;
  
  //copy right key(t) into _new,and left t-1
  i = BTREE_LEFT;
  while(i < BTREE_KEY_MAX_TEST) {
    __copy_bnode_key(&_new->item->key[i - BTREE_LEFT],&root->item->key[i]);
    __copy_bnode_off(&_new->item->ptrs[i - BTREE_LEFT],&root->item->ptrs[i]);
    memset(&root->item->key[i],0,sizeof(root->item->key[i]));
    memset(&root->item->ptrs[i],0,sizeof(root->item->ptrs[i]));
    _new->ptrs[i - BTREE_LEFT] = root->ptrs[i];
    root->ptrs[i] = NULL;
    i++;
  }

  if(!node->parent) 
  {
      node->parent = root->parent;
      if(!is_root(sb,root)) {
          assert(root->parent);
          node->item->level = root->parent->item->level;
          __set_header(&node->item->parent,&root->parent->item->location);
      }
  }
  
  __copy_bnode_off(&_new->item->ptrs[i-BTREE_DEGREE_TEST],&root->item->ptrs[i]);
  _new->ptrs[i - BTREE_DEGREE_TEST] = root->ptrs[i];
  memset(&root->item->ptrs[i],0,sizeof(root->item->ptrs[i]));
  
  _new->flags |= STP_INDEX_BNODE_DIRTY;
  _new->item->nrkeys = BTREE_RIGHT;
  _new->item->flags |= BTREE_ITEM_LEAF;
  _new->item->nrptrs = _new->item->nrkeys + 1;
  __set_header(&_new->item->parent,&node->item->location);
  _new->parent = node;
  _new->item->level = node->item->level + 1;

  root->item->nrkeys = BTREE_LEFT;
  root->item->flags |= BTREE_ITEM_LEAF;
  root->flags |= STP_INDEX_BNODE_DIRTY;
  root->item->nrptrs = root->item->nrkeys+1;
  __set_header(&root->item->parent,&node->item->location);
  root->parent = node;
  root->item->level = node->item->level + 1;
  
  list_move(&sb->dirty_list,&_new->dirty);
  list_move(&sb->dirty_list,&root->dirty);

  __move_backward(node->item,pos);
  
  //nrptrs also one larger than nrkeys 
  node->item->nrkeys++;
  node->item->nrptrs = node->item->nrkeys + 1;
  node->ptrs[pos+1] = _new;
  node->ptrs[pos]  = root;
  
  off.ino = _new->item->key[0].ino;
  off.flags = _new->item->flags;
  off.len = _new->item->location.count;
  off.offset = _new->item->location.offset;
  __copy_bnode_off(&node->item->ptrs[pos+1],&off);
  
  off.ino = root->item->key[0].ino;
  off.flags = root->item->flags;
  off.len = root->item->location.count;
  off.offset = root->item->location.offset;
  __copy_bnode_off(&node->item->ptrs[pos],&off);
 
  //  printf("copy_bnode pos:%d(offset:%llu),offset:%llu\n",pos,node->item->ptrs[pos].offset,node->item->ptrs[pos+1].offset);
  
  //so,if the pos don't equal to 0,so don't increment
  //  if(!pos) node->item->nrptrs++;
  node->item->flags &= ~BTREE_ITEM_LEAF;
  //!! it is total different from split_internal
  __copy_bnode_key(&node->item->key[pos],&_new->item->key[0]);


  node->flags |= STP_INDEX_BNODE_DIRTY;
  list_move(&sb->dirty_list,&node->dirty);
  
  //link the left and right
  __copy_bnode_off(&root->item->ptrs[root->item->nrkeys],&off);

  node->item->flags &= ~BTREE_ITEM_LEAF;

  if(is_root(sb,root)) 
      set_root(sb,node);

  return 0;
}

/**
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
 */
#define BTREE_INTERNAL_LEFT (BTREE_DEGREE_TEST - 1)
#define BTREE_INTERNAL_RIGHT (BTREE_DEGREE_TEST - 1)

static  int __do_btree_split_internal(struct stp_btree_info *sb,struct stp_bnode *root,struct stp_bnode *node,int pos)
{
  int i;
  struct stp_bnode *_new;
  struct stp_bnode_off off;

  printf("%s:%d,nrkeys:%d\n",__FUNCTION__,__LINE__,root->item->nrkeys);
  assert(root->item->nrkeys == BTREE_CHILD_MAX_TEST);
  
  if(!(_new = sb->ops->allocate(sb,0))) return -1;
  
  //copy right key into _new
  i = BTREE_INTERNAL_LEFT+1;
  while(i < BTREE_CHILD_MAX_TEST) {
    __copy_bnode_key(&_new->item->key[i - (BTREE_INTERNAL_LEFT + 1)],&root->item->key[i]);
    __copy_bnode_off(&_new->item->ptrs[i - (BTREE_INTERNAL_LEFT + 1)],&root->item->ptrs[i]);
    _new->ptrs[i - (BTREE_INTERNAL_LEFT + 1)] = root->ptrs[i];
    memset(&root->item->key[i],0,sizeof(root->item->key[i]));
    memset(&root->item->ptrs[i],0,sizeof(root->item->ptrs[i]));
    root->ptrs[i] = NULL;
    i++;
  }
  
  if(is_root(sb,root)) {
      set_root(sb,node);
  } else
      node->item->level = root->item->level - 1;
  
  
  __copy_bnode_off(&_new->item->ptrs[i-BTREE_DEGREE_TEST],&root->item->ptrs[i]);
  _new->ptrs[i-BTREE_DEGREE_TEST] = root->ptrs[i];
  memset(&root->item->ptrs[i],0,sizeof(root->item->ptrs[i]));
  
  _new->flags |= STP_INDEX_BNODE_DIRTY;
  _new->item->nrkeys = BTREE_INTERNAL_RIGHT;
  _new->item->flags &= ~BTREE_ITEM_LEAF;
  _new->parent = node;
  __set_header(&_new->item->parent,&node->item->location);
  _new->item->level = node->item->level + 1;
  _new->item->nrptrs = _new->item->nrkeys + 1;
  
  root->item->nrkeys = BTREE_INTERNAL_LEFT;
  root->item->nrptrs = root->item->nrkeys + 1;
  root->item->flags &= ~BTREE_ITEM_LEAF;
  root->flags |= STP_INDEX_BNODE_DIRTY;
  root->item->level = node->item->level + 1;
  root->parent = node;
  __set_header(&root->item->parent,&node->item->location);
  
  list_move(&sb->dirty_list,&_new->dirty);
  list_move(&sb->dirty_list,&root->dirty);

  __move_backward(node->item,pos);

  node->item->nrkeys++;
  node->item->nrptrs = node->item->nrkeys + 1;
  node->ptrs[pos]  = root;
  node->ptrs[pos+1] = _new;
  node->item->flags &= ~BTREE_ITEM_LEAF;
  node->flags |= STP_INDEX_BNODE_DIRTY;
  
  //record ptrs position
  off.ino = _new->item->key[0].ino;
  off.flags = _new->item->flags;
  off.len = _new->item->location.count;
  off.offset = _new->item->location.offset;
  __copy_bnode_off(&node->item->ptrs[pos+1],&off);
  
  off.ino = root->item->key[0].ino;
  off.flags = root->item->flags;
  off.len = root->item->location.count;
  off.offset = root->item->location.offset;
  __copy_bnode_off(&node->item->ptrs[pos],&off);

  //move the internal_left key into parent
  //this is different from split_leaf
  __copy_bnode_key(&node->item->key[pos],&root->item->key[BTREE_INTERNAL_LEFT]);
  memset(&root->item->key[BTREE_INTERNAL_LEFT],0,sizeof(root->item->key[0]));
  

  node->flags |= STP_INDEX_BNODE_DIRTY;
  list_move(&sb->dirty_list,&node->dirty);

  return 0;
}


static int __do_btree_insert(struct stp_btree_info *sb,struct stp_bnode_off *off)
{
  struct stp_bnode *root = sb->root;
  struct stp_bnode *node;
  
  //split root node
  if(root->item->nrkeys == BTREE_KEY_MAX_TEST) {
    
    if(!(node = sb->ops->allocate(sb,0))) return -1;
    node->ptrs[0] = root;
    //copy the last left key and the first right key into node(in split)
    if(__do_btree_split_internal(sb,root,node,0)<0) return -1;
    
   }
  
  return -1;
}


/*
 * store a key(ino),value(size,offset) into B+ tree
 *
 */
static int do_btree_super_insert(struct stp_btree_info *sb,const struct stp_bnode_off *off,u8 flags)
{
    struct stp_bnode *root = sb->root;
    
    assert(off->ino !=0 && off->len >0 && off->offset > 0);
    
    return  __do_btree_insert2(sb,off,flags,NULL);
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
    
    printf("%s:%d,flags:%d,error:%s\n",__FUNCTION__,__LINE__,sb->super->root.flags,strerror(errno));
    /*free all bnode in **/
    list_for_each_entry_del(bnode,next,&sb->node_list,list) {
        list_del_element(&bnode->list);
        pthread_mutex_destroy(&bnode->lock);
        bnode->ops->destroy(bnode);
        if(bnode->flags & STP_INDEX_BNODE_CREAT) {
            free(bnode->item);
            // umem_cache_free(btree_bnode_item_slab,bnode->item);
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
    struct stp_bnode *n[20];
    struct stp_bnode *node;
    
    printf("-----------function:%s,root:%p,active:%u\n",__FUNCTION__,sb->root,sb->active);
    f = 0;
    b = 0;
    node = sb->root;
    while(f <= b && node) 
    {
        printf("node:%p,nrkeys:%u,ptrs:%u,level:%u,flags:%d,parent:%p\n",node,node->item->nrkeys,node->item->nrptrs,\
               node->item->level,node->item->flags,node->parent);
        printf("ino:(%llu - %llu),offset:%llu,len:%llu\n",node->item->key[0].ino,node->item->key[node->item->nrkeys-1].ino,\
               node->item->location.offset,node->item->location.count);

        for(i = 0;i<node->item->nrptrs;i++)
        {
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
};
