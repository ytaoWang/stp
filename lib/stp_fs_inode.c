#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#include "stp_fs.h"
#include "stp_error.h"
#include "list.h"
#include "rb_tree.h"

static struct stp_fs_entry *__get_fs_entry(struct stp_fs_info *sb,struct stp_inode *inode);
static inline void __set_fs_header(struct stp_header *,const struct stp_header *);
static inline void __set_inode_dirty(struct stp_fs_info *sb,struct stp_inode *inode);
static inline void __set_entry_dirty(struct stp_fs_info *sb,struct stp_fs_entry *entry);

static inline int __empty_location(const struct stp_header *location);
static inline void __debug_entry(const struct stp_fs_dirent * ent);
static int do_fs_inode_setattr(struct stp_inode *inode)
{
    return -1;
}

static int do_fs_inode_init(struct stp_inode *inode)
{
    
    inode->item->size = 0;
    inode->item->nlink = 1;
    inode->item->uid = getuid();
    inode->item->gid = getgid();
    inode->item->mode = S_IRWXU|S_IRGRP|S_IROTH;
    time((time_t *)&inode->item->atime);
    inode->item->ctime = inode->item->atime;
    inode->item->mtime = inode->item->atime;
    inode->item->nritem = 0;

    return 0;
}

static int dir_item_cmp(const void *s1,const void *s2)
{
    struct stp_dir_item *it1,*it2;
    
    it1 = (struct stp_dir_item *)s1;
    it2 = (struct stp_dir_item *)s2;
    
    return strcmp(it1->name, it2->name);
}

static inline void __set_inode_dirty(struct stp_fs_info *sb,struct stp_inode *inode)
{
    if(!(inode->flags & STP_FS_INODE_DIRTY)) {
            inode->flags |= STP_FS_INODE_DIRTY;
            list_move(&sb->dirty_list,&inode->dirty);
        }
}


static int __location_entry_exist(const struct stp_header *location,struct stp_inode *parent,const struct stp_dir_item *key,struct stp_dir_item *origin)
{
    struct stp_fs_info *sb = parent->fs;
    struct stp_fs_entry *entry;
    struct rb_node *node;
    
    origin = NULL;
    
    if(!location)
        return -1;
    //search in rb tree
    if((node = rb_tree_find(&parent->root,location->offset))) {
        entry = rb_entry(node,struct stp_fs_entry,node);
    } else {
        if(!(entry = sb->ops->alloc_entry(sb,parent,location->offset,location->count))) {
            fprintf(stderr,"[ERROR]:cann't allocate memory.\n");
            return -1;
        }
    
        if(entry->ops->read(sb,entry) < 0) return -1;
    }
    //search in entry
    struct stp_fs_dirent *ent;
    
    ent = (struct stp_fs_dirent *)entry->entry;
    
    __debug_entry(ent);
    
    //search in entry
    if((origin = bsearch(key,ent->item,ent->location.nritems,sizeof(struct stp_dir_item),dir_item_cmp))) return 0;
    
    stp_errno = STP_FS_ENTRY_NOEXIST;
    
    return -1;
}

static int __location_indir_exist(const struct stp_header *location,struct stp_inode *parent,const struct stp_dir_item *key,struct stp_dir_item *origin)
{
    struct stp_fs_info *sb = parent->fs;
    struct stp_fs_entry *entry;
    struct rb_node *node;
    struct stp_fs_indir *in;
    int i,flags;
    
    origin = NULL;
    
    if((node = rb_tree_find(&parent->root,location->offset))) {
        entry = rb_entry(node,struct stp_fs_entry,node);
    } else {
        if(!(entry = sb->ops->alloc_entry(sb,parent,location->offset,location->count))) {
            fprintf(stderr,"[ERROR]:cann't allocate memory for indirect entry.\n");
            return -1;
        }
        if(entry->ops->read(sb,entry) < 0) {
            fprintf(stderr,"[ERROR]:read pages for indirect entry.\n");
            return -1;
        }
        
    }
    
    in = (struct stp_fs_indir *)entry->entry;
    for(i = 0;i < in->location.nritems;i++)
    {
        flags = __location_entry_exist(&in->index[i],parent,key,origin);
        if(!flags) return 0;
        if(flags < 0 && stp_errno != STP_FS_ENTRY_NOEXIST)
            return -1;
    }
    
    stp_errno = STP_FS_ENTRY_NOEXIST;
    
    return -1;
}


static int _do_fs_inode_exist(struct stp_inode *parent,u64 ino,const char *filename,size_t len,int *found,struct stp_dir_item *origin)
{
    struct stp_fs_info *sb = parent->fs;
    struct stp_fs_entry *entry;
    struct rb_node *node;
    struct stp_header *location;
    struct stp_dir_item key;
    struct stp_fs_indir *in;
    int i,flags;
    
    assert(parent->item->mode & S_IFDIR);    
    *found = 0;
    origin = NULL;
    
    memset(&key,0,sizeof(key));    
    key.ino = ino;
    key.name_len = len;
    strncpy(key.name,filename,len);

    //search in direct entry
    location = &parent->item->entry[0];
    
    if(!location || __empty_location(location)) return 0;

    if(!(flags = __location_entry_exist(location,parent,&key,origin))) {
        *found = 1;
        return 0;
    }

    if(flags < 0 && stp_errno != STP_FS_ENTRY_NOEXIST)
        return -1;

    //search in indirect entry
    location = &parent->item->entry[1];
    if(!location || __empty_location(location)) return 0;
    
    if(!__location_indir_exist(location,parent,&key,origin)) {
        *found = 1;
        return 0;
    }
    
    //search in 3-indirect entry entry
    location = &parent->item->entry[2];
    if(!location || __empty_location(location)) return 0;
 
   if((node = rb_tree_find(&parent->root,location->offset))) {
        entry = rb_entry(node,struct stp_fs_entry,node);
    } else {
        if(!(entry = sb->ops->alloc_entry(sb,parent,location->offset,location->count))) {
            fprintf(stderr,"[ERROR]:cann't allocate memory for indirect entry.\n");
            return -1;
        }
        if(entry->ops->read(sb,entry) < 0) {
            fprintf(stderr,"[ERROR]:read pages for indirect entry.\n");
            return -1;
        }   
    }
 
   in = (struct stp_fs_indir *)entry->entry;
   for(i = 0;i< in->location.nritems;i++)
   {
       if(!__location_indir_exist(&in->index[i],parent,&key,origin))
       {
           *found = 1;
           return 0;
       }
       
   }
   
   return 0;
}                 

static int do_fs_inode_lookup(struct stp_inode *inode,const char *filename,size_t len,u64 ino)
{
    int found;
    struct stp_dir_item *origin;
    
    if(_do_fs_inode_exist(inode,ino,filename,len,&found,origin) < 0)
        return -1;
    
    if(!found) {
        stp_errno = STP_FS_ENTRY_NOEXIST;
        return -1;
    }
    
    return 0;
}

static void __copy_dir_item(struct stp_dir_item *dest,const struct stp_dir_item *src)
{
    memset(dest,0,sizeof(*dest));
    
    dest->ino = src->ino;
    dest->name_len = src->name_len;
    dest->flags = src->flags;
    strncpy(dest->name,src->name,src->name_len);
}


static int __do_fs_entry_insert(struct stp_inode *parent,const struct stp_dir_item *item,const struct stp_header *location)
{
    struct stp_fs_info *sb = parent->fs;
    struct stp_fs_entry *entry;
    struct rb_node *node;
    
    if((node = rb_tree_find(&parent->root,location->offset))) {
        entry = rb_entry(node,struct stp_fs_entry,node);
    } else {
        if(!(entry = sb->ops->alloc_entry(sb,parent,location->offset,location->count))) {
            fprintf(stderr,"[ERROR]:cann't allocate  memory in %s\n",__FUNCTION__);
            return -1;
        }
        
        if(entry->ops->read(sb,entry) < 0) return -1;
    }
    
    //search in entry
    struct stp_fs_dirent *ent;
    
    ent = (struct stp_fs_dirent *)entry->entry;
    entry->flags |= STP_FS_ENTRY_DIRECT;
    
    if(ent->location.nritems == STP_FS_DIR_NUM) 
    {
        stp_errno = STP_FS_ENTRY_FULL;
        return -1;
    }
    
    __copy_dir_item(&ent->item[ent->location.nritems++],item);
    //must be sorted(sorted by ino)
    qsort(ent->item,ent->location.nritems,sizeof(*item),dir_item_cmp);
    __set_entry_dirty(sb,entry);
    
    return 0;
}

static inline int __ent_empty(const struct stp_header *location)
{
    if(!location) return 1;
    
    return location->offset == 0 && location->count == 0;
}


static int __do_fs_indir_insert(struct stp_inode *parent,const struct stp_dir_item *item,const struct stp_header *header)
{
    struct stp_fs_info *sb = parent->fs;
    struct stp_fs_entry *entry;
    struct rb_node *node;
    struct stp_header *location;
    
    if((node = rb_tree_find(&parent->root,location->offset))) {
        entry = rb_entry(node,struct stp_fs_entry,node);
    } else {
        if(!(entry = sb->ops->alloc_entry(sb,parent,location->offset,location->count))) {
            fprintf(stderr,"[ERROR]:cann't allocate  memory in %s\n",__FUNCTION__);
            return -1;
        }
        entry->flags |= STP_FS_ENTRY_INDIR1;
        if(entry->ops->read(sb,entry) < 0) return -1;
    }
    
    //search in entry
    struct stp_fs_indir *ent;
    
    ent = (struct stp_fs_indir *)entry->entry;

    int i = 0;
    
    while(i < ent->location.nritems && ent->index[i].nritems == STP_FS_DIR_NUM) {
        i++;
    }
    
    if(ent->location.nritems !=0 && i == ent->location.nritems) {
        stp_errno = STP_FS_ENTRY_FULL;
        return -1;
    }
    
    location = &ent->index[i];
    //allocate direct entry,then insert into it
    if(__ent_empty(location)) {
        struct stp_fs_entry *item;
        if(!(item = __get_fs_entry(sb,parent)))
            return -1;
        __set_fs_header(location,(struct stp_header *)item->entry);
        __set_entry_dirty(sb,entry);
    }
    
    return __do_fs_entry_insert(parent,item,location);
}

static int __do_fs_inode_insert(struct stp_inode *parent,const struct stp_dir_item *item)
{
    struct stp_fs_info  *sb = parent->fs;
    struct stp_fs_entry *entry;
    struct stp_header *location;
    
    //insert in the direct dir
    location = &parent->item->entry[0];
    if(__ent_empty(location)) {
        //allocate entry
        if(!(entry = __get_fs_entry(sb,parent))) 
            return -1;
        __set_fs_header(location,(struct stp_header *)entry->entry);
        __set_inode_dirty(sb,parent);
        entry->flags |= STP_FS_ENTRY_DIRECT;
    }
    
    if(location->nritems < STP_FS_DIR_NUM) 
        return __do_fs_entry_insert(parent,item,location);
    
    //insert in the indirect dir
    location = &parent->item->entry[1];
    if(__ent_empty(location)) {
        //allocate entry
        if(!(entry = __get_fs_entry(sb,parent))) 
            return -1;
        __set_fs_header(location,(struct stp_header *)entry->entry);
        __set_inode_dirty(sb,parent);
        entry->flags |= STP_FS_ENTRY_INDIR1;
    }
    if(location->nritems < STP_FS_DIRENT_MAX) 
        return __do_fs_indir_insert(parent,item,location);
    
    location = &parent->item->entry[2];
    if(__ent_empty(location)) {
        //allocate entry
        if(!(entry = __get_fs_entry(sb,parent))) 
            return -1;
        __set_fs_header(location,(struct stp_header *)entry->entry);
        __set_inode_dirty(sb,parent);
        entry->flags |= STP_FS_ENTRY_INDIR2;
    }
    if(location->nritems == STP_FS_DIRENT_MAX) {
        stp_errno = STP_FS_ENTRY_FULL;
        return -1;
    }
    
    int i = 0;
    struct stp_fs_indir *ent;
    
    ent = (struct stp_fs_indir *)entry->entry;
    
    while(i < location->nritems && \
          ent->index[i].nritems == STP_FS_DIRENT_MAX)
        //search the unused item
        i++;
    
    if(location->nritems !=0 && i == ent->location.nritems) {
        stp_errno = STP_FS_ENTRY_FULL;
        return -1;
    }
    
    struct stp_header *l;
    
    l = &ent->index[i];
    if(__ent_empty(l)) {
        struct stp_fs_entry *item;
        if(!(item = __get_fs_entry(sb,parent)))
            return -1;
        __set_fs_header(&ent->index[i],(struct stp_header *)item->entry);
        __set_entry_dirty(sb,entry);
        }
    
    
    return __do_fs_indir_insert(parent,item,l);
}

static int do_fs_inode_mkdir(struct stp_inode *parent,const char *filename,size_t len,struct stp_inode *inode)
{
    struct stp_fs_info *sb = parent->fs;
    struct stp_dir_item item;
    
    if(!parent || !inode || len==0 || len > DIR_LEN) {
        stp_errno = STP_INVALID_ARGUMENT;
        return -1;
    }
    
    memset(&item,0,sizeof(item));
    item.ino = inode->item->ino;
    item.name_len = len;
    strncpy(item.name,filename,len);
    
    if(!(inode->item->mode & S_IFDIR)) {
        inode->item->mode |= S_IFDIR;
        __set_inode_dirty(sb,inode);
    }
    
    return  __do_fs_inode_insert(parent,&item);

}

static int do_fs_inode_rm(struct stp_inode *parent,u64 ino)
{
    
    return -1;
}

static int do_fs_inode_create(struct stp_inode *parent,const char *filename,size_t len,struct stp_inode *inode,mode_t mode)
{
    struct stp_fs_info *sb = parent->fs;
    struct stp_dir_item item;
    int flags;
    
    if(!parent || !inode || len ==0 || len > DIR_LEN) {
        stp_errno = STP_INVALID_ARGUMENT;
        return -1;
    }

    flags = parent->ops->lookup(parent,filename,len,inode->item->ino);
    
    if(!flags) {
        stp_errno = STP_FS_ENTRY_EXIST;
        return -1;
    }
    
    if((flags<0) && (stp_errno != STP_FS_ENTRY_NOEXIST) )
        return -1;

    memset(&item,0,sizeof(item));
    item.ino = inode->item->ino;
    item.name_len = len;
    strncpy(item.name,filename,len);
    
    inode->item->mode = mode;
    __set_inode_dirty(sb,inode);
    

    return __do_fs_inode_insert(parent,&item);
}

static int do_fs_inode_readdir(struct stp_inode *inode)
{
    return -1;
}

static int do_fs_inode_destroy(struct stp_inode *inode)
{
    struct stp_fs_info *sb = inode->fs;
    struct stp_fs_entry *dir,*ndir;
    
    //destroy all entry and then itself
    list_for_each_entry_del(dir,ndir,&inode->entry_list,list) {
        dir->ops->destroy(sb,dir);
        list_del_element(&dir->list);        
    }
    
    //if dirty must be flush
    if(inode->flags & STP_FS_INODE_DIRTY) {
        sb->ops->write(sb,inode);
        inode->flags &= ~STP_FS_INODE_DIRTY;
    }
    
    list_del_element(&inode->lru);
    list_del_element(&inode->dirty);
    list_del_element(&inode->list);
    list_del_element(&inode->sibling);
    list_del_element(&inode->child);
    
    rb_tree_erase(&sb->root,&inode->node);
    pthread_mutex_destroy(&inode->lock);
    
    return 0;
}

static int do_fs_inode_free(struct stp_inode *inode)
{
    struct stp_fs_info *sb = inode->fs;
    struct stp_fs_entry *dir,*ndir;
    
    list_for_each_entry_del(dir,ndir,&inode->entry_list,list) 
    {
        dir->ops->free_entry(sb,dir);
        list_del_element(&dir->list);
    }
    
    return inode->ops->destroy(inode);
}

static struct stp_fs_entry* __get_fs_entry(struct stp_fs_info *sb,struct stp_inode *inode)
{
    struct stp_fs_entry *entry;
    
    if(!(entry = sb->ops->alloc_entry(sb,inode,0,0))) return NULL;
    if(entry->ops->alloc(sb,inode,entry) < 0) {
        sb->ops->free_entry(sb,entry);
        return NULL;
    }
    
    return entry;
}


static void __set_fs_header(struct stp_header *dest,const struct stp_header *src)
{
    dest->offset = src->offset;
    dest->count = src->count;
    dest->flags = src->flags;
    dest->nritems = src->nritems;
}

static inline void __set_entry_dirty(struct stp_fs_info *sb,struct stp_fs_entry *entry)
{
    if(entry->flags & STP_FS_ENTRY_DIRTY) return;
    
    entry->flags |= STP_FS_ENTRY_DIRTY;
    list_move(&sb->entry_dirty_list,&entry->dirty);    
}

static inline int __empty_location(const struct stp_header *location)
{
    return __ent_empty(location);
    
}

static inline void __debug_entry(const struct stp_fs_dirent * ent)
{
    int i;
    printf("%s:%d,ent(%p),nritems:%d\n",__FUNCTION__,\
           __LINE__,ent,ent->location.nritems);
    
    for(i = 0;i<ent->location.nritems;i++)
    {
        printf("ent[%d],ino:%llu,name:%s\n",i,ent->item[i].ino,\
               ent->item[i].name);
    }
    
}


const struct stp_inode_operations inode_operations = {
    .init = do_fs_inode_init,
    .setattr = do_fs_inode_setattr,
    .mkdir = do_fs_inode_mkdir,
    .rm = do_fs_inode_rm,
    .creat = do_fs_inode_create,
    .readdir = do_fs_inode_readdir,
    .destroy = do_fs_inode_destroy,
    .free = do_fs_inode_free,
    .lookup = do_fs_inode_lookup,
};

    
