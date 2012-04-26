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

static int do_fs_inode_setattr(struct stp_inode *inode)
{
    return -1;
}

static int do_fs_inode_init(struct stp_inode *inode)
{
    struct stp_fs_info *fs = inode->fs;
    
    inode->item->location.count = 0;
    inode->item->location.offset = 0;
    inode->item->location.flags = 0;
    inode->item->location.nritems = 0;
    
    inode->item->size = 0;
    inode->item->nlink = 1;
    inode->item->uid = getuid();
    inode->item->gid = getgid();
    inode->item->mode = S_IRWXU|S_IRGRP|S_IROTH;
    inode->flags = 0;
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
    
    return it1->ino - it2->ino;
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
    int i;
    
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
        if(!__location_entry_exist(&in->index[i],parent,key,origin)) 
            return 0;
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
    int i;
    
    assert(parent->item->mode & S_IFDIR);    
    *found = 0;
    origin = NULL;
    
    memset(&key,0,sizeof(key));    
    key.ino = ino;
    key.name_len = len;
    strncpy(key.name,filename,len);

    //search in direct entry
    location = &parent->item->entry[0];
    
    if(!location) return 0;
    
    if(!__location_entry_exist(location,parent,&key,origin)) {
        *found = 1;
        return 0;
    }

    //search in indirect entry
    location = &parent->item->entry[1];
    if(!location) return 0;
    
    if(!__location_indir_exist(location,parent,&key,origin)) {
        *found = 1;
        return 0;
    }
    
    //search in 3-indirect entry entry
    location = &parent->item->entry[2];
    if(!location) return 0;
 
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


static int __do_fs_entry_insert(struct stp_inode *parent,const struct stp_dir_item *item,const struct stp_header *header)
{
    struct stp_fs_info *sb = parent->sb;
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
    
    if(ent->location->nritems == STP_FS_DIR_NUM) 
    {
        stp_errno = STP_FS_ENTRY_FULL;
        return -1;
    }
    
    __copy_dir_item(&ent->item[ent->location->nritems++],item);
    //must be sorted(sorted by ino)
    qsort(ent->item,ent->location->nritems,sizeof(*item),dir_item_cmp);
    
    return 0;
}

static int __do_fs_indir_insert(struct stp_inode *parent,const struct stp_dir_item *item,const struct stp_header *header)
{
    struct stp_fs_info *sb = parent->sb;
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
    struct stp_fs_indir *ent;
    
    ent = (struct stp_fs_dirent *)entry->entry;

    int i = 0;
    
    while(i < ent->location.nritems && ent->index[i].nritems == STP_FS_DIR_NUM) {
        i++;
    }
    

    if(i == ent->location.nritems && ent->index[i-1].nritems == DIRENT_MAX) {
        stp_errno = STP_FS_ENTRY_FULL;
        return -1;
    }
    
    return __do_fs_entry_insert(parent,item,&ent->index[i-1]);
}

static int __do_fs_inode_insert(struct stp_inode *parent,const struct stp_dir_item *item)
{
    struct stp_dir_item item;
    
    if(len > DIR_LEN) {
        stp_errno = STP_INVALID_ARGUMENT;
        return -1;
    }
    
    memset(&item,0,sizeof(item));
    item.ino = ino;
    item.name_len = len;
    strncpy(item.name,filename,len);
    
    
    
    stp_errno = STP_FS_ENTRY_EXIST;
    
    return -1;
}

static int do_fs_inode_mkdir(struct stp_inode *parent,const char *filename,size_t len,u64 ino)
{
    return  -1;
}

static int do_fs_inode_rm(struct stp_inode *parent,u64 ino)
{
    
    return -1;
}

static int do_fs_inode_create(struct stp_inode *inode,u64 ino)
{
    
    return -1;
}

static int do_fs_inode_readdir(struct stp_inode *inode)
{
    return -1;
}

static int do_fs_inode_destroy(struct stp_inode *inode)
{
    return -1;
}

static int do_fs_inode_free(struct stp_inode *inode)
{
    return -1;
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

    
