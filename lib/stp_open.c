#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "stp_fs.h"
#include "stp_error.h"
#include "stp.h"
#include "rb_tree.h"

static int read_fs_info(int ffd,struct stp_fs_info **,unsigned int mode);
static int read_btree_info(int bfd,struct stp_btree_info **,unsigned int mode);
static int __fs_info_insert(struct stp_fs_info *,u64 pino,struct stp_dir_item *,struct stp_bnode_off *,mode_t);
static int __btree_info_insert(struct stp_btree_info *,const struct stp_bnode_off *);
static int __btree_info_unlink(struct stp_btree_info *,const struct stp_bnode_off *);
static int __fs_info_unlink(struct stp_fs_info *,struct stp_inode *inode,const char *name,struct stp_bnode_off *off);


static int stp_check(const struct stp_fs_info *fs,const struct stp_btree_info *btree)
{
    if(fs->super->magic != btree->super->magic )
    {
        stp_errno = STP_BAD_MAGIC_NUMBER;
        return -1;
    }
    
    struct stat stbuf;
    
    //check meta file size
    if((fstat(fs->fd,&stbuf) < 0) || (fs->super->total_bytes != stbuf.st_size)) {
        fprintf(stderr,"total_bytes:%llu,size:%lu\n",fs->super->total_bytes,stbuf.st_size);
        stp_errno = STP_META_FILE_CHECK_ERROR;
        return -1;
    }
    
    //check index file size
    
    if((fstat(btree->fd,&stbuf) < 0)) {
        fprintf(stderr,"btree total_bytes:%llu,size:%lu\n",btree->super->total_bytes,stbuf.st_size);
        stp_errno = STP_INDEX_FILE_CHECK_ERROR;
        return -1;
    }
    
    return 0;
}


STP_FILE stp_open(const char *ffile,const char *bfile,unsigned int mode)
{
    int ffd,bfd;
    mode_t m = O_RDWR;
    struct stat stf,stb;
    unsigned int flags = 0;
    
    mode &= ~STP_FS_CREAT;

    if((stat(ffile,&stf) < 0) || (stat(bfile,&stb) < 0)) {
        mode |= STP_FS_CREAT;
        fprintf(stderr,"[WARNING] can't find the index or fs file.\n");
    }
    
    if(mode & STP_FS_CREAT) {   
        m |= O_CREAT;
        mode |= STP_FS_RDWR;
    }
    
    if((ffd = open(ffile,m,S_IRWXU|S_IRGRP|S_IROTH)) < 0) {
        stp_errno = STP_META_OPEN_ERROR;
        return NULL;
    }
    
    if((bfd = open(bfile,m,S_IRWXU|S_IRGRP|S_IROTH)) < 0) {
        stp_errno = STP_INDEX_OPEN_ERROR;
        return NULL;
    }                                                          
     
    STP_FILE_INFO *pfile = (STP_FILE_INFO *)calloc(1,sizeof(STP_FILE_INFO));
    if(!pfile) {
        stp_errno = STP_MALLOC_ERROR;
        return NULL;
    }
    
    struct stp_fs_info *fs = NULL;
    struct stp_btree_info *tree = NULL;
    
    
    if(read_fs_info(ffd,&fs,mode) < 0) {
        free(pfile);
        return NULL;
    }
    pfile->fs = fs;
    pfile->fs->filename = ffile;
    
    if(read_btree_info(bfd,&tree,mode) < 0) {
        if((void *)&fs->super) 
            munmap(&fs->super,FS_SUPER_SIZE);
        free(fs);
        free(pfile);
        return NULL;
    }

    pfile->tree = tree;
    pfile->tree->filename = bfile;
    
    if(stp_check(pfile->fs,pfile->tree))
        return NULL;
    
    return pfile;
}

static int read_fs_info(int ffd,struct stp_fs_info ** _fs,unsigned int mode)
{
    struct stp_fs_info *fs = NULL;
    void *addr;
    
    if(!(fs = (struct stp_fs_info *)calloc(1,sizeof(struct stp_fs_info)))) {
        stp_errno = STP_MALLOC_ERROR;
        return -1;
    }
    
    fs->ops = &stp_fs_super_operations;
    
    if((mode & STP_FS_CREAT) && ftruncate(ffd,FS_SUPER_SIZE) < 0)
    {       
        stp_errno = STP_META_CREAT_ERROR;
        return -1;
    }
    
    //read from file
    if((addr = mmap(NULL,FS_SUPER_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_LOCKED,ffd,0)) == MAP_FAILED) {
        stp_errno = STP_MALLOC_ERROR;
        free(fs);
        return -1;
    }

    if(mode & STP_FS_CREAT)
        memset(addr,0,FS_SUPER_SIZE);
    
    fs->super = (struct stp_fs_super *)addr;
    fs->mode = mode;
    fs->fd = ffd;
    
    if(fs->ops->init(fs) < 0) {
        munmap(fs->super,FS_SUPER_SIZE);
        stp_errno = STP_MALLOC_ERROR;
        free(fs);
        return -1;
    }
    *_fs = fs;
    return 0;
}

static int read_btree_info(int bfd,struct stp_btree_info ** _btree,unsigned int mode)
{
    struct stp_btree_info *btree = NULL;
    void *addr;
    
    if(!(btree = (struct stp_btree_info *)calloc(1,sizeof(struct stp_btree_info)))) {
        stp_errno = STP_MALLOC_ERROR;
        return -1;
    }

    //memset(btree,0,sizeof(struct stp_btree_info));

    btree->ops = &stp_btree_super_operations;
    
    if((mode & STP_FS_CREAT) && ftruncate(bfd,BTREE_SUPER_SIZE) < 0) {
        stp_errno = STP_INDEX_CREAT_ERROR;
        return -1;
    }
    
    if((addr = mmap(NULL,BTREE_SUPER_SIZE,PROT_READ|PROT_WRITE,\
        MAP_SHARED|MAP_LOCKED,bfd,0)) == MAP_FAILED) {
        stp_errno = STP_MALLOC_ERROR;
        free(btree);
        return -1;
    }

    if(mode & STP_FS_CREAT)
        memset(addr,0,BTREE_SUPER_SIZE);

    btree->super = (struct stp_btree_super *)addr;
    if(!(mode & STP_FS_CREAT))
    	printf("%s:btree->super:%p,addr:%p,flags:%d\n",__FUNCTION__,btree->super,addr,btree->super->root.flags);
    else
      	printf("%s:btree->super:%p,addr:%p,root:%p,flags:%p\n",__FUNCTION__,btree->super,addr,&btree->super->root,&btree->super->root.flags);

    btree->mode = mode;
    btree->fd = bfd;
    
    if(btree->ops->init(btree) < 0) {
        munmap(btree->super,BTREE_SUPER_SIZE);
        stp_errno = STP_MALLOC_ERROR;
        free(btree);
        return -1;
    }

    *_btree = btree;
    return 0;
}



int stp_close(STP_FILE pfile)
{
    struct stp_fs_info * fs = pfile->fs;
    struct stp_btree_info *btree = pfile->tree;
    
    printf("%s:%d b+ tree:\n",__FUNCTION__,__LINE__);
    //btree->ops->debug_btree(btree);
    

    fs->ops->destroy(fs);
    fsync(fs->fd);
    munmap(fs->super,FS_SUPER_SIZE);
    close(fs->fd);
    free(fs);
    //btree->ops->debug_btree(btree);
    btree->ops->destroy(btree);
    printf("__function__:%s,flags:%d,nrkeys:%d\n",__FUNCTION__,btree->super->root.flags,btree->super->nritems);
    fsync(btree->fd);
    msync(btree->super,BTREE_SUPER_SIZE,MS_SYNC);
    munmap(btree->super,BTREE_SUPER_SIZE);
    close(btree->fd);
    free(btree);
    
    free(pfile);
    
    return 0;
}

/**
  * create a file.
  */
int stp_creat(STP_FILE file,const char *filename,mode_t mode)
{
  struct stp_fs_info *fs;
  struct stp_btree_info *tree;
  struct stp_bnode_off off;
  struct stp_dir_item item;
  int flags;
  
  if(!file || !filename || strlen(filename) > DIR_LEN) {
      stp_errno = STP_INVALID_ARGUMENT;
      return -1;
  }

  
  fs = file->fs;
  tree = file->tree;

  if(!(tree->mode & STP_FS_RDWR)) {
      stp_errno =  STP_INDEX_CANT_BE_WRITER;
      return -1;
  }

  memset(&item,0,sizeof(item));
  
  item.name_len = strlen(filename);
  strncpy(item.name,filename,item.name_len);
  
  off.ino = random();
  off.offset = off.ino;
  off.len = off.offset;
  off.flags = 0;
  
  flags = __fs_info_insert(fs,1,&item,&off,mode);
  if(flags < 0) return -1;
  flags =  __btree_info_insert(tree,&off);

  return flags;
}

int stp_unlink(STP_FILE file,const char *filename)
{
    struct stp_fs_info *fs;
    struct stp_btree_info *tree;
    struct stp_bnode_off off;
    struct stp_inode *inode;
    
    u64 ino = 1;//parent ino
    static u64 num = 1;
    u8 flags;
    
    if(!file) {
      stp_errno = STP_INVALID_ARGUMENT;
      return -1;
  }

  fs = file->fs;
  tree = file->tree;
  
  if(!(tree->mode & STP_FS_RDWR)) {
      stp_errno =  STP_INDEX_CANT_BE_WRITER;
      return -1;
  }
  
  memset(&off,0,sizeof(off));
  /*
   * unlink entry
   */
  //find the parent inode position
  if(ino != 1) {
      if(tree->ops->search(tree,ino,&off) < 0)
          return -1;
  } else {
      off.ino = 1;
      off.offset = sizeof(struct stp_fs_super) - sizeof(struct stp_inode_item);
  }
  
  //find the corresponding parent inode
  if(fs->ops->lookup(fs,&inode,off.ino,off.offset) < 0)
      return -1;
  
  //unlink the filename entry of parent and corresponding inode
  if(__fs_info_unlink(fs,inode,filename,&off) < 0) {   
      /*
       * unlink the name corresponding inode
       */
      if(stp_errno != STP_FS_INO_NOEXIST) 
          return -1;
      if(tree->ops->search(tree,off.ino,&off)< 0) 
          return -1;
      if(fs->ops->lookup(fs,&inode,off.ino,off.ino) < 0)
          return -1;
      if(inode->ops->unlink(inode) < 0)
          return -1;
  }
  
  //unlink the corresponding position
  if(__btree_info_unlink(tree,&off) < 0)
      return -1;
  
  //  tree->ops->debug_btree(tree);
  /*
  printf("%s,before delete ino:%llu,num:%llu\n",__FUNCTION__,ino,num);
  flags = tree->ops->rm(tree,ino);
  printf("%s,after delete ino:%llu,num:%llu\n",__FUNCTION__,ino,num);
  num ++;
  ino --;
  */
  //tree->ops->debug_btree(tree);

  return 0;
}

static int __fs_info_insert(struct stp_fs_info *sb,u64 pino,struct stp_dir_item *key,struct stp_bnode_off *off,mode_t mode)
{
    struct stp_inode *inode,*parent;
    int flags;
    
    if(sb->ops->find(sb,&parent,pino) < 0) return -1;
    
    flags = parent->ops->lookup(parent,key->name,key->name_len,0);
    
    if(flags < 0 && stp_errno != STP_FS_ENTRY_NOEXIST) return -1;
    if(!flags) {
        stp_errno = STP_FS_ENTRY_EXIST;
        return -1;
    }
    
    if(!(inode = sb->ops->allocate(sb,0))) return -1;
    
    key->ino = inode->item->ino;
    off->ino = inode->item->ino;
    off->offset = inode->item->location.offset;
    off->len = inode->item->location.count;
    printf("ino:%llu,len:%llu,offset:%llu\n",off->ino,off->len,off->offset);
    
    return inode->ops->creat(parent,key->name,key->name_len,inode,mode);
}


static int __btree_info_insert(struct stp_btree_info *tree,const struct stp_bnode_off *off)
{
    return tree->ops->insert(tree,off,BTREE_OVERFLAP);
}

static int __fs_info_unlink(struct stp_fs_info *sb,struct stp_inode *inode,const char *name,struct stp_bnode_off *off)
{
    struct stp_inode *_inode;
    u64 ino;
    size_t len = strlen(name);
    
    //rm entry
    if(inode->ops->rm(inode,name,len,&ino) < 0)
        return -1;
    off->ino = ino;
    //search corresponding_inode of name
    if(sb->ops->find(sb,&_inode,ino) < 0) 
        return -1;
    
    assert(_inode->item);
    off->offset = _inode->item->location.offset;
    off->len = _inode->item->location.count;
    off->flags = _inode->item->location.flags;

    return _inode->ops->unlink(_inode);
}

static int __btree_info_unlink(struct stp_btree_info *sb,const struct stp_bnode_off *off)
{    
    #ifdef DEBUG
    printf("btree unlink ino:%llu\n",off->ino);
    #endif
    return sb->ops->rm(sb,off->ino);
}

