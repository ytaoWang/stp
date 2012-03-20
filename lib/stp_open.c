#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "stp_fs.h"
#include "stp_error.h"
#include "stp.h"


static int read_fs_info(int ffd,struct stp_fs_info **,unsigned int mode);
static int read_btree_info(int bfd,struct stp_btree_info **,unsigned int mode);

STP_FILE stp_open(const char *ffile,const char *bfile,unsigned int mode)
{
    int ffd,bfd;
    mode_t m = O_RDWR;
    struct stat stf,stb;
    
    mode &= ~STP_FS_CREAT;

    if((stat(ffile,&stf) < 0) || (stat(bfile,&stb) < 0))
        mode |= STP_FS_CREAT;

    if(mode & STP_FS_CREAT) {   
        m |= O_CREAT;
        mode |= STP_FS_RDWR;
    }
    
    if((ffd = open(ffile,O_APPEND|m,S_IRWXU|S_IRGRP|S_IROTH)) < 0) {
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
    
    if(!(btree = (struct stp_btree_info *)calloc(1,\
             sizeof(struct stp_btree_info)))) {
        stp_errno = STP_MALLOC_ERROR;
        return -1;
    }
    
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
    btree->super = (struct stp_btree_super *)addr;
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
    
    fs->ops->destroy(fs);
    munmap(&fs->super,FS_SUPER_SIZE);
    close(fs->fd);
    free(fs);
    
    btree->ops->destroy(btree);
    munmap(&btree->super,BTREE_SUPER_SIZE);
    close(btree->fd);
    free(btree);
    
    free(pfile);
    
    return 0;
}
