#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

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

static int do_fs_inode_mkdir(struct stp_inode *inode,const char *filename,size_t len,u64 ino)
{
    return -1;
}

static int do_fs_inode_rm(struct stp_inode *inode,u64 ino)
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


const struct stp_inode_operations inode_operations = {
    .init = do_fs_inode_init,
    .setattr = do_fs_inode_setattr,
    .mkdir = do_fs_inode_mkdir,
    .rm = do_fs_inode_rm,
    .create = do_fs_inode_create,
    .readdir = do_fs_inode_readdir,
    .destroy = do_fs_inode_destroy,
	};

    
