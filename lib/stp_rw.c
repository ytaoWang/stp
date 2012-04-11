
/*
 * stp read/write function implementation
 *
 */

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


int stp_stat(STP_FILE pfile,u64 ino,struct stat *buf)
{
    struct stp_fs_info * fs = pfile->fs;
    struct stp_btree_info *btree = pfile->tree;
    struct stp_bnode_off off;
    int ret;
        
    memset(&off,0,sizeof(off));
    
    ret = btree->ops->search(btree,ino,&off);
    /*
     * read from fs 
     *
     */
    
    printf("%s:%d,ino:%llu(%llu),offset:%llu,size:%llu,ret:%d\n",__FUNCTION__,__LINE__,off.ino,ino,off.offset,off.len,ret);
    
    if(ret < 0) return ret;
    if(!buf) return 0;
    
    return fstat(btree->fd,buf);
}
