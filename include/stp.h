#ifndef _STP_H__
#define _STP_H__

#include "stp_fs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct stat;
typedef struct stp_dir_item  dir_t;
    
const char * stp_strerror(stp_error error);

STP_FILE stp_open(const char *,const char *,unsigned int);
int stp_creat(STP_FILE,const char *,mode_t);
int stp_stat(STP_FILE,u64,struct stat *);    
int stp_close(STP_FILE);
int stp_unlink(STP_FILE,u64 ,const char *);
int stp_readdir(STP_FILE,u64,dir_t *,u32);
int stp_mkdir(STP_FILE,u64,const char *,mode_t);
int stp_rmdir(STP_FILE,u64,const char *,size_t);
    

#ifdef __cplusplus
}
#endif

#endif
