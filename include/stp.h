#ifndef _STP_H__
#define _STP_H__

#include "stp_fs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct stat;
    
const char * stp_strerror(stp_error error);

STP_FILE stp_open(const char *ffile,const char *bfile,unsigned int mode);
int stp_creat(STP_FILE file,const char *);
int stp_stat(STP_FILE file,u64 ino,struct stat *);    
int stp_close(STP_FILE file);
int stp_unlink(STP_FILE file,const char *);
    

#ifdef __cplusplus
}
#endif

#endif
