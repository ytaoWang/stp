#ifndef _STP_H__
#define _STP_H__

#include "stp_fs.h"

#ifdef __cplusplus
extern "C" {
#endif

const char * stp_strerror(stp_error error);

STP_FILE stp_open(const char *ffile,const char *bfile,unsigned int mode);

int stp_close(STP_FILE file);


#ifdef __cplusplus
}
#endif

#endif
