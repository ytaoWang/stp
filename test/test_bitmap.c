#include "bitmap.h"
#include "stp_types.h"
#include "stp.h"

#include <stdio.h>
#include <sys/types.h>

#define N 10
#define BITS (N * BITS_PER_U32)

int main_testbitmap(int argc,char *argv[]) 
{
    u32 b[N];
    int i;
    off_t off;
    
    bitmap_clean(b,BITS);
    
    
    i = 0;
    off = 0;
    //while(i < BITS_PER_U32) 
    {
        b[0] |= ~0UL;
        b[1] |= ~0UL;
        b[2] |= ~0UL;
        b[2] &= 0xfffffff0;
    
        off = bitmap_find_first_zero_bit(b,11,BITS_PER_U32 * 2 - 10);
        #ifdef DEBUG
        printf("offset:%ld\n",off);
        #endif
        bitmap_set(b,off);
        i++;
    }
    
    printf("sizeof node:%d\n",sizeof(struct stp_bnode_item));
    return 0;
}

int main(int argc,char *argv[]) 
{
    STP_FILE file;
    u64 ino;
    
    if(!(file = stp_open("stp.fs","stp.index",STP_FS_RDWR|STP_FS_CREAT)))
    {
        printf("open stp error:%s\n",stp_strerror(stp_errno));
        return -1;
    }
    
    /*
     * test b+ tree insert 
     **/
    ino = 1;
    while(ino <= 7) 
    {
        //printf("create file ino:%llu\n",ino);
        if(stp_creat(file,"test1") < 0) {
            printf("creat file test1 error:%s,errno:%d\n",stp_strerror(stp_errno),stp_errno);
                  break;
        }
        ino ++;
    }
    
    ino = 2;
    
    /*
     * test b+tree search
     **/
    if(stp_stat(file,ino,NULL) < 0) {
        fprintf(stderr,"stat file ino:%llu,error:%s\n",ino,stp_strerror(stp_errno));
    }
    
    ino = 1;
    
    if(stp_stat(file,ino,NULL) < 0) {
        fprintf(stderr,"stat file ino:%llu,error:%s\n",ino,stp_strerror(stp_errno));
    }
    
    /*
     * test destroy
     */
    stp_close(file);
    return 0;
}
