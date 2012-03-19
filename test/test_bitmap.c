#include "bitmap.h"
#include "stp_types.h"

#include <stdio.h>
#include <sys/types.h>

#define N 10
#define BITS (N * BITS_PER_U32)

int main(int argc,char *argv[]) 
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
    
    
    return 0;
}
