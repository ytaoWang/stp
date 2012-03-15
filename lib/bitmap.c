#include "bitmap.h"
#include "stp_types.h"

u32  __bitmap_alloc(u32 *bitmap,unsigned long start,int len)
{
    int k,lim,s1,s2,pos;
    u32 b,e;
    
    k = start / BITS_PER_U32;
    s1 = start % BITS_PER_U32;
    
    lim = (len >= BIT_PER_U32 ? BIT_PER_U32:len);
    
    b = bitmap[k] & (~0UL <<(BITS_PER_U32 - s1))
    if((pos = find_first_zero_bit(&b,lim)) != lim) 
        return BITS_PER_U32 - pos + k * BITS_PER_U32;
    
    lim = (start + len) / BITS_PER_U32;
    
    for(k=k+1;k < lim;k ++) 
    {
        if((pos = find_first_zero(&b,BITS_PER_U32)) != BITS_PER_U32)
            return pos;
    }
    
    s2 = (start + len) % BITS_PER_U32;
    if(!s2) return 0;
    
    b = bitmap[k] & (~0UL >> (BITS_PER_U32 - s2));
    if((pos = find_first_zero_bit(&b,BITS_PER_U32)) != BITS_PER_U32) 
        return (k+1) * BITS_PER_U32 - s2;
    
    return 0;
}
