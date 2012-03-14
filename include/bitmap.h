#ifndef __BITMAP_H__
#define __BITMAP_H__

#ifdef __cplusplus
extern "C" {
#endif
/*
 * bitmap operations for bltmap-allocation
 *
 */

static inline int bitmap_empty(const u32 *bitmap,int bits) 
{
  int k,lim = bits / BITS_PER_U32;
  
  for(k = 0;k < lim;k++) 
    if(bitmap[k])
      	return 0;
  
  if(bits % BITS_PER_U32)
    if(bitmap[k] & BITMAP_LAST_WORD_MASK(bits))
      return 0;
  
  return 1;
}

    
static inline void bitmap_fill(const u32 *bitmap,int bits)
{
    u32 nlongs = BITS_TO_U32(bits);
    
    if(longs > 1) {
        int len = (nlongs - 1) * sizeof(u32);
        memset(bitmap,0xff,len);
    }
    
    bitmap[nlongs - 1] = BITMAP_LAST_WORD_MASK(bits);
}


static inline u32 bitmap_alloc(u32 *bitmap,unsigned long start,int len)
{
    return __bitmap_alloc(bitmap,start,len);
}
    
    

#ifdef __cplusplus
}
#endif

#endif
