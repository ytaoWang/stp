#ifndef __STP_FS_H__
#define __STP_FS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "list.h"
#include "stp_types.h"
#include "rb_tree.h"

#include <pthread.h>
#include <semaphore.h>

/*
 * every object(meta_item or btree_item) has a header to indicate where the node is.
 */
struct stp_header {
    u64 offset;
    u64 count;
    u8 flags;
    u32 nritems;
}__attribute__((__packed__));

/*
 * directory item in directory
 */
#define DIR_LEN 127

struct stp_dir_item {
    u64 ino;
    u32 name_len;
    char name[DIR_LEN + 1];
}__attribute__((__packed__));

/*
 * inode item in disk 128 byte
 * 
 */
struct stp_inode_item {
    struct stp_header location;
    u64 ino;
    u64 size;
    u8 nlink;
    u32 uid;
    u32 gid;
    u8 mode;
    u16 flags;
    u64 atime;
    u64 ctime;
    u64 mtime;
    u64 otime;
    u64 transid;
    u32 nritem;//file-item number dir_item 
    u8 padding[35];
} __attribute__((__packed__));

/*
 * meta file super block
 *
 */
#define FS_SUPER_SIZE  (4*1024)
#define STP_FS_MAGIC (0x1357ef77)
struct stp_fs_super {
    u32 magic;
    u32 flags;
    u64 total_bytes;
    u64 bytes_used;
    u64 bytes_hole;
    u64 ino;
    u32 nritems;//number item
    u32 nrdelete;//delete item number
    struct stp_inode_item root;
} __attribute__((__packed__));

/*
 *
 * may be add some operations later
 */

struct stp_inode;
    
struct stp_inode_operations {
    int (*init)(struct stp_inode *);
    int (*setattr)(struct stp_inode *);
    int (*mkdir)(struct stp_inode *,const char *,size_t,u64);
    int (*rm)(struct stp_inode *,u64 ino);
    int (*create)(struct stp_inode *,u64 ino);
    int (*readdir)(struct stp_inode *);
    int (*destroy)(struct stp_inode *);
};

#define STP_FS_INODE_CREAT  (1<<0)
#define STP_FS_INODE_DIRTY  (1<<1)
#define STP_FS_INODE_DIRTY_MM (1<<2)

struct stp_inode {
    u8 flags;
    u32 ref;
    pthread_mutex_t lock;
    struct rb_node node;//for search
    struct list lru;
    struct list dirty;
    struct list list;
    struct stp_fs_info *fs;
    struct stp_inode_item *item;
    const struct stp_inode_operations *ops;
};

extern const struct stp_inode_operations inode_operations;

struct stp_fs_info;
    
struct stp_fs_operations {
    int (*init)(struct stp_fs_info *);
    struct stp_inode* (*allocate)(struct stp_fs_info *,off_t);
    int (*alloc_page)(struct stp_inode *,off_t);
    int (*free)(struct stp_fs_info *,struct stp_inode *);
    int (*read)(struct stp_fs_info *,struct stp_inode *,off_t offset);
    int (*sync)(struct stp_fs_info *);
    int (*release_page)(struct stp_inode *);
    int (*write)(struct stp_fs_info *,struct stp_inode *);
    int (*destroy)(struct stp_fs_info *);
};

extern const struct stp_fs_operations stp_super_operations;

/* 4KB metadata*/
struct stp_fs_info {
    const char *filename;
    int fd;
    u32 mode;
    u32 magic;
    u32 active;
    u64 transid;
    sem_t sem;
    pthread_mutex_t mutex;
    struct stp_fs_super *super;
    struct rb_root root;//rb root for read/search in memory
    struct list inode_list;
    struct list inode_lru;
    //    struct list inode_mm;//inode from mmap
    struct list dirty_list;
    const struct stp_fs_operations *ops;//inode read/write/sync operations
};

extern const struct stp_fs_operations stp_fs_super_operations;

/*
 *
 * b+ tree
 */
struct stp_bnode_off {
    u64 ino;
    u8 flags;
    u64 len;
    u64 offset;
} __attribute__((__packed__));

#define BTREE_KEY_DELETE  (1<<0)

    
struct stp_bnode_key {
    u64 ino;
    u8 flags;
} __attribute__((__packed__));

#define BTREE_DEGREE 59      
#define MAX ((u32)-1)

#define KEY(t)  (2*(t) - 1)
#define MIN_KEY(t)  ((t) - 1)
#define MIN_CHILD(t)  (t)
#define CHILD(t) (2*(t))


#define BTREE_CHILD_MAX (CHILD(BTREE_DEGREE))
#define BTREE_CHILD_MIN (MIN_CHILD(BTREE_DEGREE))
#define BTREE_KEY_MIN (MIN_KEY(BTREE_DEGREE))
#define BTREE_KEY_MAX (KEY(BTREE_DEGREE))

#define BTREE_ITEM_HOLE (1<<0)
#define BTREE_ITEM_LEAF (1<<1)

struct stp_bnode_item {  //4096 bytes
    struct stp_header location;
    struct stp_bnode_key key[KEY(BTREE_DEGREE)];
    u32 nrkeys;
    struct stp_bnode_off ptrs[CHILD(BTREE_DEGREE)];
    u32 nrptrs;
    u32 level;
    u8 flags;
    u8 padding[52];
}__attribute__((__packed__));


struct stp_bnode;
    
struct stp_bnode_operations {
    int (*init)(struct stp_bnode * node);
    int (*insert)(struct stp_bnode * node,u64 ino,size_t start,off_t offset);
    int (*update)(struct stp_bnode * node,u64 ino,size_t start,off_t offset);
    int (*delete)(struct stp_bnode * node,u64 ino);
    struct stp_bnode * (*search)(struct stp_bnode *node,u64 ino);
    int (*destroy)(struct stp_bnode * node);
};
    
#define STP_INDEX_BNODE_CREAT (1<<0)
#define STP_INDEX_BNODE_DIRTY (1<<1)        

struct stp_bnode {
    u8 flags;
    u8 ref;
    pthread_mutex_t lock;
    struct list lru;
    struct list dirty;
    struct list list;
    struct stp_bnode *ptrs[CHILD(BTREE_DEGREE)];
    struct stp_btree_info *tree;
    struct stp_bnode_item *item;
    const struct stp_bnode_operations *ops;
};

extern const struct stp_bnode_operations bnode_operations;
    

/*
 * btree index file layout:
 * superinfo:4KB--4KB--4KB btree-node
 */
#define BTREE_SUPER_SIZE (3*1024)
#define BITMAP_ENTRY  (512)
#define BITMAP_SIZE  (BITMAP_ENTRY * sizeof(u32) * 8)

struct stp_btree_super {
    u32 magic;
    u32 flags;
    u64 total_bytes;
    u32 nritems;//btree node number
    u32 bitmap[BITMAP_ENTRY];
    struct stp_bnode_item root;
} __attribute__((__packed__));

#define BTREE_MAX_NODE (BITMAP_ENTRY * 32)
#define BTREE_TOTAL_SIZE (BTREE_MAX_NODE*(sizeof(struct stp_bnode_item))\
                          + BTREE_SUPER_SIZE)   

struct stp_btree_info;
    

struct stp_btree_operations {
    int (*init)(struct stp_btree_info *);
    struct stp_bnode* (*allocate)(struct stp_btree_info *,off_t offset);
    int (*read)(struct stp_btree_info *,struct stp_bnode *,off_t offset);
    int (*sync)(struct stp_btree_info *);
    int (*write)(struct stp_btree_info *,struct stp_bnode *);
    struct stp_bnode ** (*search)(struct stp_btree_info *,u64 ino);
    int (*insert)(struct stp_btree_info *,u64 ino,size_t size,off_t offset);
    int (*rm)(struct stp_btree_info *,u64 ino);
    int (*destroy)(struct stp_btree_info *);
};

extern const struct stp_btree_operations stp_btree_super_operations;
    

struct stp_btree_info {
    const char *filename;
    int fd;
    u8 mode;
    u64 transid;
    sem_t sem;
    u32 active;//item in memory
    pthread_mutex_t mutex;
    struct stp_btree_super *super;
    struct stp_bnode *root;
    struct list node_list;
    struct list node_lru;
    struct list dirty_list;
    const struct stp_btree_operations *ops;//node operations
};

typedef struct {
    struct stp_fs_info *fs;
    struct stp_btree_info *tree;
}STP_FILE_INFO;

#define STP_FS_READ  (1<<0)
#define STP_FS_WRITE (1<<1)
#define STP_FS_RDWR  (1<<2)
#define STP_FS_CREAT (1<<3)

typedef unsigned int stp_error;

extern stp_error stp_errno;

typedef STP_FILE_INFO* STP_FILE;
    

#ifdef __cplusplus
}
#endif

#endif
