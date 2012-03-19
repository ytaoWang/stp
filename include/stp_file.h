#ifndef __STP_FILE_H__
#define __STP_FILE_H__

#include "stp_types.h"

#include <pthread.h>
#include <semaphore.h>

/*
 * every object(meta_item or btree_item) has a header to indicate where the node is.
 */
struct stp_header {
    u64 start;
    u64 offset;
    u8 flags;
    u32 nritems;
}__attribute__((__packed__));

/*
 * directory item in directory
 */
#define DIR_LEN 128

struct stp_dir_item {
    u64 ino;
    u32 name_len;
    char name[DIR_LEN];
}__attribute__((__packed__));

/*
 * inode item in disk
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
} __attribute__((__packed__));

/*
 * meta file super block
 *
 */
struct stp_fs_super {
    u32 flags;
    u64 total_bytes;
    u64 bytes_used;
    u64 bytes_hole;
    u32 nritems;//number item
    u32 nrdelete;//delete item number
    struct stp_inode_item root;
} __attribute__((__packed__));

struct stp_btree_super {
    u32 flags;
    u64 total_bytes;
    u32 nritems;//btree node number
    struct stp_bnode_item root;
} __attribute__((__packed__));

struct stp_bnode_key {
    u64 ino;
    u8 flags;
    u64 start;
    u64 offset;
} __attribute__((__packed__));

#define BTREE_LEVEL  64    

struct stp_bnode_item {
    struct stp_header location;
    struct stp_bnode_key ptrs[BTREE_LEVEL];
};

    

struct stp_file_info {
    
}
    
    
