/*
 * Copyright (c) 2008-2012 Red Hat, Inc. <http://www.redhat.com>
 * This file is part of GlusterFS.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 3 or any later version (LGPLv3 or
 * later), or the GNU General Public License, version 2 (GPLv2), in All
 * cases as published by the Free Software Foundation.
 *
 * Copyright (c) 2016 XTAO technology <www.xtaotech.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __IO_CACHE_H
#define __IO_CACHE_H

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include "compat-errno.h"

#include "glusterfs.h"
#include "logging.h"
#include "dict.h"
#include "xlator.h"
#include "common-utils.h"
#include "call-stub.h"
#include "rbthash.h"
#include "hashfn.h"
#include <sys/time.h>
#include <fnmatch.h>

#define IOC_DEFAULT_PAGE_SIZE    (1024 * 64)   /* 128KB */
#define IOC_CACHE_SIZE   (32 * 1024 * 1024)
#define IOC_PAGE_TABLE_BUCKET_COUNT 1
#define IOC_STREAM_CAP (64 * IOC_DEFAULT_PAGE_SIZE)

struct ioc_table;
struct ioc_local;
struct ioc_page;
struct ioc_inode;

struct ioc_priority {
        struct list_head list;
        char             *pattern;
        uint32_t         priority;
};

/*
 * ioc_waitq - this structure is used to represents the waiting
 *             frames on a page
 *
 * @next: pointer to next object in waitq
 * @data: pointer to the frame which is waiting
 */
struct ioc_waitq {
        struct ioc_waitq *next;
        void             *data;
        off_t            pending_offset;
        size_t           pending_size;
	uint64_t	 generation;
};

/*
 * ioc_fill -
 *
 */
struct ioc_fill {
        struct list_head list;  /* list of ioc_fill structures of a frame */
        off_t            offset;
        size_t           size;
        struct iovec     *vector;
        int32_t          count;
        struct iobref    *iobref;
};

struct ioc_local {
        mode_t           mode;
        int32_t          flags; 
        int32_t          wbflags;
        loc_t            file_loc;
        off_t            offset;
        size_t           size;
        int32_t          op_ret;
        int32_t          op_errno;
        struct list_head fill_list;      /* list of ioc_fill structures */
        off_t            pending_offset; /*
                                          * offset from this frame should
                                          * continue
                                          */
        size_t           pending_size;   /*
                                          * size of data this frame is waiting
                                          * on
                                          */
        struct ioc_inode *inode;
        int32_t          wait_count;
        pthread_mutex_t  local_lock;
        struct ioc_waitq *waitq;
        void             *stub;
        fd_t             *fd;
        int32_t          need_xattr;
        dict_t           *xattr_req;
	uint64_t	 generation;
#ifdef PERF_STATS
	struct timeval	 start;
#endif
};



/*
 * ioc_page - structure to store page of data from file
 *
 */
#define IOC_PAGE_STATE_INIT   0x0
#define IOC_PAGE_STATE_CLEAN  0x1
#define IOC_PAGE_STATE_DIRTY  0x2
#define IOC_PAGE_STATE_INTRAN 0x4

struct ioc_page {
        struct list_head    page_lru;
        struct ioc_inode    *inode;   /* inode this page belongs to */
        struct ioc_priority *priority;
	char		    state:4;
	char		    eof:4;
        struct iovec        *vector;
        int32_t             count;
        off_t               offset;
        size_t              size;
        struct ioc_waitq    *waitq;
        struct iobref       *iobref;
	uint64_t	    gen; /* increase on every cache flush */
        pthread_mutex_t     page_lock;
};

struct ioc_cache {
        rbthash_table_t  *page_table;
        struct list_head  page_lru;
        time_t            mtime;       /*
                                        * seconds component of file mtime
                                        */
        time_t            mtime_nsec;  /*
                                        * nanosecond component of file mtime
                                        */
        struct timeval    tv;          /*
                                        * time-stamp at last re-validate
                                        */
};

typedef enum ioc_fetch_dirn {
	GFFETCH_FORWARD = 1,		/* prefetch increasing */
	GFFETCH_BACKWARD = -1		/* prefetch decreasing */
} ioc_fetch_dirn_t;

typedef struct ioc_stream {
	struct list_head list;
	uint64_t	offset;	/* offset of starting */
	uint64_t	len;	/* length of range */
	uint64_t	stride;	/* length of stride */
	uint64_t	poffset;/* prefetch offset */
	struct timeval  last;
	ioc_fetch_dirn_t direction;
	pthread_mutex_t	lock;	/* protects stream */
} ioc_stream_t;

struct ioc_inode {
        struct ioc_table      *table;
        off_t                  ia_size;
        struct ioc_cache       cache;
        struct list_head       inode_list; /*
                                            * list of inodes, maintained by
                                            * io-cache translator
                                            */
        struct list_head       inode_lru;
        struct ioc_waitq      *waitq;
        pthread_mutex_t        inode_lock;
        uint32_t               weight;      /*
                                             * weight of the inode, increases
                                             * on each read
                                             */
	pthread_rwlock_t       stream_lock;  /*
					      * to protect streams
					      */
	uint32_t               stream_cnt;    /* active stream count */
	struct list_head       streams;       /* stream list */
};

struct ioc_table {
        uint64_t         page_size;
        uint64_t         cache_size;
        uint64_t         cache_used;
        uint64_t         water_mark;
        int64_t          min_file_size;
        int64_t          max_file_size;
	uint64_t	 nocache_throttle;
        struct list_head inodes; /* list of inodes cached */
        struct list_head active;
        struct list_head *inode_lru;
        struct list_head priority_list;
        int32_t          readv_count;
        uint32_t          ra_pagecnt; /* prefetch page count */
        pthread_mutex_t  table_lock;
        xlator_t         *xl;
        uint32_t         inode_count;
        int32_t          cache_timeout;
        int32_t          max_pri;
	uint32_t	 gen;
	uint32_t	 max_streams;
        struct mem_pool  *mem_pool;
        gf_boolean_t     fetch_status;
#ifdef PERF_STATS
	uint64_t	faultcnt;
	uint64_t	hitcnt;
	uint64_t	readcnt;
	uint64_t        conticnt;
	uint64_t	pagecnt;
	uint64_t	waitcnt;
	uint64_t	timeoutcnt;
	uint64_t	wasteracnt;
	double		elapsed;
#endif
};

typedef struct ioc_table ioc_table_t;
typedef struct ioc_local ioc_local_t;
typedef struct ioc_page ioc_page_t;
typedef struct ioc_inode ioc_inode_t;
typedef struct ioc_waitq ioc_waitq_t;
typedef struct ioc_fill ioc_fill_t;

void *
str_to_ptr (char *string);

char *
ptr_to_str (void *ptr);

int32_t
ioc_readv_disabled_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                        int32_t op_ret, int32_t op_errno, struct iovec *vector,
                        int32_t count, struct iatt *stbuf,
                        struct iobref *iobref, dict_t *xdata);

ioc_page_t *
__ioc_page_get (ioc_inode_t *ioc_inode, off_t offset);

ioc_page_t *
__ioc_page_create (ioc_inode_t *ioc_inode, off_t offset);

void
ioc_page_fault (ioc_inode_t *ioc_inode, call_frame_t *frame, fd_t *fd,
                off_t offset, uint64_t generation, char flags);
void
__ioc_wait_on_page (ioc_page_t *page, call_frame_t *frame, off_t offset,
		    size_t size);

ioc_waitq_t *
__ioc_page_wakeup (ioc_page_t *page, uint64_t generation);

void
ioc_page_flush (ioc_page_t *page);

ioc_waitq_t *
__ioc_page_error (ioc_page_t *page, int32_t op_ret, int32_t op_errno,
    uint64_t generation, int *destroy_size);

void
ioc_frame_return (call_frame_t *frame);

void
ioc_waitq_return (ioc_waitq_t *waitq);

int32_t
ioc_frame_fill (ioc_page_t *page, call_frame_t *frame, off_t offset,
                size_t size);

#define ioc_inode_lock(ioc_inode)                                       \
        do {                                                            \
                gf_log (ioc_inode->table->xl->name, GF_LOG_TRACE,       \
                        "locked inode(%p)", ioc_inode);                 \
                pthread_mutex_lock (&ioc_inode->inode_lock);            \
        } while (0)


#define ioc_inode_unlock(ioc_inode)                                     \
        do {                                                            \
                gf_log (ioc_inode->table->xl->name, GF_LOG_TRACE,       \
                        "unlocked inode(%p)", ioc_inode);               \
                pthread_mutex_unlock (&ioc_inode->inode_lock);          \
        } while (0)


#define ioc_table_lock(table)                                   \
        do {                                                    \
                gf_log (table->xl->name, GF_LOG_TRACE,          \
                        "locked table(%p)", table);             \
                pthread_mutex_lock (&table->table_lock);        \
        } while (0)


#define ioc_table_unlock(table)                                 \
        do {                                                    \
                gf_log (table->xl->name, GF_LOG_TRACE,          \
                        "unlocked table(%p)", table);           \
                pthread_mutex_unlock (&table->table_lock);      \
        } while (0)


#define ioc_local_lock(local)                                           \
        do {                                                            \
                gf_log (local->inode->table->xl->name, GF_LOG_TRACE,    \
                        "locked local(%p)", local);                     \
                pthread_mutex_lock (&local->local_lock);                \
        } while (0)


#define ioc_local_unlock(local)                                         \
        do {                                                            \
                gf_log (local->inode->table->xl->name, GF_LOG_TRACE,    \
                        "unlocked local(%p)", local);                   \
                pthread_mutex_unlock (&local->local_lock);              \
        } while (0)


#define ioc_page_lock(page)                                             \
        do {                                                            \
                gf_log (page->inode->table->xl->name, GF_LOG_TRACE,     \
                        "locked page(%p)", page);                       \
                pthread_mutex_lock (&page->page_lock);                  \
        } while (0)


#define ioc_page_unlock(page)                                           \
        do {                                                            \
                gf_log (page->inode->table->xl->name, GF_LOG_TRACE,     \
                        "unlocked page(%p)", page);                     \
                pthread_mutex_unlock (&page->page_lock);                \
        } while (0)


static inline uint64_t
time_elapsed (struct timeval *now,
              struct timeval *then)
{
        uint64_t sec = now->tv_sec - then->tv_sec;

        if (sec)
                return sec;

        return 0;
}

ioc_inode_t *
ioc_inode_search (ioc_table_t *table, inode_t *inode);

void
ioc_inode_destroy (ioc_inode_t *ioc_inode);

ioc_inode_t *
ioc_inode_update (ioc_table_t *table, inode_t *inode, uint32_t weight);

int64_t
__ioc_page_destroy (ioc_page_t *page);

int64_t
__ioc_inode_flush (ioc_inode_t *ioc_inode);

void
ioc_inode_flush (ioc_inode_t *ioc_inode);

void
ioc_inode_wakeup (call_frame_t *frame, ioc_inode_t *ioc_inode,
                  struct iatt *stbuf);

int8_t
ioc_cache_still_valid (ioc_inode_t *ioc_inode, struct iatt *stbuf);

int32_t
ioc_prune (ioc_table_t *table);

int32_t
ioc_need_prune (ioc_table_t *table);

uint32_t
ioc_hashfn (void *data, int len);

void
ioc_fetch_free(ioc_inode_t *ioc_inode);

int
ioc_fetch (ioc_inode_t *ioc_inode, ioc_stream_t *st);

#endif /* __IO_CACHE_H */
