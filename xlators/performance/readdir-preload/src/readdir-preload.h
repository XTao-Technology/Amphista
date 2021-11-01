/*
  Copyright (c) 2017 XTAO Technology, Inc. <http://www.xtaotech.com>

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#ifndef __READDIR_PRELOAD_H
#define __READDIR_PRELOAD_H

/* state flags */
#define RDP_ST_NEW	(1 << 0)
#define RDP_ST_RUNNING	(1 << 1)
#define RDP_ST_EOD	(1 << 2)
#define RDP_ST_ERROR	(1 << 3)
#define RDP_ST_BYPASS	(1 << 4)
#define RDP_ST_PLUGGED	(1 << 5)

#define NFS_CLIENT_MAX_COUNT_PER_PAGE 102
#define RDP_STREAM_TIMEOUT	3


struct rdp_inode {
    gf_boolean_t	       cached;
    pthread_rwlock_t       stream_lock;  /* to protect streams */
    inode_t	               *inode;
    uint32_t               stream_cnt;    /* active stream count */
    struct list_head       streams;       /* stream list */
    struct list_head       inode_lru;
};

typedef struct rdp_inode rdp_inode_t;

struct rdp_stream {
	struct list_head list;
	gf_lock_t lock;
	off_t cur_offset;	/* current head of the stream */
	size_t cur_size;	/* current size of the preload */
	off_t next_offset;	/* tail of the stream */
	struct timeval last;
	uint32_t state;
	uint32_t ref;
	gf_boolean_t prune;
	rdp_inode_t *rdp_inode;
	gf_dirent_t entries;
	call_frame_t *fill_frame;
	call_stub_t *stub;
	int op_errno;
	int fill_count;
};


struct rdp_local {
	struct rdp_stream *stream;
	fd_t *fd;
	off_t offset;
};

struct rdp_priv {
	gf_boolean_t special_client_active;
	struct list_head inode_lru;
	pthread_mutex_t  lock;
	xlator_t	 *xl;
	uint32_t rdp_req_size;
	uint32_t rdp_stream_cnt;
	uint64_t rdp_low_wmark;
	uint64_t rdp_high_wmark;
	uint64_t rdp_cache_wmark;
	uint64_t rdp_cache_limit;
	uint64_t rdp_cache_size;
};

typedef struct rdp_local rdp_local_t;
typedef struct rdp_stream rdp_stream_t;

#define rdp_priv_lock(priv)                                   \
        do {                                                    \
                gf_log (priv->xl->name, GF_LOG_TRACE,          \
                        "locked priv(%p)", priv);             \
                pthread_mutex_lock (&priv->lock);        \
        } while (0)

#define rdp_priv_unlock(priv)                                 \
        do {                                                    \
                gf_log (priv->xl->name, GF_LOG_TRACE,          \
                        "unlocked priv(%p)", priv);           \
                pthread_mutex_unlock (&priv->lock);      \
        } while (0)


#endif /* __READDIR_PRELOAD_H */
