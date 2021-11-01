/*
  Copyright (c) 2017, XTAO Technology Inc. <http://www.xtaotech.com>

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

/*
 * performance/readdir-preload preloads a local buffer with directory entries
 * on readdirp request from NFS. The optimization involves using maximum
 * sized gluster rpc requests (128k) to minimize overhead of smaller client
 * requests.
 *
 *
 * The translator is currently designed to handle the simple, sequential case
 * only. If a non-sequential directory read occurs, readdir-preload disables
 * preloads on the directory.
 */

#ifndef _CONFIG_H
#define _CONFIG_H

#include "config.h"

#endif
#include <sys/syscall.h>
#include <math.h>
#include "glusterfs.h"
#include "xlator.h"
#include "call-stub.h"
#include "readdir-preload.h"
#include "readdir-preload-mem-types.h"
#include "defaults.h"
#include "readdir-preload-messages.h"

static int rdp_fill_st(call_frame_t *, xlator_t *, struct rdp_stream *, fd_t *);

/*
 * Reset the tracking state of the inode context stream.
 * with stream->lock held
 */
static void
rdp_stream_reset(xlator_t *this, struct rdp_stream *st, off_t offset) {
        struct rdp_priv *priv = NULL;

        priv = this->private;

        st->state = RDP_ST_NEW;
        st->cur_offset = offset;
        st->next_offset = offset;
        st->op_errno = 0;

        gf_dirent_free(&st->entries);
        atomic_sub(&priv->rdp_cache_size, st->cur_size);
        st->cur_size = 0;
        st->fill_count = 0;
}

static size_t
__rdp_stream_part_reset(xlator_t *this, struct rdp_stream *st, off_t offset, gf_dirent_t *prune_entries) {
        struct rdp_priv *priv = NULL;
        size_t stream_size = 0;

        priv = this->private;

        st->state = RDP_ST_NEW;
        st->cur_offset = offset;
        st->next_offset = offset;
        st->op_errno = 0;

        list_splice_init(&st->entries.list, &prune_entries->list);
        atomic_sub(&priv->rdp_cache_size, st->cur_size);
        stream_size = st->cur_size;
        st->cur_size = 0;
        st->fill_count = 0;

        return stream_size;
}


static uint64_t
__rdp_stream_prune(xlator_t *this, rdp_inode_t *rdp_inode, gf_dirent_t *entries) {
        rdp_stream_t *walk = NULL;
        rdp_stream_t *tmp = NULL;
        struct timeval now = {0,};
        struct list_head tmp_list  = {0,};
        uint64_t prune_size = 0;
        gf_boolean_t prune = _gf_false;

        INIT_LIST_HEAD (&tmp_list);

        list_for_each_entry_safe(walk, tmp, &rdp_inode->streams, list) {
                prune = _gf_false;
                if (walk->ref != 0) {
                        continue;
                }

                LOCK(&walk->lock);
                {
                        if ((walk->state & RDP_ST_EOD) && (walk->cur_size) == 0) {
                                gf_log(this->name, GF_LOG_DEBUG, "end of directory, remove the stream %p", walk);
                                prune = _gf_true;
                                list_move_tail(&walk->list, &tmp_list);
                                rdp_inode->stream_cnt--;
                        } else {
                                gettimeofday(&now, NULL);
                                if (now.tv_sec - walk->last.tv_sec > RDP_STREAM_TIMEOUT) {
                                        gf_log(this->name, GF_LOG_DEBUG, "timeout, remove the stream time %d  now time %d %p", (int32_t)walk->last.tv_sec,
                                               (int32_t)now.tv_sec, walk);
                                        prune = _gf_true;
                                        list_move_tail(&walk->list, &tmp_list);
                                        rdp_inode->stream_cnt--;
                                }
                        }
                }
                UNLOCK(&walk->lock);
                if (prune) {
                        walk->prune = _gf_true;
                }
        }

        list_for_each_entry_safe(walk, tmp, &tmp_list, list) {
                prune_size += (uint64_t) __rdp_stream_part_reset(this, walk, 0, entries);
                list_del(&walk->list);
                LOCK_DESTROY(&walk->lock);
                GF_FREE(walk);
        }

        return prune_size;
}


/*
 * Get (or create) the inode context for storing readdir
 * preload streams.
 */
static
rdp_inode_t *__get_rdp_inode_ctx(inode_t *inode, xlator_t *this) {
        uint64_t tmp_rdp_inode = 0;
        rdp_inode_t *rdp_inode = NULL;

        __inode_ctx_get(inode, this, &tmp_rdp_inode);
        rdp_inode = (rdp_inode_t *) (long) tmp_rdp_inode;

        if (!rdp_inode) {
                rdp_inode = GF_CALLOC(1, sizeof(struct rdp_inode), gf_rdp_mt_rdp_inode);
                if (!rdp_inode) {
                        goto out;
                }

                INIT_LIST_HEAD(&rdp_inode->inode_lru);
                INIT_LIST_HEAD(&rdp_inode->streams);
                pthread_rwlock_init(&rdp_inode->stream_lock, NULL);
                rdp_inode->stream_cnt = 0;
                rdp_inode->cached = _gf_false;
                __inode_ctx_put(inode, this, (uint64_t) (long) rdp_inode);
        }
out:
        return rdp_inode;
}

static void
rdp_inode_update(inode_t *inode, rdp_inode_t *rdp_inode, xlator_t *this) {
        struct rdp_priv *priv = this->private;

        GF_VALIDATE_OR_GOTO("readdir-preload", priv, out);
        if (!rdp_inode || !inode) {
                return;
        }

        rdp_priv_lock(priv);
        {
                pthread_rwlock_wrlock(&rdp_inode->stream_lock);
                {
                        if (rdp_inode->cached) {
                                list_move_tail(&rdp_inode->inode_lru, &priv->inode_lru);
                        } else {
                                list_add_tail(&rdp_inode->inode_lru, &priv->inode_lru);
                                rdp_inode->cached = _gf_true;
                                rdp_inode->inode = inode_ref(inode);
                        }
                }
                pthread_rwlock_unlock(&rdp_inode->stream_lock);
        }
        rdp_priv_unlock(priv);

out:
        return;
}


void
rdp_try_prune(struct rdp_priv *priv, inode_t *inode) {
        rdp_inode_t *curr = NULL, *next_rdp_inode = NULL;
        uint64_t size_to_prune = 0;
        uint32_t size_pruned = 0;
        uint64_t cache_difference = 0;
        gf_dirent_t prune_entries;
        INIT_LIST_HEAD(&prune_entries.list);


        if (!priv) {
                return;
        }

        rdp_priv_lock(priv);
        {
                cache_difference = priv->rdp_cache_size - priv->rdp_cache_limit;
                if (cache_difference <= 0) {
                        goto unlock;
                }

                size_to_prune = priv->rdp_cache_size - priv->rdp_cache_wmark;
                list_for_each_entry_safe(curr, next_rdp_inode, &priv->inode_lru, inode_lru) {
                        if (pthread_rwlock_trywrlock(&curr->stream_lock)) {
                                continue;
                        }
                        {
                                size_pruned += __rdp_stream_prune(priv->xl, curr, &prune_entries);
                                if (curr->stream_cnt == 0) {
                                        curr->cached = _gf_false;
                                        inode_unref(curr->inode);
                                        list_del(&curr->inode_lru);
                                }
                        }
                        pthread_rwlock_unlock(&curr->stream_lock);
                        if (size_pruned >= size_to_prune) {
                                break;
                        }
                }
        }
unlock:
        rdp_priv_unlock(priv);

        gf_dirent_free(&prune_entries);
}


static rdp_stream_t *
__rdp_stream_create(off_t offset, rdp_inode_t *rdp_inode) {
        rdp_stream_t *st = NULL;
        st = GF_CALLOC(1, sizeof(struct rdp_stream), gf_rdp_mt_rdp_stream);
        if (!st)
                goto out;

        LOCK_INIT(&st->lock);
        INIT_LIST_HEAD(&st->entries.list);
        st->state = RDP_ST_NEW;
        st->cur_offset = offset;
        st->next_offset = offset;
        st->rdp_inode = rdp_inode;
out:
        return st;
}

static rdp_stream_t *
__rdp_st_ref(rdp_stream_t *st) {
        if (!st) {
                return NULL;
        }

        if (st->prune) {
                return NULL;
        } else {
                ++st->ref;
        }

        return st;
}

/*
 * reclaim stream, if the stream is timed out or is
 * reach end of directory && cur_size is 0.
 * with rdp_inode->stream_lock write lock held
 */
static rdp_stream_t *
__rdp_stream_reclaim(xlator_t *this, rdp_inode_t *rdp_inode, off_t offset, gf_dirent_t *prune_entries) {
        rdp_stream_t *st = NULL;
        rdp_stream_t *walk = NULL;
        rdp_stream_t *tmp = NULL;
        struct timeval now = {0,};

        list_for_each_entry_safe(walk, tmp, &rdp_inode->streams, list) {
                if (walk->ref != 0) {
                        continue;
                }

                LOCK(&walk->lock);
                {
                        if ((walk->state & RDP_ST_EOD) && (walk->cur_size == 0)) {
                                st = walk;
                                __rdp_stream_part_reset(this, st, offset, prune_entries);
                                UNLOCK(&walk->lock);
                                break;
                        }

                        gettimeofday(&now, NULL);
                        gf_log(this->name, GF_LOG_DEBUG, "timeout =  = %d, reset the stream time %d  now time %d %p",
                               (int32_t)(now.tv_sec - walk->last.tv_sec), (int32_t)walk->last.tv_sec, (int32_t)now.tv_sec, walk);
                        if ((now.tv_sec - walk->last.tv_sec) > RDP_STREAM_TIMEOUT) {
                                st = walk;
                                __rdp_stream_part_reset(this, st, offset, prune_entries);
                                UNLOCK(&walk->lock);
                                break;
                        }
                }
                UNLOCK(&walk->lock);
        }

        if (!st) {
                gf_log(this->name, GF_LOG_DEBUG, "reclaim stream failed");
        }

        return st;
}


static rdp_stream_t *__rdp_stream_new(xlator_t *this, rdp_inode_t *rdp_inode, off_t offset, gf_dirent_t *prune_entries)
{
        struct rdp_priv *priv = this->private;
        rdp_stream_t *st = NULL;

        if (rdp_inode->stream_cnt > (priv->rdp_stream_cnt / 2)) {
                st = __rdp_stream_reclaim(this, rdp_inode, offset, prune_entries);
        }
        if (!st) {
                if (rdp_inode->stream_cnt >= priv->rdp_stream_cnt) {
                        gf_log(this->name, GF_LOG_DEBUG, "stream count is out of range %d", rdp_inode->stream_cnt);
                        goto out;
                }
                st = __rdp_stream_create(offset, rdp_inode);
                list_add_tail(&st->list, &rdp_inode->streams);
                rdp_inode->stream_cnt++;
                if (!st) {
                        gf_log(this->name, GF_LOG_DEBUG, "new stream failed!");

                        goto out;
                }
                gf_log(this->name, GF_LOG_DEBUG, "insert new stream.");
        }
out:
        return st;
}

/*
 * find a stream, if offset is 0, it's probobaly a new start of stream,
 * reclaim or new a stream; if offset is not 0, search stream list of
 * the rdp_inode, if the stream->cur_offset is requested offset, it's
 * the stream. return NULL stream if no available stream.
 */

static rdp_stream_t *
rdp_stream_find(xlator_t *this, inode_t *inode, off_t offset) {
        rdp_stream_t *target_st = NULL;
        rdp_stream_t *st = NULL;
        rdp_stream_t *walk = NULL;
        rdp_stream_t *tmp = NULL;
        rdp_inode_t *rdp_inode = NULL;
        struct timeval now = {0,};
        gettimeofday(&now, NULL);
        gf_dirent_t prune_entries;
        INIT_LIST_HEAD(&prune_entries.list);

        LOCK(&inode->lock);
        {
                rdp_inode = __get_rdp_inode_ctx(inode, this);
                if (!rdp_inode) {
                        UNLOCK(&inode->lock);
                        gf_log(this->name, GF_LOG_DEBUG, "inode_ctx get failed!");
                        goto out;
                }
        }
        UNLOCK(&inode->lock);

        rdp_inode_update(inode, rdp_inode, this);

        if (pthread_rwlock_trywrlock(&rdp_inode->stream_lock)) {
                gf_log(this->name, GF_LOG_DEBUG, "get stream lock failed!");
                goto out;
        }
        if (!offset) {
                gf_log(this->name, GF_LOG_DEBUG, "offset = 0, first readdir");
                st = __rdp_stream_new(this, rdp_inode, offset, &prune_entries);
        } else {
                list_for_each_entry_safe(walk, tmp, &rdp_inode->streams, list) {
                        LOCK(&walk->lock);
                        {
                                if (!walk->stub && walk->cur_offset == offset &&
                                    ((now.tv_sec - walk->last.tv_sec) < RDP_STREAM_TIMEOUT)) {
                                        st = walk;
                                        UNLOCK(&walk->lock);
                                        break;
                                }
                        }
                        UNLOCK(&walk->lock);
                }

                if (!st) {
                        st = __rdp_stream_new(this, rdp_inode, offset, &prune_entries);
                }
        }

        if (st) {
                target_st = __rdp_st_ref(st);
        }
        gf_log("wangguoqing", GF_LOG_DEBUG, "stream count = %d", rdp_inode->stream_cnt);
        pthread_rwlock_unlock(&rdp_inode->stream_lock);
out:
        gf_dirent_free(&prune_entries);
        return target_st;
}

/*
 * Check whether we can handle a request. Offset verification is done by the
 * caller, so we only check whether the preload buffer has completion status
 * (including an error) or has some data to return.
 */
static gf_boolean_t
__rdp_can_serve_readdirp(struct rdp_stream *st, size_t request_size) {
        if ((st->state & RDP_ST_EOD) ||
            (st->state & RDP_ST_ERROR) ||
            (!(st->state & RDP_ST_PLUGGED) && (st->cur_size > 0)) ||
            (request_size && st->cur_size >= request_size))
                return _gf_true;

        return _gf_false;
}

/*
 * Serve a request from the stream dentry list based on the size of the request
 * buffer. stream must be locked.
 */
static int32_t
__rdp_fill_readdirp(xlator_t *this, gf_dirent_t *entries, size_t request_size,
                    struct rdp_stream *st) {
        gf_dirent_t *dirent, *tmp;
        gf_dirent_t *dst_dirent;
        size_t dirent_size, size = 0;
        int32_t count = 0;
        struct rdp_priv *priv = NULL;
        gf_boolean_t nfs_client_page_full = _gf_false;

        priv = this->private;

        list_for_each_entry_safe(dirent, tmp, &st->entries.list, list) {
                dirent_size = gf_dirent_size(dirent->d_name);
                if (size + dirent_size > request_size) {
                        break;
                }
                gf_log(this->name, GF_LOG_DEBUG, "next off = %ld, d_name = %s", dirent->d_off, dirent->d_name);
                size += dirent_size;
                st->fill_count ++;
                if (st->fill_count <= NFS_CLIENT_MAX_COUNT_PER_PAGE) {
                        list_del_init(&dirent->list);
                        st->cur_size -= dirent_size;

                        atomic_sub(&priv->rdp_cache_size, dirent_size);
                        list_add_tail(&dirent->list, &entries->list);
                        st->cur_offset = dirent->d_off;
                } else {
                        if (_gf_false == nfs_client_page_full) {
                                nfs_client_page_full = _gf_true;
                        }
                        dst_dirent = entry_copy(dirent);
                        list_add_tail(&dst_dirent->list, &entries->list);
                }

                count++;
        }

        if (nfs_client_page_full) {
                st->fill_count = 0;
        }

        if (st->cur_size <= priv->rdp_low_wmark){
                st->state |= RDP_ST_PLUGGED;
        }

        return count;
}

/*
 * with the stream->lock held
 */
static int32_t
__rdp_serve_readdirp(xlator_t *this, struct rdp_stream *st, size_t size,
                     gf_dirent_t *entries, int *op_errno) {
        int32_t ret = 0;
        struct timeval now = {0,};

        ret = __rdp_fill_readdirp(this, entries, size, st);
        gf_log(this->name, GF_LOG_DEBUG, "next expect offset = %ld", st->cur_offset);

        if (!ret && (st->state & RDP_ST_ERROR)) {
                ret = -1;
                st->state &= ~RDP_ST_ERROR;

                /*
                 * the preload has stopped running in the event of an error, so
                 * pass all future requests along
                 */
                st->state |= RDP_ST_BYPASS;
        } else {
                gettimeofday(&now, NULL);
                gf_log(this->name, GF_LOG_DEBUG, "update  the stream time %d, stream = %p", (int32_t)now.tv_sec, st);
                st->last.tv_sec = now.tv_sec;
        }

        /*
         * Use the op_errno sent by lower layers as xlators above will check
         * the op_errno for identifying whether readdir is completed or not.
         */
        *op_errno = st->op_errno;

        return ret;
}

static void
rdp_st_unref(rdp_stream_t *st) {
        rdp_inode_t *rdp_inode = NULL;
        if (!st) {
                return;
        }

        rdp_inode = st->rdp_inode;
        if (!rdp_inode) {
                return;
        }

        pthread_rwlock_wrlock(&rdp_inode->stream_lock);
        {
                --st->ref;
        }
        pthread_rwlock_unlock(&rdp_inode->stream_lock);


}

static int32_t
rdp_readdirp(call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
             off_t off, dict_t *xdata) {
        rdp_stream_t *st = NULL;
        int fill = 0;
        gf_dirent_t entries;
        int ret = 0;
        int op_errno = 0;
        gf_boolean_t serve = _gf_false;
        struct rdp_priv *priv = this->private;
        fd_t *tmp_fd = NULL;

        if (!priv) {
                goto bypass;
        }

        if (priv->special_client_active) {
                if (frame->root->pid != NFS_HIGH_PRIO_PROC_PID) {
                        goto bypass;
                }
        }

        if (!fd->inode) {
                gf_log(this->name, GF_LOG_DEBUG, "inode does not exists!");
                goto bypass;
        }

        st = rdp_stream_find(this, fd->inode, off);
        if (!st) {
                gf_log(this->name, GF_LOG_DEBUG, "can't get stream");
                goto bypass;
        }

        INIT_LIST_HEAD (&entries.list);

        LOCK(&st->lock);
        {
                /* recheck now that we have the lock */
                if (st->state & RDP_ST_BYPASS) {
                        gf_log(this->name, GF_LOG_DEBUG, "st state is bypass, off=%ld, stream cur_offset=%ld", off, st->cur_offset);
                        UNLOCK(&st->lock);
                        goto bypass;
                }

                /*
                 * If a new read comes in at offset 0 and the buffer has been
                 * completed, reset the context and kickstart the filler again.
                 */
                if (!off && (st->state & (RDP_ST_NEW | RDP_ST_EOD)) && (st->cur_size == 0)) {
                        fill = 1;
                }

                /*
                 * If a readdir occurs at an unexpected offset or we already have a
                 * request pending, admit defeat and just get out of the way.
                 */
                if (st->stub || st->cur_offset != off) {
                        gf_log(this->name, GF_LOG_DEBUG, "stream has stub, off=%ld, stream cur_offset=%ld", off, st->cur_offset);
                        UNLOCK(&st->lock);
                        goto bypass;
                }

                /*
                 * If we haven't bypassed the preload, this means we can either serve
                 * the request out of the preload or the request that enables us to do
                 * so is in flight...
                 */
                if (__rdp_can_serve_readdirp(st, size)) {
                        ret = __rdp_serve_readdirp(this, st, size, &entries,
                                                   &op_errno);
                        gf_log(this->name, GF_LOG_DEBUG, "hit stream %p, tid:%ld", st, syscall(SYS_gettid));
                        serve = _gf_true;

                        if (op_errno == ENOENT && !((st->state & RDP_ST_EOD) && (st->cur_size == 0))) {
                                op_errno = 0;
                        }
                } else {
                        gf_log(this->name, GF_LOG_DEBUG, "stub the readdir, off = %ld", off);
                        st->stub = fop_readdirp_stub(frame, NULL, fd, size, off,
                                                     xdata);
                        if (!st->stub) {
                                UNLOCK(&st->lock);
                                goto err;
                        }

                        if (!(st->state & RDP_ST_RUNNING)) {
                                fill = 1;
                                st->state |= RDP_ST_RUNNING;
                        }
                }

        }
        UNLOCK(&st->lock);

        if (serve) {
                tmp_fd = fd_ref(fd);
                STACK_UNWIND_STRICT (readdirp, frame, ret, op_errno, &entries,
                                     xdata);
                gf_dirent_free(&entries);
        }

        if (fill) {
                ret = rdp_fill_st(frame, this, st, fd);
                if (ret) {
                        goto err;
                }
        } else {
                if (st) {
                        rdp_st_unref(st);
                }
                gf_log(this->name, GF_LOG_DEBUG, "try to prune the stream...");
                rdp_try_prune(priv, fd->inode);
        }

        if (tmp_fd) {
                fd_unref(tmp_fd);
                tmp_fd = NULL;
        }
        return 0;

bypass:
        if (st) {
                rdp_st_unref(st);
        }
        gf_log(this->name, GF_LOG_DEBUG, "miss the cache, off = %ld", off);
        STACK_WIND(frame, default_readdirp_cbk, FIRST_CHILD(this),
                   FIRST_CHILD(this)->fops->readdirp, fd, size, off, xdata);
        return 0;

err:
        if (st) {
                rdp_st_unref(st);
        }
        STACK_UNWIND_STRICT(readdirp, frame, -1, ENOMEM, NULL, NULL);
        return 0;
}

void
rdp_st_local_wipe(rdp_local_t * rdp_local) {
        if (!rdp_local) {
                return;
        }

        if (rdp_local->fd) {
                fd_unref(rdp_local->fd);
        }

        if (rdp_local->stream) {
                rdp_local->stream = NULL;
        }

        mem_put(rdp_local);
}

static int32_t
rdp_fill_st_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, gf_dirent_t *entries,
                dict_t *xdata) {
        struct rdp_priv *priv = this->private;
        gf_dirent_t *dirent = NULL, *tmp = NULL;
        gf_dirent_t serve_entries;
        rdp_local_t *local = frame->local;
        rdp_stream_t *st = local->stream;
        fd_t *fd = fd_ref(local->fd);
        inode_t *inode = fd->inode;
        int fill = 1;
        size_t dirent_size = 0;
        int ret = 0;
        gf_boolean_t serve = _gf_false;
        call_stub_t *stub = NULL;
        rdp_local_t *rdp_local = NULL;
        gf_boolean_t local_wipe = _gf_false;

        INIT_LIST_HEAD (&serve_entries.list);
        LOCK(&st->lock);
        {
                /* Verify that the preload buffer is still pending on this data. */
                if (st->next_offset != local->offset) {
                        gf_msg(this->name, GF_LOG_ERROR,
                               0, READDIR_PRELOAD_MSG_OUT_OF_SEQUENCE,
                               "Out of sequence directory preload.");
                        gf_log(this->name, GF_LOG_ERROR, "st next offset = %ld, local->offset = %ld", st->next_offset, local->offset);
                        st->state |= (RDP_ST_BYPASS | RDP_ST_ERROR);
                        st->op_errno = EUCLEAN;
                        UNLOCK(&st->lock);
                        goto out;
                }

                if (entries) {
                        list_for_each_entry_safe(dirent, tmp, &entries->list, list) {
                                list_del_init(&dirent->list);
                                /* must preserve entry order */
                                list_add_tail(&dirent->list, &st->entries.list);

                                dirent_size = gf_dirent_size (dirent->d_name);

                                st->cur_size += dirent_size;

                                atomic_add(&priv->rdp_cache_size, dirent_size);
                                st->next_offset = dirent->d_off;
                        }
                }

                if (st->cur_size >= priv->rdp_high_wmark)
                        st->state &= ~RDP_ST_PLUGGED;

                if (!op_ret || op_errno == ENOENT) {
                        /* we've hit eod */
                        st->state &= ~RDP_ST_RUNNING;
                        st->state |= RDP_ST_EOD;
                        st->op_errno = op_errno;
                } else if (op_ret == -1) {
                        /* kill the preload and pend the error */
                        st->state &= ~RDP_ST_RUNNING;
                        st->state |= RDP_ST_ERROR;
                        st->op_errno = op_errno;
                }

                /*
                * NOTE: The strict bypass logic in readdirp() means a pending request
                * is always based on st->cur_offset.
                */
                if (st->stub && __rdp_can_serve_readdirp(st, st->stub->args.size)) {
                        gf_log(this->name, GF_LOG_DEBUG, "server the stub readdir, off = %ld", st->stub->args.offset);
                        ret = __rdp_serve_readdirp(this, st, st->stub->args.size, &serve_entries, &op_errno);
                        serve = _gf_true;
                        stub = st->stub;
                        st->stub = NULL;
                }

out:
                /*
                * If we have been marked for bypass and have no pending stub, clear the
                * run state so we stop preloading the context with entries.
                */
                if (!st->stub && ((st->state & RDP_ST_BYPASS) || (atomic_get(&priv->rdp_cache_size) > priv->rdp_cache_limit)))
                        st->state &= ~RDP_ST_RUNNING;

                if (!(st->state & RDP_ST_RUNNING)) {
                        fill = 0;
                        if (st->fill_frame) {
                                rdp_local = st->fill_frame->local;
                                st->fill_frame->local = NULL;
                                local_wipe = _gf_true;
                                STACK_DESTROY(st->fill_frame->root);
                                st->fill_frame = NULL;
                        }
                }

                if (op_errno == ENOENT && !((st->state & RDP_ST_EOD) && (st->cur_size == 0))) {
                        op_errno = 0;
                }
        }
        UNLOCK(&st->lock);

        if (rdp_local && local_wipe) {
                rdp_st_local_wipe(rdp_local);
        }

        if (serve) {
                STACK_UNWIND_STRICT (readdirp, stub->frame, ret, op_errno,
                                     &serve_entries, xdata);
                gf_dirent_free(&serve_entries);
                call_stub_destroy(stub);
        }

        if (fill) {
                rdp_fill_st(frame, this, st, fd);
        } else {
                if (st) {
                        rdp_st_unref(st);
                }
        }

        gf_log(this->name, GF_LOG_DEBUG, "try to prune the stream...");
        rdp_try_prune(priv, inode);

        if (fd) {
                fd_unref(fd);
        }

        return 0;
}


/*
 * Start prepopulating the stream with directory entries.
 */
static int
rdp_fill_st(call_frame_t *frame, xlator_t *this, struct rdp_stream *st, fd_t *fd) {
        call_frame_t *nframe = NULL;
        struct rdp_local *local = NULL;
        off_t offset;
        struct rdp_priv *priv = this->private;

        if (!st)
                goto err;

        LOCK(&st->lock);
        {
                if (st->state & RDP_ST_NEW) {
                        st->state &= ~RDP_ST_NEW;
                        st->state |= RDP_ST_RUNNING;
                        if (priv->rdp_low_wmark)
                                st->state |= RDP_ST_PLUGGED;
                }

                offset = st->next_offset;

                if (!st->fill_frame) {
                        nframe = copy_frame(frame);
                        if (!nframe) {
                                UNLOCK(&st->lock);
                                goto err;
                        }

                        local = mem_get0(this->local_pool);
                        if (!local) {
                                UNLOCK(&st->lock);
                                goto err;
                        }

                        local->stream = st;
                        local->fd = fd_ref(fd);
                        nframe->local = local;
                        st->fill_frame = nframe;
                } else {
                        nframe = st->fill_frame;
                        local = nframe->local;
                }
        }
        UNLOCK(&st->lock);

        local->offset = offset;


        STACK_WIND(nframe, rdp_fill_st_cbk, FIRST_CHILD(this),
                   FIRST_CHILD(this)->fops->readdirp, fd,
                   priv->rdp_req_size, offset, NULL);

        return 0;

err:
        if (nframe) {
                rdp_st_local_wipe(nframe->local);
                FRAME_DESTROY(nframe);
        }

        return -1;
}

static int32_t
rdp_forget(xlator_t *this, inode_t *inode) {
        uint64_t tmp_rdp_inode = 0;
        rdp_inode_t *rdp_inode = NULL;
        rdp_stream_t *walk = NULL, *tmp = NULL;
        rdp_local_t *rdp_local = NULL;

        inode_ctx_del(inode, this, &tmp_rdp_inode);
        if (!tmp_rdp_inode) {
                goto out;
        }

        rdp_inode = (rdp_inode_t *) (long) tmp_rdp_inode;

        list_for_each_entry_safe(walk, tmp, &rdp_inode->streams, list) {
                list_del_init(&walk->list);
                rdp_stream_reset(this, walk, 0);
                if (walk->fill_frame) {
                        rdp_local = walk->fill_frame->local;
                        walk->fill_frame->local = NULL;
                        rdp_st_local_wipe(rdp_local);
                        STACK_DESTROY(walk->fill_frame->root);
                        walk->fill_frame = NULL;
                }

                if (walk->stub) {
                        gf_msg(this->name, GF_LOG_CRITICAL, 0,
                               READDIR_PRELOAD_MSG_DIR_RELEASE_PENDING_STUB,
                               "released a directory with a pending stub");
                        call_stub_destroy(walk->stub);
                        walk->stub = NULL;
                }

                GF_FREE(walk);
        }

        out:
        return 0;
}

int32_t
mem_acct_init(xlator_t *this) {
        int ret = -1;

        if (!this)
                goto out;

        ret = xlator_mem_acct_init(this, gf_rdp_mt_end + 1);

        if (ret != 0)
                gf_msg(this->name, GF_LOG_ERROR, ENOMEM,
                       READDIR_PRELOAD_MSG_NO_MEMORY, "Memory accounting init"
                               "failed");

        out:
        return ret;
}

int
reconfigure(xlator_t *this, dict_t *options) {
        struct rdp_priv *priv = NULL;
        int ret = 0;

        if (!this || !this->private) {
                goto out;
        }

        priv = this->private;

        rdp_priv_lock(priv);
        {
                GF_OPTION_RECONF("rdp-special-client", priv->special_client_active, options,
                                 bool, unlock);
                GF_OPTION_RECONF("rdp-request-size", priv->rdp_req_size, options,
                                 uint32, unlock);
                GF_OPTION_RECONF("rdp-stream-count", priv->rdp_stream_cnt, options,
                                 uint32, unlock);
                GF_OPTION_RECONF("rdp-low-wmark", priv->rdp_low_wmark, options,
                                 uint64, unlock);
                GF_OPTION_RECONF("rdp-high-wmark", priv->rdp_high_wmark, options,
                                 uint64, unlock);
                GF_OPTION_RECONF("rdp-cache-limit", priv->rdp_cache_limit, options,
                                 uint64, unlock);
                GF_OPTION_RECONF("rdp-cache-wmark", priv->rdp_cache_wmark, options,
                                 uint64, unlock);
        }
        unlock:
        rdp_priv_unlock(priv);
        out:
        return ret;
}

int
init(xlator_t *this) {
        struct rdp_priv *priv = NULL;

        GF_VALIDATE_OR_GOTO("readdir-preload", this, err);

        if (!this->children || this->children->next) {
                gf_msg(this->name, GF_LOG_ERROR, 0,
                       READDIR_PRELOAD_MSG_XLATOR_CHILD_MISCONFIGURED,
                       "FATAL: readdir-preload not configured with exactly one"
                               " child");
                goto err;
        }

        if (!this->parents) {
                gf_msg(this->name, GF_LOG_WARNING, 0,
                       READDIR_PRELOAD_MSG_VOL_MISCONFIGURED,
                       "dangling volume. check volfile ");
        }

        priv = GF_CALLOC(1, sizeof(struct rdp_priv), gf_rdp_mt_rdp_priv);
        if (!priv)
                goto err;

        priv->xl = this;
        atomic_init(priv->rdp_cache_size, 0);
        INIT_LIST_HEAD(&priv->inode_lru);
        pthread_mutex_init(&priv->lock, NULL);

        this->private = priv;

        this->local_pool = mem_pool_new(struct rdp_local, 32);
        if (!this->local_pool)
                goto err;

        GF_OPTION_INIT("rdp-special-client", priv->special_client_active, bool, err);
        GF_OPTION_INIT("rdp-request-size", priv->rdp_req_size, uint32, err);
        GF_OPTION_INIT("rdp-stream-count", priv->rdp_stream_cnt, uint32, err);
        GF_OPTION_INIT("rdp-low-wmark", priv->rdp_low_wmark, size_uint64, err);
        GF_OPTION_INIT("rdp-high-wmark", priv->rdp_high_wmark, size_uint64, err);
        GF_OPTION_INIT("rdp-cache-wmark", priv->rdp_cache_wmark, size_uint64, err);
        GF_OPTION_INIT("rdp-cache-limit", priv->rdp_cache_limit, size_uint64, err);

        return 0;

        err:
        if (this->local_pool)
                mem_pool_destroy(this->local_pool);
        if (priv)
                GF_FREE(priv);

        return -1;
}


void
fini(xlator_t *this) {
        GF_VALIDATE_OR_GOTO ("readdir-preload", this, out);

        GF_FREE(this->private);

        out:
        return;
}

struct xlator_fops fops = {
        .readdirp      = rdp_readdirp,
};

struct xlator_cbks cbks = {
        .forget      = rdp_forget,
};

struct volume_options options[] = {
        {.key = {"rdp-special-client"},
                .type = GF_OPTION_TYPE_BOOL,
                .default_value = "on",
                .description = "enable/disable readdir-preload for special client"
        },
        {.key = {"rdp-request-size"},
                .type = GF_OPTION_TYPE_SIZET,
                .min = 4096,
                .max = 131072,
                .default_value = "131072",
                .description = "size of buffer in readdirp calls initiated by "
                        "readdir-preload ",
        },
        {.key = {"rdp-stream-count"},
                .type = GF_OPTION_TYPE_INT,
                .min = 2,
                .max = 16,
                .default_value = "8",
                .description = "readdir-preload stream count per inode",
        },
        {.key = {"rdp-low-wmark"},
                .type = GF_OPTION_TYPE_SIZET,
                .min = 0,
                .max = 10 * GF_UNIT_MB,
                .default_value = "4096",
                .description = "the value under which readdir-preload plugs",
        },
        {.key = {"rdp-high-wmark"},
                .type = GF_OPTION_TYPE_SIZET,
                .min = 0,
                .max = 100 * GF_UNIT_MB,
                .default_value = "128KB",
                .description = "the value over which readdir-preload unplugs",
        },
        {.key = {"rdp-cache-wmark"},
                .type = GF_OPTION_TYPE_SIZET,
                .min = 0,
                .max = 100 * GF_UNIT_MB,
                .default_value = "8MB",
                .description = "the water mark of dirents cache by readdir-preload xlator.",
        },
        {.key = {"rdp-cache-limit"},
                .type = GF_OPTION_TYPE_SIZET,
                .min = 0,
                .max = INFINITY,
                .default_value = "10MB",
                .description = "maximum size of cache consumed by readdir-preload "
                        "xlator. This value is global and total memory "
                        "consumption by readdir-preload is capped by this "
                        "value, irrespective of the number/size of "
                        "directories cached",
        },
        {.key = {NULL}},
};


