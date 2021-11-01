/*
 * Copyright (c) 2017 XTAO technology <www.xtaotech.com>
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

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "glusterfs.h"
#include "dict.h"
#include "xlator.h"
#include "dirstat-cache.h"
#include "dsc-mem-types.h"


struct volume_options options[];

/*
 * check if cached stat is timed out, need revalidate
 * assumes dsc_inode is locked
 */
int32_t
_dsc_inode_need_revalidate(dsc_inode_t *dsc_inode, dsc_priv_t *dsc_priv) {
        int8_t need_revalidate = 0;
        struct timeval tv = {0,};

        gettimeofday(&tv, NULL);

        if (time_elapsed(&tv, &dsc_inode->tv) >= dsc_priv->cache_timeout) {
                need_revalidate = 1;
        }
        return need_revalidate;
}

void
_dsc_cache_update_iatt(struct iatt *to, struct iatt *from) {
        if (!from || !to) {
                return;
        }

        to->ia_dev = from->ia_dev;
        gf_uuid_copy(to->ia_gfid, from->ia_gfid);
        to->ia_ino = from->ia_ino;
        to->ia_prot = from->ia_prot;
        to->ia_type = from->ia_type;
        to->ia_nlink = from->ia_nlink;
        to->ia_rdev = from->ia_rdev;
        to->ia_size = from->ia_size;
        to->ia_blksize = from->ia_blksize;
        to->ia_blocks = from->ia_blocks;
        to->ia_uid = from->ia_uid;
        to->ia_gid = from->ia_gid;
        to->ia_mtime = from->ia_mtime;
        to->ia_mtime_nsec = from->ia_mtime_nsec;
        to->ia_ctime = from->ia_ctime;
        to->ia_ctime_nsec = from->ia_ctime_nsec;
        to->ia_atime = from->ia_atime;
        to->ia_atime_nsec = from->ia_atime_nsec;
}


void
_dsc_cache_update(dsc_inode_t *dsc_inode, struct iatt *stbuf) {
        struct iatt *cur_stat = &dsc_inode->stat;
        if (!stbuf) {
                return;
        }

        if (cur_stat->ia_ctime < stbuf->ia_ctime ||
            ((cur_stat->ia_ctime == stbuf->ia_ctime) &&
             (cur_stat->ia_ctime_nsec < stbuf->ia_ctime_nsec))) {
		_dsc_cache_update_iatt(cur_stat, stbuf);
        } else if (cur_stat->ia_ctime == stbuf->ia_ctime &&
                   cur_stat->ia_ctime_nsec == stbuf->ia_ctime_nsec) {
                if (cur_stat->ia_atime < stbuf->ia_atime ||
                    ((cur_stat->ia_atime == stbuf->ia_atime) &&
                     (cur_stat->ia_atime_nsec < stbuf->ia_atime_nsec))) {
                        _dsc_cache_update_iatt(cur_stat, stbuf);
                } else if (cur_stat->ia_atime == stbuf->ia_atime &&
                        cur_stat->ia_atime_nsec == stbuf->ia_atime_nsec) {
                        if (cur_stat->ia_mtime < stbuf->ia_mtime ||
                                ((cur_stat->ia_mtime == stbuf->ia_mtime) &&
                                 (cur_stat->ia_mtime_nsec < stbuf->ia_mtime_nsec))) {
                                    _dsc_cache_update_iatt(cur_stat, stbuf);
                        }
                }
        }
        gettimeofday(&dsc_inode->tv, NULL);
}

void dsc_cache_update(xlator_t *this, inode_t *inode, struct iatt *stbuf)
{
        dsc_inode_t *dsc_inode = NULL;
        uint64_t tmp_dsc_inode = 0;

        LOCK(&inode->lock);
        {
                __inode_ctx_get (inode, this, &tmp_dsc_inode);
                dsc_inode = (dsc_inode_t *) (long) tmp_dsc_inode;

                if (!dsc_inode) {
                        dsc_inode = GF_CALLOC(1, sizeof(dsc_inode_t), gf_dsc_mt_dsc_inode_t);
                        if (!dsc_inode) {
                                gf_log(this->name, GF_LOG_ERROR, "allocate dsc inode memory failed!");
                                goto unlock;
                        }
                        __inode_ctx_put(inode, this,
                                        (uint64_t) (long) dsc_inode);
                }
                _dsc_cache_update(dsc_inode, stbuf);

        }
unlock:
        UNLOCK(&inode->lock);
}

void dsc_local_init(call_frame_t *frame, loc_t *oldloc, loc_t *newloc)
{
        dsc_local_t *local = NULL;
        local = GF_CALLOC (1, sizeof(dsc_local_t), gf_dsc_mt_dsc_local_t);
        if (!local) {
                gf_log("dirstat cache", GF_LOG_ERROR, "allocate dirstat cache local struct failed!");
                return;
        }
        if (oldloc) {
                local->inode = inode_ref(oldloc->inode);
                local->parg_inode = inode_ref(oldloc->parent);
        }

        if (newloc) {
                local->new_inode = inode_ref(newloc->inode);
                local->new_parg_inode = inode_ref(newloc->parent);
        }

        frame->local = local;
}

void dsc_local_wipe(dsc_local_t *local)
{
        if (!local) {
                return;
        }

        if (local->inode) {
                inode_unref(local->inode);
        }

        if (local->parg_inode) {
                inode_unref(local->parg_inode);
        }

        if (local->new_inode) {
                inode_unref(local->new_inode);
        }

        if (local->new_parg_inode) {
                inode_unref(local->new_parg_inode);
        }

        if (local) {
                GF_FREE(local);
        }
}


int32_t
dsc_forget(xlator_t *this, inode_t *inode) {
        uint64_t dsc_inode = 0;

        inode_ctx_del(inode, this, &dsc_inode);
        if (!dsc_inode) {
                return 0;
        }

        GF_FREE((dsc_inode_t *) (long) dsc_inode);

        return 0;
}

int32_t
dsc_setattr_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno,
                struct iatt *preop, struct iatt *postop, dict_t *xdata) {
        dsc_local_t *local = frame->local;

        DSC_STACK_UNWIND (setattr, frame, op_ret, op_errno, preop, postop, xdata);


        if (op_ret != 0 || !IA_ISDIR(postop->ia_type) || (!local || !(local->inode))) {
                goto out;
        }

        dsc_cache_update(this, local->inode, postop);

out:
        dsc_local_wipe(local);

        return 0;
}

int32_t
dsc_setattr(call_frame_t *frame, xlator_t *this, loc_t *loc,
            struct iatt *stbuf, int32_t valid, dict_t *xdata) {
        dsc_local_init(frame, loc, NULL);

        STACK_WIND (frame, dsc_setattr_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->setattr, loc, stbuf, valid, xdata);

        return 0;
}

/*
 * lookup is a good chance to update parent's iatt; if the node is directory,
 * then update the iatt cache at same time.
 */
int32_t
dsc_lookup_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, inode_t *inode,
               struct iatt *stbuf, dict_t *dict, struct iatt *postparent) {
        inode_t *self = NULL;
        dsc_local_t *local = frame->local;

        if (op_ret != 0 || !local) {
                goto out;
        }

        if (IA_ISDIR(stbuf->ia_type)) {
                self = inode_ref(inode);
        }

        if (local->parg_inode != NULL) {
                dsc_cache_update(this, local->parg_inode, postparent);
        }

        if (self != NULL) {
                dsc_cache_update(this, self, stbuf);
        }

out:
        dsc_local_wipe(local);

        if (self) {
                inode_unref(self);
        }

        DSC_STACK_UNWIND (lookup, frame, op_ret, op_errno, inode, stbuf,
                dict, postparent);

        return 0;
}

int32_t
dsc_lookup(call_frame_t *frame, xlator_t *this, loc_t *loc,
           dict_t *xattr_req) {
        dsc_local_init(frame, loc, NULL);
        STACK_WIND (frame, dsc_lookup_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->lookup, loc, xattr_req);

        return 0;
}

/*
 * opendir need bring back the iatt of the directory, so that we
 * can cache it better.
 */
static int32_t
dsc_opendir_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, fd_t *fd, dict_t *xdata) {
        int ret = -1;
        inode_t *inode = inode_ref(fd->inode);
        struct iatt *stat = NULL;
        dict_t * cur_xdata = NULL;

        if (xdata) {
                cur_xdata = dict_ref(xdata);
                DSC_STACK_UNWIND(opendir, frame, op_ret, op_errno, fd, cur_xdata);
        } else {
                gf_log(this->name, GF_LOG_ERROR, "dict is invalid! cache iatt failed!");
                DSC_STACK_UNWIND(opendir, frame, op_ret, op_errno, fd, NULL);
                goto out;
        }

        if (op_ret != 0) {
                goto out;
        }

        /*
         * retrieve iatt from cur_xdata
         */
        ret = dict_get_bin(cur_xdata, DIR_STAT_CACHE, (void **)&stat);
        if (ret != 0) {
                goto out;
        }

        if (inode) {
                dsc_cache_update(this, inode, stat);
        }

out:
        if (inode) {
                inode_unref(inode);
        }

        if (cur_xdata) {
                dict_unref(cur_xdata);
        }

        return 0;
}

static int32_t
dsc_opendir(call_frame_t *frame, xlator_t *this, loc_t *loc, fd_t *fd,
            dict_t *xdata)
{
        int ret = -1;
        /*
         * bring a special dict to server side, ask for iatt of the dir
         */
        if (!xdata) {
                xdata = dict_new();
        } else {
                xdata = dict_ref(xdata);
        }

        ret = dict_set_int8(xdata, NFS_SVC_READDIR, 1);
        if (ret) {
                gf_log(this->name, GF_LOG_ERROR, "set nfs svc readdir flag failed!");
        }

        STACK_WIND(frame, dsc_opendir_cbk, FIRST_CHILD(this),
                   FIRST_CHILD(this)->fops->opendir, loc, fd, xdata);

        if (xdata) {
                dict_unref(xdata);
        }

        return 0;
}

int32_t
dsc_mkdir_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
              int32_t op_ret, int32_t op_errno, inode_t *inode,
              struct iatt *buf, struct iatt *preparent,
              struct iatt *postparent, dict_t *xdata) {
        dsc_local_t *local = frame->local;

        DSC_STACK_UNWIND (mkdir, frame, op_ret, op_errno, inode,
                          buf, preparent, postparent, xdata);
        if (op_ret != 0) {
                goto out;
        }

        if (local == NULL || local->parg_inode == NULL) {
                goto out;
        }

        dsc_cache_update(this, local->parg_inode, postparent);

out:
        dsc_local_wipe(local);

        return 0;
}

int32_t
dsc_unlink_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, struct iatt *preparent,
               struct iatt *postparent, dict_t *xdata) {
        dsc_local_t *local = frame->local;

        DSC_STACK_UNWIND (unlink, frame, op_ret, op_errno, preparent,
                          postparent, xdata);
        if (op_ret != 0 || (local == NULL || local->parg_inode == NULL)) {
                goto out;
        }

        dsc_cache_update(this, local->parg_inode, postparent);

out:
        dsc_local_wipe(local);

        return 0;
}

int32_t
dsc_rmdir_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
              int32_t op_ret, int32_t op_errno, struct iatt *preparent,
              struct iatt *postparent,
              dict_t *xdata) {
        dsc_local_t *local = frame->local;

        DSC_STACK_UNWIND (rmdir, frame, op_ret, op_errno, preparent,
                          postparent, xdata);
        if (op_ret != 0 || (local == NULL || local->parg_inode == NULL)) {
                goto out;
        }

        dsc_cache_update(this, local->parg_inode, postparent);

out:
        dsc_local_wipe(local);

        return 0;
}


int32_t
dsc_symlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, inode_t *inode,
                 struct iatt *buf, struct iatt *preparent,
                 struct iatt *postparent, dict_t *xdata)
{
        dsc_local_t *local = frame->local;

        DSC_STACK_UNWIND (symlink, frame, op_ret, op_errno, inode, buf,
                          preparent, postparent, xdata);
        if (op_ret != 0 || (local == NULL || local->parg_inode == NULL)) {
                goto out;
        }

        dsc_cache_update(this, local->parg_inode, postparent);

out:
        dsc_local_wipe(local);

        return 0;
}


int32_t
dsc_rename_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, struct iatt *buf,
               struct iatt *preoldparent, struct iatt *postoldparent,
               struct iatt *prenewparent, struct iatt *postnewparent,
               dict_t *xdata) {
        dsc_local_t *local = frame->local;

        DSC_STACK_UNWIND (rename, frame, op_ret, op_errno, buf, preoldparent,
                          postoldparent, prenewparent, postnewparent, xdata);

        if (op_ret != 0) {
                goto out;
        }

        if (!local) {
                goto out;
        }
        if (IA_ISDIR(buf->ia_type) && local->new_inode) {
                dsc_cache_update(this, local->new_inode, buf);
        }

        if (IA_ISDIR(postoldparent->ia_type) && local->parg_inode) {
                dsc_cache_update(this, local->parg_inode, postoldparent);
        }

        if (IA_ISDIR(postnewparent->ia_type) && local->new_parg_inode) {
                dsc_cache_update(this, local->new_parg_inode, postnewparent);
        }

out:
        dsc_local_wipe(local);

        return 0;
}


int32_t
dsc_link_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
             int32_t op_ret, int32_t op_errno, inode_t *inode,
             struct iatt *buf, struct iatt *preparent,
             struct iatt *postparent,
             dict_t *xdata) {
        dsc_local_t *local = frame->local;

        DSC_STACK_UNWIND (link, frame, op_ret, op_errno, inode, buf,
                          preparent, postparent, xdata);

        if (op_ret != 0 || (local == NULL || local->new_parg_inode == NULL)) {
                goto out;
        }

        dsc_cache_update(this, local->new_parg_inode, postparent);

out:
        dsc_local_wipe(local);
        /*
         * check if cache need to be pruned
         */
        return 0;
}


int32_t
dsc_create_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, fd_t *fd,
               inode_t *inode, struct iatt *buf, struct iatt *preparent,
               struct iatt *postparent, dict_t *xdata) {
        dsc_local_t *local = frame->local;

        DSC_STACK_UNWIND (create, frame, op_ret, op_errno, fd, inode, buf,
                          preparent, postparent, xdata);

        if (op_ret != 0) {
                goto out;
        }

        if (local == NULL || local->parg_inode == NULL) {
                gf_log(this->name, GF_LOG_INFO, "parent is not found.");
                goto out;
        }

        dsc_cache_update(this, local->parg_inode, postparent);

out:
        dsc_local_wipe(local);

        return 0;
}


int32_t
dsc_mknod_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
              int32_t op_ret, int32_t op_errno, inode_t *inode,
              struct iatt *buf, struct iatt *preparent,
              struct iatt *postparent, dict_t *xdata) {
        dsc_local_t *local = frame->local;

        DSC_STACK_UNWIND (mknod, frame, op_ret, op_errno, inode, buf,
                          preparent, postparent, xdata);

        if (op_ret != 0) {
                goto out;
        }

        if (local == NULL || local->parg_inode == NULL) {
                goto out;
        }

        dsc_cache_update(this, local->parg_inode, postparent);

out:
        dsc_local_wipe(local);

        return 0;
}


int
dsc_mknod (call_frame_t *frame, xlator_t *this, loc_t *loc, mode_t mode,
           dev_t rdev, mode_t umask, dict_t *params)
{
        dsc_local_init(frame, loc, NULL);

        STACK_WIND (frame, dsc_mknod_cbk,
                    FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->mknod,
                    loc, mode, rdev, umask, params);
        return 0;
}


int32_t
dsc_create (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flags,
            mode_t mode, mode_t umask, fd_t *fd, dict_t *params)
{
        dsc_local_init(frame, loc, NULL);

        STACK_WIND (frame, dsc_create_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->create, loc, flags, mode,
                    umask, fd, params);

        return 0;
}


int32_t
dsc_link (call_frame_t *frame, xlator_t *this, loc_t *oldloc, loc_t *newloc,
          dict_t *xdata)
{
        dsc_local_init(frame, oldloc, newloc);

        STACK_WIND (frame, dsc_link_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->link, oldloc, newloc, xdata);
        return 0;
}


int32_t
dsc_rename (call_frame_t *frame, xlator_t *this, loc_t *oldloc,
            loc_t *newloc, dict_t *xdata)
{
        dsc_local_init(frame, oldloc, newloc);

        STACK_WIND (frame, dsc_rename_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->rename, oldloc, newloc,
                    xdata);
        return 0;
}


int
dsc_symlink (call_frame_t *frame, xlator_t *this, const char *linkpath,
             loc_t *loc, mode_t umask, dict_t *xdata)
{
        dsc_local_init(frame, loc, NULL);
        STACK_WIND (frame, dsc_symlink_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->symlink, linkpath, loc,
                    umask, xdata);
        return 0;
}

int32_t
dsc_rmdir(call_frame_t *frame, xlator_t *this, loc_t *loc, int flags,
          dict_t *xdata) {
        dsc_local_init(frame, loc, NULL);

        STACK_WIND (frame, dsc_rmdir_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->rmdir, loc, flags, xdata);
        return 0;
}

int32_t
dsc_unlink(call_frame_t *frame, xlator_t *this, loc_t *loc, int xflag,
           dict_t *xdata) {
        dsc_local_init(frame, loc, NULL);

        STACK_WIND (frame, dsc_unlink_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->unlink, loc, xflag, xdata);
        return 0;
}

int
dsc_mkdir (call_frame_t *frame, xlator_t *this, loc_t *loc, mode_t mode,
           mode_t umask, dict_t *xdata)
{
        dsc_local_init(frame, loc, NULL);

        STACK_WIND (frame, dsc_mkdir_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->mkdir, loc, mode, umask,
                    xdata);
        return 0;
}

int32_t
dsc_fstat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, struct iatt *buf,
               dict_t *xdata)
{
        inode_t *inode = frame->local;

        DSC_STACK_UNWIND (fstat, frame, op_ret, op_errno, buf, xdata);

        if (op_ret != 0 || !IA_ISDIR(buf->ia_type) || !inode) {
                goto out;
        }

        dsc_cache_update(this, inode, buf);

out:
        if (inode) {
                inode_unref(inode);
        }
        /*
         * check if cache need to be pruned
         */
        return 0;
}

int32_t
dsc_fstat(call_frame_t *frame, xlator_t *this, fd_t *fd, dict_t *xdata) {
        inode_t *inode = fd->inode;
        uint64_t tmp_dsc_inode = 0;
        dsc_inode_t *dsc_inode = NULL;
        struct iatt buf;
        dsc_priv_t *priv = this->private;

        if (!priv) {
                goto bypass;
        }

        if (priv->special_client_active) {
                if (frame->root->pid != NFS_HIGH_PRIO_PROC_PID) {
                        goto bypass;
                }
        }

        frame->local = inode_ref(inode);

        LOCK (&inode->lock);
        {
                __inode_ctx_get (inode, this, &tmp_dsc_inode);
                if (!tmp_dsc_inode) {
                        UNLOCK(&inode->lock);
                        goto bypass;
                }

                dsc_inode = (dsc_inode_t *) (long) tmp_dsc_inode;

                if (_dsc_inode_need_revalidate(dsc_inode, this->private)) {
                        UNLOCK(&inode->lock);
                        gf_log(this->name, GF_LOG_DEBUG, "fstat bypass");
                        goto bypass;
                }
                /*
                 * cache hit, fullfill stat and return direclty
                 */
                memcpy(&buf, &dsc_inode->stat, sizeof(struct iatt));
        }
        UNLOCK(&inode->lock);

        gf_log(this->name, GF_LOG_DEBUG, "fstat hit cache and unwind");
        if (frame->local) {
                inode_unref(frame->local);
        }
        DSC_STACK_UNWIND (fstat, frame, 0, 0, &buf, NULL);
        goto out;

bypass:
        STACK_WIND (frame, dsc_fstat_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->fstat, fd, xdata);

out:
        return 0;
}


int32_t
mem_acct_init(xlator_t *this) {
        int ret = -1;

        if (!this)
                return ret;

        ret = xlator_mem_acct_init(this, gf_dsc_mt_end + 1);

        if (ret != 0) {
                gf_log (this->name, GF_LOG_ERROR, "Memory accounting init"
                        "failed");
                return ret;
        }

        return ret;
}

int
reconfigure(xlator_t *this, dict_t *options) {
        dsc_priv_t *priv = NULL;
        int ret = 0;

        if (!this || !this->private)
                goto out;

        priv = this->private;

        GF_OPTION_RECONF ("dsc-special-client", priv->special_client_active,
                         options, bool, out);
        GF_OPTION_RECONF ("dsc-cache-timeout", priv->cache_timeout,
                          options, int32, out);

out:
        return ret;
}

/*
 * init -
 * @this:
 *
 */
int32_t
init(xlator_t *this) {
        dsc_priv_t *priv = NULL;
        int32_t ret = -1;

        if (!this->children || this->children->next) {
                gf_log (this->name, GF_LOG_ERROR,
                        "FATAL: dirstat-cache not configured with exactly "
                                "one child");
                goto out;
        }

        if (!this->parents) {
                gf_log (this->name, GF_LOG_WARNING,
                        "dangling volume. check volfile ");
        }

        priv = GF_CALLOC (1, sizeof(*priv), gf_dsc_mt_dsc_priv_t);
        if (priv == NULL) {
                gf_log (this->name, GF_LOG_ERROR, "out of memory");
                goto out;
        }

        GF_OPTION_INIT ("dsc-special-client", priv->special_client_active, bool, out);
        GF_OPTION_INIT ("dsc-cache-timeout", priv->cache_timeout, int32, out);

        this->private = priv;

        ret = 0;


out:
        if (ret == -1) {
                if (priv != NULL) {
                        GF_FREE (priv);
                }
        }
        return ret;
}

int
dsc_priv_dump(xlator_t *this) {
        return 0;
}


void
fini(xlator_t *this) {
        dsc_priv_t *priv = NULL;

        priv = this->private;

        if (priv == NULL)
                return;

        GF_FREE (priv);

        this->private = NULL;
}

struct xlator_fops fops = {
        /*
         * need update parent's iatt cache
         */
        .create      = dsc_create,
        .mknod       = dsc_mknod,
        .mkdir       = dsc_mkdir,
        .rmdir       = dsc_rmdir,
        .unlink      = dsc_unlink,
        .link        = dsc_link,
        .symlink     = dsc_symlink,
        .rename      = dsc_rename,

        /*
         * read iatt cache, if hit return, miss wind
         */
        .fstat       = dsc_fstat,

        /*
         * verify cache validity, update iatt
         */
        .lookup      = dsc_lookup,
        .opendir    = dsc_opendir,
        .setattr     = dsc_setattr,
};


struct xlator_dumpops dumpops = {
        .priv        = dsc_priv_dump,
};

struct xlator_cbks cbks = {
        .forget      = dsc_forget,
};

struct volume_options options[] = {
        {.key = {"dsc-special-client"},
                .type = GF_OPTION_TYPE_BOOL,
                .default_value = "on",
                .description = "enable/disable dirstat-cache for special client"
        },
        {.key  = {"dsc-cache-timeout", "force-revalidate-timeout"},
                .type = GF_OPTION_TYPE_INT,
                .min  = 0,
                .max  = 60,
                .default_value = "10",
                .description = "The cached iatt for a dir will be retained till "
                        "'cache-refresh-timeout' seconds, after which data "
                        "re-validation is performed."
        },
        {.key = {NULL}},
};

