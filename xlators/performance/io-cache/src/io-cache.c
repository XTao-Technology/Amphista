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

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "glusterfs.h"
#include "logging.h"
#include "dict.h"
#include "xlator.h"
#include "io-cache.h"
#include "ioc-mem-types.h"
#include "statedump.h"
#include <assert.h>
#include <sys/time.h>

/*
Design & Convention

Page State:
============
INIT: Initial state
INTRAN: The page is on the way
CLEAN: The page content is cached and valid
DIRTY: The cached page content is invalid


Event:
==========
Normal Read : The read request came from client
Prefetch Read: The read ahead request
Fault Back: Faulted page come back
Flush: Write/Truncate/Setattr arrive
Expire: Cache expire

Normal Read: ioc_dispatch_requests()
Prefetch Read: ioc_prefetch()
Fault ckb: ioc_fault_cbk()
Flush: ioc_page_destroy()
Expire: ioc_inode_wakeup()


Conditions:
==========
page->waitq == NULL: w waitq
page->waitq != NULL: wo waitq
faulted gen == page's current gen: fgen == pgen
faulted gen != page's current gen: fgen != pgen

Conclusions:
===========
page->waitq == NULL has two possibilities:
1. Page is clean
2. Page is dirty no further read request after
all outstanding read cbk.

Clean state: waitq == NULL
Clean state never transit to Dirty state
Only Intran and Dirty can transit to Dirty state
Intran state means waitq != NULL
Expire event must be with waitq != NULL
Dirty state, page's waitq either NULL or !NULL

The page can be destroied on below conditions:
1. When flush, page is clean
2. When faultcbk, dirty && waitq==NULL

State Transition Matrix:
=======================

===============================================================================|
   \ State|                |               |                 |                 |
      \   |                |               |                 |                 |
 Event   \|      INIT      |     INTRAN    |     CLEAN       |      DIRTY      |
==========|================|===============|=================|=================|
          | 1              |               |                 |                 |
 Prefetch |     INTRAN     |       N/A     |     N/A         |       N/A       |
          |     gen=0      |               |                 |                 |
          |    waitq!=NULL |               |                 |                 |
==========|================|===============|=================|=================|
          |                | 2             |                 | 3               |
 Readv    |     N/A        |    INTRAN     |     N/A         |      INTRAN     |
 w waitq  |                | wait on page, |                 |  page fault on  |
          |                | gen no change |                 |     new gen     |
==========|================|===============|=================|=================|
          | 4              |               | 5               | 6               |
 Readv    |     INTRAN     |               |     CLEAN       |      INTRAN     |
 wo waitq |    page fault  |     N/A       |   cache hit     |  page fault on  |
          |      gen=0     |               |    wakeup 	     |      new gen    |
==========|================|===============|=================|=================|
          |                | 7             |                 | 8               |
  Flush   |     N/A        |    DIRTY      |     N/A         |     DIRTY       |
 w waitq  |                |    gen++      |  Clean no waitq |     gen++?      |
          |                |               |                 |                 |
==========|================|===============|=================|=================|
          |                |               | 9               | a       	       |
 Flush    |     N/A        |               |     DESTROY     |     DESTROY     |
 wo waitq |                |      N/A      | destroy page    |                 |
          |                |               |                 |                 |
==========|================|===============|=================|=================|
          |                | b             |                 | 	       	       |
 FAULT cbk|     N/A        |    CLEAN      |     N/A         |     N/A         |
 w waitq  |                |   wakeup all  |clean = no fault | Dirty must      |
fgen=pgen |                |               |on the way       | fgen != pgen    |
==========|================|===============|=================|=================|
          |                | c             |                 | d               |
 FAULT cbk|     N/A        |   INTRAN      |     N/A         |   DIRTY|DESTROY |
 w waitq  |                |  wakeup <=fgen|                 |if(waitq) DIRTY  |
fgen!=pgen|                |               |                 |if(!waitq)DESTROY|
==========|================|===============|=================|=================|
          |                | e             | f               | g               |
 Expire   |                |     INTRAN    |     INTRAN      |    INTRAN       |
          |     N/A        |   do nothing  |     gen++,      |  gen no change  |
          |                |               |    page fault   |    page fault   |
===========================|===============|=================|=================|
*/

int ioc_log2_page_size;

uint32_t
ioc_get_priority (ioc_table_t *table, const char *path);

uint32_t
ioc_get_priority (ioc_table_t *table, const char *path);

struct volume_options options[];

uint32_t
ioc_hashfn (void *data, int len)
{
        off_t offset;

        offset = *(off_t *) data;

        return (offset >> ioc_log2_page_size);
}

static inline ioc_inode_t *
ioc_inode_reupdate (ioc_inode_t *ioc_inode)
{
        ioc_table_t *table = NULL;

        table = ioc_inode->table;

        list_add_tail (&ioc_inode->inode_lru,
                       &table->inode_lru[ioc_inode->weight]);

        return ioc_inode;
}

static inline ioc_inode_t *
ioc_get_inode (dict_t *dict, char *name)
{
        ioc_inode_t *ioc_inode      = NULL;
        data_t      *ioc_inode_data = NULL;
        ioc_table_t *table          = NULL;

        ioc_inode_data = dict_get (dict, name);
        if (ioc_inode_data) {
                ioc_inode = data_to_ptr (ioc_inode_data);
                table = ioc_inode->table;

                ioc_table_lock (table);
                {
                        if (list_empty (&ioc_inode->inode_lru)) {
                                ioc_inode = ioc_inode_reupdate (ioc_inode);
                        }
                }
                ioc_table_unlock (table);
        }

        return ioc_inode;
}

int32_t
ioc_inode_need_revalidate (ioc_inode_t *ioc_inode)
{
        int8_t          need_revalidate = 0;
        struct timeval  tv              = {0,};
        ioc_table_t    *table           = NULL;

        table = ioc_inode->table;

        gettimeofday (&tv, NULL);

        if (time_elapsed (&tv, &ioc_inode->cache.tv) >= table->cache_timeout) {
		STATS_INC(table->timeoutcnt);
		need_revalidate = 1;
	}
        return need_revalidate;
}

/*
 * __ioc_inode_flush - flush all the cached pages of the given inode
 *
 * @ioc_inode:
 *
 * assumes lock is held
 */
int64_t
__ioc_inode_flush (ioc_inode_t *ioc_inode)
{
        ioc_page_t *curr         = NULL, *next = NULL;
        int64_t     destroy_size = 0;
        int64_t     ret          = 0;

        list_for_each_entry_safe (curr, next, &ioc_inode->cache.page_lru,
                                  page_lru) {
                ret = __ioc_page_destroy (curr);

                if (ret != -1)
                        destroy_size += ret;
        }

        return destroy_size;
}

void
ioc_inode_flush (ioc_inode_t *ioc_inode)
{
        int64_t destroy_size = 0;

        ioc_inode_lock (ioc_inode);
        {
                destroy_size = __ioc_inode_flush (ioc_inode);
        }
        ioc_inode_unlock (ioc_inode);

        if (destroy_size) {
                ioc_table_lock (ioc_inode->table);
                {
                        ioc_inode->table->cache_used -= destroy_size;
                }
                ioc_table_unlock (ioc_inode->table);
        }

        return;
}

int32_t
ioc_setattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno,
                 struct iatt *preop, struct iatt *postop, dict_t *xdata)
{
        STACK_UNWIND_STRICT (setattr, frame, op_ret, op_errno, preop, postop, xdata);
        return 0;
}

int32_t
ioc_setattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
             struct iatt *stbuf, int32_t valid, dict_t *xdata)
{
        uint64_t ioc_inode = 0;
	int ret = -1;

        ret = inode_ctx_get (loc->inode, this, &ioc_inode);
	if (ret)
		goto wind;

        if (ioc_inode
            && ((valid & GF_SET_ATTR_ATIME)
                || (valid & GF_SET_ATTR_MTIME)))
                ioc_inode_flush ((ioc_inode_t *)(long)ioc_inode);
wind:
        STACK_WIND (frame, ioc_setattr_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->setattr, loc, stbuf, valid, xdata);

        return 0;
}

int32_t
ioc_lookup_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret,	int32_t op_errno, inode_t *inode,
                struct iatt *stbuf, dict_t *dict, struct iatt *postparent)
{
        ioc_inode_t *ioc_inode         = NULL;
        ioc_table_t *table             = NULL;
        uint8_t      cache_still_valid = 0;
        uint64_t     tmp_ioc_inode     = 0;
        uint32_t     weight            = 0xffffffff;
        const char  *path              = NULL;
        ioc_local_t *local             = NULL;

        if (op_ret != 0)
                goto out;

        local = frame->local;
        if (local == NULL) {
                op_ret = -1;
                op_errno = EINVAL;
                goto out;
        }

        if (!this || !this->private) {
                op_ret = -1;
                op_errno = EINVAL;
                goto out;
        }

	if (IA_ISDIR(stbuf->ia_type))
		goto out;

        table = this->private;

        path = local->file_loc.path;

        LOCK (&inode->lock);
        {
                __inode_ctx_get (inode, this, &tmp_ioc_inode);
                ioc_inode = (ioc_inode_t *)(long)tmp_ioc_inode;

                if (!ioc_inode) {
                        weight = ioc_get_priority (table, path);

                        ioc_inode = ioc_inode_update (table, inode,
                                                      weight);

                        __inode_ctx_put (inode, this,
                                         (uint64_t)(long)ioc_inode);
                }
        }
        UNLOCK (&inode->lock);

        ioc_inode_lock (ioc_inode);
        {
                if (ioc_inode->cache.mtime == 0) {
                        ioc_inode->cache.mtime = stbuf->ia_mtime;
                        ioc_inode->cache.mtime_nsec = stbuf->ia_mtime_nsec;
                }

                ioc_inode->ia_size = stbuf->ia_size;
        }
        ioc_inode_unlock (ioc_inode);

        cache_still_valid = ioc_cache_still_valid (ioc_inode,
                                                   stbuf);

        if (!cache_still_valid) {
                ioc_inode_flush (ioc_inode);
        }

        ioc_table_lock (ioc_inode->table);
        {
                list_move_tail (&ioc_inode->inode_lru,
                                &table->inode_lru[ioc_inode->weight]);
        }
        ioc_table_unlock (ioc_inode->table);

out:
        if (frame->local != NULL) {
                local = frame->local;
                loc_wipe (&local->file_loc);
        }

        STACK_UNWIND_STRICT (lookup, frame, op_ret, op_errno, inode, stbuf,
                             dict, postparent);
        return 0;
}

int32_t
ioc_lookup (call_frame_t *frame, xlator_t *this, loc_t *loc,
            dict_t *xattr_req)
{
        ioc_local_t *local    = NULL;
        int32_t      op_errno = -1, ret = -1;

        /*local = GF_CALLOC (1, sizeof (*local),
                           gf_ioc_mt_ioc_local_t);
         */
        local = mem_get0 (this->local_pool);
        if (local == NULL) {
                op_errno = ENOMEM;
                gf_log (this->name, GF_LOG_ERROR, "out of memory");
                goto unwind;
        }

        ret = loc_copy (&local->file_loc, loc);
        if (ret != 0) {
                op_errno = ENOMEM;
                gf_log (this->name, GF_LOG_ERROR, "out of memory");
                goto unwind;
        }

        frame->local = local;

        STACK_WIND (frame, ioc_lookup_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->lookup, loc, xattr_req);

        return 0;

unwind:
        STACK_UNWIND_STRICT (lookup, frame, -1, op_errno, NULL, NULL,
                             NULL, NULL);

        return 0;
}

/*
 * ioc_forget -
 *
 * @frame:
 * @this:
 * @inode:
 *
 */
int32_t
ioc_forget (xlator_t *this, inode_t *inode)
{
        uint64_t ioc_inode = 0;
	int ret = -1;

        ret = inode_ctx_get (inode, this, &ioc_inode);
	if (ret)
		return 0;

        if (ioc_inode)
                ioc_inode_destroy ((ioc_inode_t *)(long)ioc_inode);

        return 0;
}


/*
 * ioc_cache_validate_cbk -
 *
 * @frame:
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @buf
 *
 */
int32_t
ioc_cache_validate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                        int32_t op_ret, int32_t op_errno, struct iatt *stbuf,
                        dict_t *xdata)
{
        ioc_local_t *local        = NULL;
        ioc_inode_t *ioc_inode    = NULL;
        size_t       destroy_size = 0;
        struct iatt *local_stbuf  = NULL;

        local = frame->local;
        ioc_inode = local->inode;
        local_stbuf = stbuf;

        if ((op_ret == -1) ||
            ((op_ret >= 0) && !ioc_cache_still_valid(ioc_inode, stbuf))) {
                gf_log (ioc_inode->table->xl->name, GF_LOG_DEBUG,
                        "cache for inode(%p) is invalid. flushing all pages",
                        ioc_inode);
                /* NOTE: only pages with no waiting frames are flushed by
                 * ioc_inode_flush. page_fault will be generated for all
                 * the pages which have waiting frames by ioc_inode_wakeup()
                 */
                ioc_inode_lock (ioc_inode);
                {
                        destroy_size = __ioc_inode_flush (ioc_inode);
                        if (op_ret >= 0) {
                                ioc_inode->cache.mtime = stbuf->ia_mtime;
                                ioc_inode->cache.mtime_nsec
                                        = stbuf->ia_mtime_nsec;
                        }
                }
                ioc_inode_unlock (ioc_inode);
                local_stbuf = NULL;
        }

        if (destroy_size) {
                ioc_table_lock (ioc_inode->table);
                {
                        ioc_inode->table->cache_used -= destroy_size;
                }
                ioc_table_unlock (ioc_inode->table);
        }

        if (op_ret < 0)
                local_stbuf = NULL;

        ioc_inode_lock (ioc_inode);
        {
                gettimeofday (&ioc_inode->cache.tv, NULL);
        }
        ioc_inode_unlock (ioc_inode);

        ioc_inode_wakeup (frame, ioc_inode, local_stbuf);

        /* any page-fault initiated by ioc_inode_wakeup() will have its own
         * fd_ref on fd, safe to unref validate frame's private copy
         */
        fd_unref (local->fd);

        STACK_DESTROY (frame->root);

        return 0;
}

int32_t
ioc_wait_on_inode (ioc_inode_t *ioc_inode, ioc_page_t *page)
{
        ioc_waitq_t *waiter     = NULL, *trav = NULL;
        uint32_t     page_found = 0;
        int32_t      ret        = 0;

        trav = ioc_inode->waitq;

        while (trav) {
                if (trav->data == page) {
                        page_found = 1;
                        break;
                }
                trav = trav->next;
        }

        if (!page_found) {
                waiter = GF_CALLOC (1, sizeof (ioc_waitq_t),
                                    gf_ioc_mt_ioc_waitq_t);
                if (waiter == NULL) {
                        gf_log (ioc_inode->table->xl->name, GF_LOG_ERROR,
                                "out of memory");
                        ret = -ENOMEM;
                        goto out;
                }

                waiter->data = page;
                waiter->next = ioc_inode->waitq;
		waiter->generation = page->gen;
                ioc_inode->waitq = waiter;
        }
out:
        return ret;
}

/*
 * ioc_cache_validate -
 *
 * @frame:
 * @ioc_inode:
 * @fd:
 *
 */
int32_t
ioc_cache_validate (call_frame_t *frame, ioc_inode_t *ioc_inode, fd_t *fd,
                    ioc_page_t *page)
{
        call_frame_t *validate_frame = NULL;
        ioc_local_t  *validate_local = NULL;
        ioc_local_t  *local          = NULL;
        int32_t       ret            = 0;

        local = frame->local;
        /*validate_local = GF_CALLOC (1, sizeof (ioc_local_t),
                                    gf_ioc_mt_ioc_local_t);
        */
        validate_local = mem_get0 (frame->this->local_pool);
        if (validate_local == NULL) {
                ret = -1;
                local->op_ret = -1;
                local->op_errno = ENOMEM;
                gf_log (ioc_inode->table->xl->name, GF_LOG_ERROR,
                        "out of memory");
                goto out;
        }

        validate_frame = copy_frame (frame);
        if (validate_frame == NULL) {
                ret = -1;
                local->op_ret = -1;
                local->op_errno = ENOMEM;
                mem_put (validate_local);
                gf_log (ioc_inode->table->xl->name, GF_LOG_ERROR,
                        "out of memory");
                goto out;
        }

        validate_local->fd = fd_ref (fd);
        validate_local->inode = ioc_inode;
        validate_frame->local = validate_local;

        STACK_WIND (validate_frame, ioc_cache_validate_cbk,
                    FIRST_CHILD (frame->this),
                    FIRST_CHILD (frame->this)->fops->fstat, fd, NULL);

out:
        return ret;
}

static inline uint32_t
is_match (const char *path, const char *pattern)
{
        int32_t ret = 0;

        ret = fnmatch (pattern, path, FNM_NOESCAPE);

        return (ret == 0);
}

uint32_t
ioc_get_priority (ioc_table_t *table, const char *path)
{
        uint32_t             priority = 1;
        struct ioc_priority *curr     = NULL;

        if (list_empty(&table->priority_list))
                return priority;

        priority = 0;
        list_for_each_entry (curr, &table->priority_list, list) {
                if (is_match (path, curr->pattern))
                        priority = curr->priority;
        }

        return priority;
}

/*
 * ioc_open_cbk - open callback for io cache
 *
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @fd:
 *
 */
int32_t
ioc_open_cbk (call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
              int32_t op_errno, fd_t *fd, dict_t *xdata)
{
        uint64_t     tmp_ioc_inode = 0;
        ioc_local_t *local         = NULL;
        ioc_table_t *table         = NULL;
        ioc_inode_t *ioc_inode     = NULL;
        uint32_t     weight        = 0xffffffff;
	int ret = -1;

        local = frame->local;
        if (!this || !this->private) {
                op_ret = -1;
                op_errno = EINVAL;
                goto out;
        }

        table = this->private;

        if (op_ret != -1) {
                ret = inode_ctx_get (fd->inode, this, &tmp_ioc_inode);
		if (ret)
			goto out;
                ioc_inode = (ioc_inode_t *)(long)tmp_ioc_inode;

                ioc_table_lock (ioc_inode->table);
                {
                        list_move_tail (&ioc_inode->inode_lru,
                                        &table->inode_lru[ioc_inode->weight]);
                }
                ioc_table_unlock (ioc_inode->table);

                ioc_inode_lock (ioc_inode);
                {
                        if ((table->min_file_size > ioc_inode->ia_size)
                            || ((table->max_file_size > 0)
                                && (table->max_file_size < ioc_inode->ia_size))) {
                                fd_ctx_set (fd, this, 1);
                        }
                }
                ioc_inode_unlock (ioc_inode);

                /* If O_DIRECT open, we disable caching on it */
                if ((local->flags & O_DIRECT)){
                        /* O_DIRECT is only for one fd, not the inode
                         * as a whole
                         */
                        fd_ctx_set (fd, this, 1);
                }
                if ((local->wbflags & GF_OPEN_NOWB) != 0) {
                        /* disable caching as asked by NFS */
                        fd_ctx_set (fd, this, 1);
                }

                /* weight = 0, we disable caching on it */
                if (weight == 0) {
                        /* we allow a pattern-matched cache disable this way
                         */
                        fd_ctx_set (fd, this, 1);
                }
        }

out:
        mem_put (local);
        frame->local = NULL;

        STACK_UNWIND_STRICT (open, frame, op_ret, op_errno, fd, xdata);

        return 0;
}

/*
 * ioc_create_cbk - create callback for io cache
 *
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @fd:
 * @inode:
 * @buf:
 *
 */
int32_t
ioc_create_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret,	int32_t op_errno, fd_t *fd,
                inode_t *inode,	struct iatt *buf, struct iatt *preparent,
                struct iatt *postparent, dict_t *xdata)
{
        ioc_local_t *local     = NULL;
        ioc_table_t *table     = NULL;
        ioc_inode_t *ioc_inode = NULL;
        uint32_t     weight    = 0xffffffff;
        const char  *path      = NULL;
        int          ret       = -1;

        local = frame->local;
        if (!this || !this->private) {
                op_ret = -1;
                op_errno = EINVAL;
                goto out;
        }

        table = this->private;
        path = local->file_loc.path;

        if (op_ret != -1) {
                /* assign weight */
                weight = ioc_get_priority (table, path);

                ioc_inode = ioc_inode_update (table, inode, weight);

                ioc_inode_lock (ioc_inode);
                {
                        ioc_inode->cache.mtime = buf->ia_mtime;
                        ioc_inode->cache.mtime_nsec = buf->ia_mtime_nsec;
                        ioc_inode->ia_size = buf->ia_size;

                        if ((table->min_file_size > ioc_inode->ia_size)
                            || ((table->max_file_size >= 0)
                                && (table->max_file_size
                                    < ioc_inode->ia_size))) {
                                ret = fd_ctx_set (fd, this, 1);
                                if (ret)
                                        gf_log (this->name, GF_LOG_WARNING,
                                                        "%s: failed to set fd ctx",
                                                        local->file_loc.path);
                        }
                }
                ioc_inode_unlock (ioc_inode);

                inode_ctx_put (fd->inode, this,
                               (uint64_t)(long)ioc_inode);

                /* If O_DIRECT open, we disable caching on it */
                if (local->flags & O_DIRECT)
                        /*
                         * O_DIRECT is only for one fd, not the inode
                         * as a whole */
                        ret = fd_ctx_set (fd, this, 1);

                /* if weight == 0, we disable caching on it */
                if (!weight)
                        /* we allow a pattern-matched cache disable this way */
                        ret = fd_ctx_set (fd, this, 1);

        }

out:
        frame->local = NULL;
        mem_put (local);

        STACK_UNWIND_STRICT (create, frame, op_ret, op_errno, fd, inode, buf,
                             preparent, postparent, xdata);

        return 0;
}


int32_t
ioc_mknod_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, inode_t *inode,
               struct iatt *buf, struct iatt *preparent,
               struct iatt *postparent, dict_t *xdata)
{
        ioc_local_t *local     = NULL;
        ioc_table_t *table     = NULL;
        ioc_inode_t *ioc_inode = NULL;
        uint32_t     weight    = 0xffffffff;
        const char  *path      = NULL;

        local = frame->local;
        if (!this || !this->private) {
                op_ret = -1;
                op_errno = EINVAL;
                goto out;
        }

        table = this->private;
        path = local->file_loc.path;

        if (op_ret != -1) {
                /* assign weight */
                weight = ioc_get_priority (table, path);

                ioc_inode = ioc_inode_update (table, inode, weight);

                ioc_inode_lock (ioc_inode);
                {
                        ioc_inode->cache.mtime = buf->ia_mtime;
                        ioc_inode->cache.mtime_nsec = buf->ia_mtime_nsec;
                        ioc_inode->ia_size = buf->ia_size;
                }
                ioc_inode_unlock (ioc_inode);

                inode_ctx_put (inode, this,
                               (uint64_t)(long)ioc_inode);
        }

out:
        frame->local = NULL;

        loc_wipe (&local->file_loc);
        mem_put (local);

        STACK_UNWIND_STRICT (mknod, frame, op_ret, op_errno, inode, buf,
                             preparent, postparent, xdata);
        return 0;
}


int
ioc_mknod (call_frame_t *frame, xlator_t *this, loc_t *loc, mode_t mode,
           dev_t rdev, mode_t umask, dict_t *params)
{
        ioc_local_t *local    = NULL;
        int32_t      op_errno = -1, ret = -1;

        /*local = GF_CALLOC (1, sizeof (*local),
                           gf_ioc_mt_ioc_local_t);
        */
        local = mem_get0 (this->local_pool);
        if (local == NULL) {
                op_errno = ENOMEM;
                gf_log (this->name, GF_LOG_ERROR, "out of memory");
                goto unwind;
        }

        ret = loc_copy (&local->file_loc, loc);
        if (ret != 0) {
                op_errno = ENOMEM;
                gf_log (this->name, GF_LOG_ERROR, "out of memory");
                goto unwind;
        }

        frame->local = local;

        STACK_WIND (frame, ioc_mknod_cbk,
                    FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->mknod,
                    loc, mode, rdev, umask, params);
        return 0;

unwind:
        if (local != NULL) {
                loc_wipe (&local->file_loc);
                mem_put (local);
        }

        STACK_UNWIND_STRICT (mknod, frame, -1, op_errno, NULL, NULL,
                             NULL, NULL, NULL);

        return 0;
}


/*
 * ioc_open - open fop for io cache
 * @frame:
 * @this:
 * @loc:
 * @flags:
 *
 */
int32_t
ioc_open (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flags,
          fd_t *fd,  dict_t *xdata)
{

        ioc_local_t *local = NULL;

        //local = GF_CALLOC (1, sizeof (ioc_local_t), gf_ioc_mt_ioc_local_t);
        local = mem_get0 (this->local_pool);
        if (local == NULL) {
                gf_log (this->name, GF_LOG_ERROR, "out of memory");
                STACK_UNWIND_STRICT (open, frame, -1, ENOMEM, NULL, NULL);
                return 0;
        }

        local->flags = flags;
        local->file_loc.path = loc->path;
        local->file_loc.inode = loc->inode;
        //local->wbflags = wbflags;

        frame->local = local;

        STACK_WIND (frame, ioc_open_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->open, loc, flags, fd, xdata);

        return 0;
}

/*
 * ioc_create - create fop for io cache
 *
 * @frame:
 * @this:
 * @pathname:
 * @flags:
 * @mode:
 *
 */
int32_t
ioc_create (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flags,
            mode_t mode, mode_t umask, fd_t *fd, dict_t *params)
{
        ioc_local_t *local = NULL;

        //local = GF_CALLOC (1, sizeof (ioc_local_t), gf_ioc_mt_ioc_local_t);
        local = mem_get0 (this->local_pool);
        if (local == NULL) {
                gf_log (this->name, GF_LOG_ERROR, "out of memory");
                STACK_UNWIND_STRICT (create, frame, -1, ENOMEM, NULL, NULL,
                                     NULL, NULL, NULL, NULL);
                return 0;
        }

        local->flags = flags;
        local->file_loc.path = loc->path;
        frame->local = local;

        STACK_WIND (frame, ioc_create_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->create, loc, flags, mode,
                    umask, fd, params);

        return 0;
}




/*
 * ioc_release - release fop for io cache
 *
 * @frame:
 * @this:
 * @fd:
 *
 */
int32_t
ioc_release (xlator_t *this, fd_t *fd)
{
        return 0;
}

/*
 * ioc_readv_disabled_cbk
 * @frame:
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @vector:
 * @count:
 *
 */
int32_t
ioc_readv_disabled_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                        int32_t op_ret,	int32_t op_errno, struct iovec *vector,
                        int32_t count, struct iatt *stbuf,
                        struct iobref *iobref, dict_t *xdata)
{
	ioc_inode_t *ioc_inode = frame->local;

	if (ioc_inode) {
		        ioc_inode_lock (ioc_inode);
			ioc_inode->ia_size = stbuf->ia_size;
			ioc_inode_unlock (ioc_inode);
	}
	frame->local = NULL;
        STACK_UNWIND_STRICT (readv, frame, op_ret, op_errno, vector, count,
                             stbuf, iobref, xdata);
        return 0;
}


int32_t
ioc_need_prune (ioc_table_t *table)
{
        int64_t cache_difference = 0;

        ioc_table_lock (table);
        {
                cache_difference = table->cache_used - table->cache_size;
        }
        ioc_table_unlock (table);

        if (cache_difference > 0)
                return 1;
        else
                return 0;
}

static void
ioc_prefetch (call_frame_t *frame, ioc_inode_t *ioc_inode, fd_t *fd,
		ioc_stream_t *st)
{
        ioc_table_t *table     = NULL;
        ioc_local_t *local     = NULL;
        off_t      ra_end      = 0;
        off_t      ra_start    = 0;
        ioc_page_t  *trav      = NULL;
        char       fault       = 0;

        table = ioc_inode->table;
	if (!table->ra_pagecnt)
		goto out;

	local = frame->local;
	GF_ASSERT (local);

        ra_start = st->poffset;
        ra_end = roof (ra_start + st->len, table->page_size);

	while (ra_start < ra_end) {
		fault = 0;
                ioc_inode_lock (ioc_inode);
		/* look for requested region in the cache */
		trav = __ioc_page_get (ioc_inode, ra_start);
		if (!trav) {
			fault = 1;
                        trav = __ioc_page_create (ioc_inode,
						  ra_start);
			if (!trav) {
				ioc_inode_unlock (ioc_inode);
				goto out;
			}

			trav->gen = 0;
			trav->state = IOC_PAGE_STATE_INTRAN;
			/*
			 * Hack waiter here, NULL frame indicate create a
			 * skeleton waiter for prefetch.
			 */
			__ioc_wait_on_page (trav, NULL, ra_start,
			    table->page_size);

		}

		ioc_inode_unlock (ioc_inode);

                if (fault) {
                        gf_log (frame->this->name, GF_LOG_TRACE,
                                "ra_start=%"PRIu64" ",
                                 ra_start);
                        /* new page created, increase the table->cache_used */
                        ioc_page_fault (ioc_inode, frame, fd, ra_start, 0, 1);
                }
                ra_start += table->page_size;
	}

out:
	return;
}


/*
 * ioc_dispatch_requests -
 *
 * @frame:
 * @inode:
 *
 *
 */
void
ioc_dispatch_requests (call_frame_t *frame, ioc_inode_t *ioc_inode, fd_t *fd,
                       off_t offset, size_t size)
{
        ioc_local_t *local               = NULL;
        ioc_table_t *table               = NULL;
        ioc_page_t  *trav                = NULL;
        ioc_waitq_t *waitq               = NULL;
        off_t        rounded_offset      = 0;
        off_t        rounded_end         = 0;
        off_t        trav_offset         = 0;
        int32_t      fault               = 0;
        size_t       trav_size           = 0;
        off_t        local_offset        = 0;
        int32_t      ret                 = -1;
        int8_t       need_validate       = 0;
        int8_t       might_need_validate = 0;  /*
                                                * if a page exists, do we need
                                                * to validate it?
                                                */
	uint64_t generation		 = 0;

        local = frame->local;
        table = ioc_inode->table;

        rounded_offset = floor (offset, table->page_size);
        rounded_end = roof (offset + size, table->page_size);
        trav_offset = rounded_offset;

        /* once a frame does read, it should be waiting on something */
        local->wait_count++;

        /* Requested region can fall in three different pages,
         * 1. Ready - region is already in cache, we just have to serve it.
         * 2. In-transit - page fault has been generated on this page, we need
         *    to wait till the page is ready
         * 3. Fault - page is not in cache, we have to generate a page fault
         */

        while (trav_offset < rounded_end) {
                ioc_inode_lock (ioc_inode);
                {
                        /* look for requested region in the cache */
                        trav = __ioc_page_get (ioc_inode, trav_offset);

                        local_offset = max (trav_offset, offset);
                        trav_size = min (((offset+size) - local_offset),
                                         table->page_size);

                        if (!trav) {
                                /* page not in cache, we need to generate page
                                 * fault
                                 */
                                trav = __ioc_page_create (ioc_inode,
                                                          trav_offset);
                                fault = 1;
                                if (!trav) {
                                        gf_log (frame->this->name,
                                                GF_LOG_CRITICAL,
                                                "out of memory");
                                        local->op_ret = -1;
                                        local->op_errno = ENOMEM;
					ioc_inode_unlock (ioc_inode);
                                        goto out;
                                }
				trav->gen = 0;
                        }

			/*
			 * wait on page with current generation
			 */
                        __ioc_wait_on_page (trav, frame, local_offset,
                                            trav_size);

			generation = trav->gen;

			switch (trav->state) {
			case IOC_PAGE_STATE_INIT:
				trav->state = IOC_PAGE_STATE_INTRAN;
				break;
			case IOC_PAGE_STATE_DIRTY:
				/*
				 * If the page is in dirty, which means
				 * we need issue page fault and set the
				 * state of page to in transit
				 */
				fault = 1;
				trav->state = IOC_PAGE_STATE_INTRAN;

				break;
			case IOC_PAGE_STATE_CLEAN:
				/*
				 * Cache hit and page is clean
				 */
				might_need_validate =
					ioc_inode_need_revalidate (ioc_inode);
                                /* Page found in cache */
                                if (!might_need_validate && !ioc_inode->waitq) {
                                        /* fresh enough */
                                        gf_log (frame->this->name, GF_LOG_TRACE,
                                                "cache hit for trav_offset=%"
                                                PRId64"/local_offset=%"PRId64"",
                                                trav_offset, local_offset);

					STATS_INC(table->hitcnt);

                                        waitq = __ioc_page_wakeup (trav,
					    generation);
                                } else {
                                        /* If waitq already exists, fstat
                                         * revalidate is already on the way
                                         */
                                        if (!ioc_inode->waitq) {
                                                need_validate = 1;
                                        }

                                        ret = ioc_wait_on_inode (ioc_inode,
                                                                 trav);
                                        if (ret < 0) {
						/*
						 * Revalidation failure, mark
						 * the page to dirty, next read
						 * would have to page fault.
						 */
                                                local->op_ret = -1;
                                                local->op_errno = -ret;
                                                need_validate = 0;

                                                waitq = __ioc_page_wakeup (trav,
						    generation);
                                                ioc_inode_unlock (ioc_inode);

                                                ioc_waitq_return (waitq);
                                                goto out;
                                        }
                                }

				break;
			case IOC_PAGE_STATE_INTRAN:
				/*
				 * Page is in transit, haven't been read back
				 */
				STATS_INC(table->waitcnt);

			default:
				break;
			}
                }
                ioc_inode_unlock (ioc_inode);

		ioc_waitq_return (waitq);

		waitq = NULL;

                if (fault) {
                        fault = 0;
                        /* new page created, increase the table->cache_used */
                        ioc_page_fault (ioc_inode, frame, fd, trav_offset,
			    generation, 0);
                }

                if (need_validate) {
                        need_validate = 0;
                        gf_log (frame->this->name, GF_LOG_TRACE,
                                "sending validate request for "
                                "inode %p at offset=%"PRId64"",
                                fd->inode, trav_offset);
                        ret = ioc_cache_validate (frame, ioc_inode, fd, trav);
                        if (ret == -1) {
                                ioc_inode_lock (ioc_inode);
                                {
                                        waitq = __ioc_page_wakeup (trav,
					    generation);
					/*
					 * revalidation failure, mark
					 * the page to dirty, next read
					 * would have to page fault.
					 */
					trav->state = IOC_PAGE_STATE_DIRTY;
					if (!fault)
						atomic_inc_and_fetch(&trav->gen);

                                }
                                ioc_inode_unlock (ioc_inode);

                                ioc_waitq_return (waitq);
                                goto out;
                        }
                }

                trav_offset += table->page_size;
        }

out:
        return;
}


/*
 * ioc_readv -
 *
 * @frame:
 * @this:
 * @fd:
 * @size:
 * @offset:
 *
 */
int32_t
ioc_readv (call_frame_t *frame, xlator_t *this, fd_t *fd,
           size_t size, off_t offset, uint32_t flags, dict_t *xdata)
{
        uint64_t     tmp_ioc_inode = 0;
        ioc_inode_t *ioc_inode     = NULL;
        ioc_local_t *local         = NULL;
        uint32_t     weight        = 0;
        ioc_table_t *table         = NULL;
        uint32_t     num_pages     = 0;
        int32_t      op_errno      = -1;
	int          prefetch      = 0;
	ioc_stream_t st;

        if (!this) {
                goto out;
        }

        inode_ctx_get (fd->inode, this, &tmp_ioc_inode);
        ioc_inode = (ioc_inode_t *)(long)tmp_ioc_inode;
        if (!ioc_inode) {
                /* caching disabled, go ahead with normal readv */
		frame->local = NULL;
                STACK_WIND (frame, ioc_readv_disabled_cbk,
                            FIRST_CHILD (frame->this),
                            FIRST_CHILD (frame->this)->fops->readv, fd, size,
                            offset, flags, xdata);
                return 0;
        }

        table = this->private;

	if (!table) {
                gf_log (this->name, GF_LOG_ERROR, "table is null");
                op_errno = EINVAL;
                goto out;
        }
         
	memset (&st, 0, sizeof(st));
	st.offset = offset;
	st.len = size;
        
        STATS_INC(table->readcnt);

        prefetch = ioc_fetch (ioc_inode, &st);

#ifdef PERF_STATS
	if (prefetch) {
		STATS_INC(table->conticnt);
	}
#endif
	if (!prefetch) {
		/*
		 * random access
		 */
		if (ioc_inode->ia_size < table->cache_size &&
			ioc_inode->ia_size) {
			/*
			 * If the file is small enough, even random access
			 * we still cache it.
			 */
			goto do_cache;
		}
                  
		if (size < table->nocache_throttle) {
			/* if we detect this is small random access */
			frame->local = ioc_inode;
			STACK_WIND (frame, ioc_readv_disabled_cbk,
				    FIRST_CHILD (frame->this),
				    FIRST_CHILD (frame->this)->fops->readv, fd, size,
				    offset, flags, xdata);
			return 0;
		}
	}

do_cache:
        ioc_table_lock (table);
        {
                if (!table->mem_pool) {

                        num_pages = (table->cache_size / table->page_size)
                                + ((table->cache_size % table->page_size)
                                   ? 1 : 0);
			num_pages = num_pages + max(table->ra_pagecnt, 1);
                        table->mem_pool
                                =  mem_pool_new (rbthash_entry_t, num_pages);

                        if (!table->mem_pool) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "Unable to allocate mem_pool");
                                op_errno = ENOMEM;
                                ioc_table_unlock (table);
                                goto out;
                        }
                }
        }
        ioc_table_unlock (table);

        ioc_inode_lock (ioc_inode);
        {
                if (!ioc_inode->cache.page_table) {
                        ioc_inode->cache.page_table
                                = rbthash_table_init
                                (IOC_PAGE_TABLE_BUCKET_COUNT,
                                 ioc_hashfn, NULL, 0,
                                 table->mem_pool);

                        if (ioc_inode->cache.page_table == NULL) {
                                op_errno = ENOMEM;
                                ioc_inode_unlock (ioc_inode);
                                goto out;
                        }
                }
        }
        ioc_inode_unlock (ioc_inode);

        if (!fd_ctx_get (fd, this, NULL)) {
                /* disable caching for this fd, go ahead with normal readv */
		frame->local = ioc_inode;
                STACK_WIND (frame, ioc_readv_disabled_cbk,
                            FIRST_CHILD (frame->this),
                            FIRST_CHILD (frame->this)->fops->readv, fd, size,
                            offset, flags, xdata);
                return 0;
        }

        /*local = (ioc_local_t *) GF_CALLOC (1, sizeof (ioc_local_t),
                                            gf_ioc_mt_ioc_local_t);
        */
        local = mem_get0 (this->local_pool);
	if (local == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "out of memory");
                op_errno = ENOMEM;
                goto out;
        }

        INIT_LIST_HEAD (&local->fill_list);

        frame->local = local;
        local->pending_offset = offset;
        local->pending_size = size;
        local->offset = offset;
        local->size = size;
        local->inode = ioc_inode;

        gf_log (this->name, GF_LOG_TRACE,
                "NEW REQ (%p) offset = %"PRId64" && size = %"GF_PRI_SIZET"",
                frame, offset, size);

        weight = ioc_inode->weight;

        ioc_table_lock (ioc_inode->table);
        {
                list_move_tail (&ioc_inode->inode_lru,
                                &ioc_inode->table->inode_lru[weight]);
        }
        ioc_table_unlock (ioc_inode->table);

        ioc_dispatch_requests (frame, ioc_inode, fd, offset, size);

	if (prefetch)
		ioc_prefetch (frame, ioc_inode, fd, &st);

	ioc_frame_return (frame);

        if (ioc_need_prune (ioc_inode->table)) {
                ioc_prune (ioc_inode->table);
        }

        return 0;

out:
        STACK_UNWIND_STRICT (readv, frame, -1, op_errno, NULL, 0, NULL, NULL, NULL);
        return 0;
}

/*
 * ioc_writev_cbk -
 *
 * @frame:
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 *
 */
int32_t
ioc_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret,	int32_t op_errno, struct iatt *prebuf,
                struct iatt *postbuf, dict_t *xdata)
{
        ioc_local_t *local = NULL;
        uint64_t     tmp_ioc_inode = 0;
        ioc_inode_t *ioc_inode = NULL;
	fd_t *fd;

        local = frame->local;
	fd = local->fd;
        inode_ctx_get (fd->inode, this, &tmp_ioc_inode);
        ioc_inode = (ioc_inode_t *)(long)tmp_ioc_inode;

	if (!op_ret && ioc_inode) {
		if ((prebuf->ia_mtime != ioc_inode->cache.mtime) ||
		    (prebuf->ia_mtime_nsec != ioc_inode->cache.mtime_nsec)) {
			ioc_inode_flush (ioc_inode);
		    } else {
			/*
			 * update cache mtime
			 */
			ioc_inode_lock (ioc_inode);
			ioc_inode->cache.mtime = postbuf->ia_mtime;
			ioc_inode->cache.mtime_nsec = postbuf->ia_mtime_nsec;
			ioc_inode_unlock (ioc_inode);
		}
	}

        STACK_UNWIND_STRICT (writev, frame, op_ret, op_errno, prebuf, postbuf, xdata);
        return 0;
}

/*
 * ioc_writev
 *
 * @frame:
 * @this:
 * @fd:
 * @vector:
 * @count:
 * @offset:
 *
 */
int32_t
ioc_writev (call_frame_t *frame, xlator_t *this, fd_t *fd,
            struct iovec *vector, int32_t count, off_t offset,
            uint32_t flags,  struct iobref *iobref, dict_t *xdata)
{
        ioc_local_t *local = NULL;
        ioc_table_t *table = NULL;
        ioc_page_t  *trav = NULL;
        uint64_t     tmp_ioc_inode = 0;
        ioc_inode_t *ioc_inode = NULL;
        off_t        rounded_offset = 0;
        off_t        rounded_end = 0;
        off_t        trav_offset = 0;
	int64_t     destroy_size = 0;
	int64_t	    ret = 0;


        //local = GF_CALLOC (1, sizeof (ioc_local_t), gf_ioc_mt_ioc_local_t);
        local = mem_get0 (this->local_pool);
        if (local == NULL) {
                gf_log (this->name, GF_LOG_ERROR, "out of memory");

                STACK_UNWIND_STRICT (writev, frame, -1, ENOMEM, NULL, NULL, NULL);
                return 0;
        }

        /* TODO: why is it not fd_ref'ed */
        local->fd = fd;
        frame->local = local;

        inode_ctx_get (fd->inode, this, &tmp_ioc_inode);
        ioc_inode = (ioc_inode_t *)(long)tmp_ioc_inode;
        if (!ioc_inode)
                goto wind;

        table = ioc_inode->table;

        rounded_offset = floor (offset, table->page_size);
        rounded_end = roof (offset + iov_length (vector, count), table->page_size);
        trav_offset = rounded_offset;

        while (trav_offset < rounded_end) {
                ioc_inode_lock (ioc_inode);
		/* look for requested region in the cache */
		trav = __ioc_page_get (ioc_inode, trav_offset);
		if (trav) {
			/*
			 * Writing page is in the cache, so invalidate
			 * cache for the page.
			 */
			ret = __ioc_page_destroy (trav);
			if (ret != -1)
				destroy_size += ret;
		}
		ioc_inode_unlock (ioc_inode);
                trav_offset += table->page_size;
	}

        if (destroy_size) {
                ioc_table_lock (table);
		table->cache_used -= destroy_size;
                ioc_table_unlock (table);
        }

wind:
        STACK_WIND (frame, ioc_writev_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->writev, fd, vector, count, offset,
                    flags, iobref, xdata);
	return 0;
}

/*
 * ioc_truncate_cbk -
 *
 * @frame:
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @buf:
 *
 */
int32_t
ioc_truncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                  struct iatt *postbuf, dict_t *xdata)
{

        STACK_UNWIND_STRICT (truncate, frame, op_ret, op_errno, prebuf,
                             postbuf, xdata);
        return 0;
}


/*
 * ioc_ftruncate_cbk -
 *
 * @frame:
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @buf:
 *
 */
int32_t
ioc_ftruncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                   struct iatt *postbuf, dict_t *xdata)
{

        STACK_UNWIND_STRICT (ftruncate, frame, op_ret, op_errno, prebuf,
                             postbuf, xdata);
        return 0;
}


/*
 * ioc_truncate -
 *
 * @frame:
 * @this:
 * @loc:
 * @offset:
 *
 */
int32_t
ioc_truncate (call_frame_t *frame, xlator_t *this, loc_t *loc, off_t offset, dict_t *xdata)
{
        uint64_t ioc_inode = 0;

        inode_ctx_get (loc->inode, this, &ioc_inode);

        if (ioc_inode)
                ioc_inode_flush ((ioc_inode_t *)(long)ioc_inode);

        STACK_WIND (frame, ioc_truncate_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->truncate, loc, offset, xdata);
        return 0;
}

/*
 * ioc_ftruncate -
 *
 * @frame:
 * @this:
 * @fd:
 * @offset:
 *
 */
int32_t
ioc_ftruncate (call_frame_t *frame, xlator_t *this, fd_t *fd, off_t offset, dict_t *xdata)
{
        uint64_t ioc_inode = 0;

        inode_ctx_get (fd->inode, this, &ioc_inode);

        if (ioc_inode)
                ioc_inode_flush ((ioc_inode_t *)(long)ioc_inode);

        STACK_WIND (frame, ioc_ftruncate_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->ftruncate, fd, offset, xdata);
        return 0;
}

int32_t
ioc_lk_cbk (call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
            int32_t op_errno, struct gf_flock *lock, dict_t *xdata)
{
        STACK_UNWIND_STRICT (lk, frame, op_ret, op_errno, lock, xdata);
        return 0;
}

int32_t
ioc_lk (call_frame_t *frame, xlator_t *this, fd_t *fd, int32_t cmd,
        struct gf_flock *lock, dict_t *xdata)
{
        ioc_inode_t *ioc_inode = NULL;
        uint64_t     tmp_inode = 0;
	int ret = -1;

        ret = inode_ctx_get (fd->inode, this, &tmp_inode);
	if (ret)
		goto wind;

        ioc_inode = (ioc_inode_t *)(long)tmp_inode;
        if (!ioc_inode) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "inode context is NULL: returning EBADFD");
                STACK_UNWIND_STRICT (lk, frame, -1, EBADFD, NULL, NULL);
                return 0;
        }

        ioc_inode_lock (ioc_inode);
        {
                gettimeofday (&ioc_inode->cache.tv, NULL);
        }
        ioc_inode_unlock (ioc_inode);

wind:
        STACK_WIND (frame, ioc_lk_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->lk, fd, cmd, lock, xdata);

        return 0;
}

int32_t
ioc_get_priority_list (const char *opt_str, struct list_head *first)
{
        int32_t              max_pri    = 1;
        char                *tmp_str    = NULL;
        char                *tmp_str1   = NULL;
        char                *tmp_str2   = NULL;
        char                *dup_str    = NULL;
        char                *stripe_str = NULL;
        char                *pattern    = NULL;
        char                *priority   = NULL;
        char                *string     = NULL;
        struct ioc_priority *curr       = NULL, *tmp = NULL;

        string = gf_strdup (opt_str);
        if (string == NULL) {
                max_pri = -1;
                goto out;
        }

        /* Get the pattern for cache priority.
         * "option priority *.jpg:1,abc*:2" etc
         */
        /* TODO: inode_lru in table is statically hard-coded to 5,
         * should be changed to run-time configuration
         */
        stripe_str = strtok_r (string, ",", &tmp_str);
        while (stripe_str) {
                curr = GF_CALLOC (1, sizeof (struct ioc_priority),
                                  gf_ioc_mt_ioc_priority);
                if (curr == NULL) {
                        max_pri = -1;
                        goto out;
                }

                list_add_tail (&curr->list, first);

                dup_str = gf_strdup (stripe_str);
                if (dup_str == NULL) {
                        max_pri = -1;
                        goto out;
                }

                pattern = strtok_r (dup_str, ":", &tmp_str1);
                if (!pattern) {
                        max_pri = -1;
                        goto out;
                }

                priority = strtok_r (NULL, ":", &tmp_str1);
                if (!priority) {
                        max_pri = -1;
                        goto out;
                }

                gf_log ("io-cache", GF_LOG_TRACE,
                        "ioc priority : pattern %s : priority %s",
                        pattern,
                        priority);

                curr->pattern = gf_strdup (pattern);
                if (curr->pattern == NULL) {
                        max_pri = -1;
                        goto out;
                }

                curr->priority = strtol (priority, &tmp_str2, 0);
                if (tmp_str2 && (*tmp_str2)) {
                        max_pri = -1;
                        goto out;
                } else {
                        max_pri = max (max_pri, curr->priority);
                }

                GF_FREE (dup_str);
                dup_str = NULL;

                stripe_str = strtok_r (NULL, ",", &tmp_str);
        }
out:
        if (string != NULL) {
                GF_FREE (string);
        }

        if (dup_str != NULL) {
                GF_FREE (dup_str);
        }

        if (max_pri == -1) {
                list_for_each_entry_safe (curr, tmp, first, list) {
                        list_del_init (&curr->list);
                        GF_FREE (curr->pattern);
                        GF_FREE (curr);
                }
        }

        return max_pri;
}

int32_t
mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        if (!this)
                return ret;

        ret = xlator_mem_acct_init (this, gf_ioc_mt_end + 1);

        if (ret != 0) {
                gf_log (this->name, GF_LOG_ERROR, "Memory accounting init"
                        "failed");
                return ret;
        }

        return ret;
}
/*
int
validate_options (xlator_t *this, char **op_errstr)
{
        int                ret     = 0;
        volume_opt_list_t *vol_opt = NULL;
        volume_opt_list_t *tmp;

        if (!this) {
                gf_log (this->name, GF_LOG_DEBUG, "'this' not a valid ptr");
                ret =-1;
                goto out;
        }

        if (list_empty (&this->volume_options))
                goto out;

        vol_opt = list_entry (this->volume_options.next,
                              volume_opt_list_t, list);
        list_for_each_entry_safe (vol_opt, tmp, &this->volume_options, list) {
                ret = validate_xlator_volume_options_attacherr (this,
                                                                vol_opt->given_opt,
                                                                op_errstr);
        }

out:

        return ret;
}
*/
static gf_boolean_t
check_cache_size_ok (xlator_t *this, uint64_t cache_size)
{
        gf_boolean_t            ret = _gf_true;
        uint64_t                total_mem = 0;
        uint64_t                max_cache_size = 0;
        volume_option_t         *opt = NULL;

        GF_ASSERT (this);
        opt = xlator_volume_option_get (this, "cache-size");
        if (!opt) {
                ret = _gf_false;
                gf_log (this->name, GF_LOG_ERROR,
                        "could not get cache-size option");
                goto out;
        }

        total_mem = get_mem_size ();
        if (-1 == total_mem)
                max_cache_size = opt->max;
        else
                max_cache_size = total_mem;

        gf_msg_debug (this->name, 0, "Max cache size is %"PRIu64,
                      max_cache_size);

        if (cache_size > max_cache_size) {
                ret = _gf_false;
                gf_log (this->name, GF_LOG_ERROR,
                        "Cache size %"PRIu64
                        " is greater than the max size of %"PRIu64,
                        cache_size, max_cache_size);
                goto out;
        }
out:
        return ret;
}
	int
reconfigure (xlator_t *this, dict_t *options)
{
	ioc_table_t *table             = NULL;
	int          ret               = 0;
	uint64_t      cache_size_new    = 0;

	if (!this || !this->private)
		goto out;

	table = this->private;

	ioc_table_lock (table);
	{
		GF_OPTION_RECONF ("cache-timeout", table->cache_timeout,
				options, int32, unlock);

		GF_OPTION_RECONF ("max-streams", table->max_streams,
				options, uint32, unlock);
		GF_OPTION_RECONF ("prefetch-page-count", table->ra_pagecnt,
				options,uint32, unlock);
               
		gf_log(this->name,GF_LOG_INFO,"table->ra_pagecnt = %u",table->ra_pagecnt);
		GF_OPTION_RECONF ("ioc-multistreams", table->fetch_status,
				options, bool, unlock);

		gf_log (this->name, GF_LOG_INFO,"ioc-fetch multistreams %s ", table->fetch_status > 0 ? "enabel" :"disable");
		GF_OPTION_RECONF ("cache-size", cache_size_new,
				options, size_uint64, unlock);
		if (cache_size_new < (4 * GF_UNIT_MB)) {
			gf_log(this->name, GF_LOG_ERROR,
					"Reconfiguration"
					"'option cache-size (%"PRIu64")' failed , "
					"Max value can be 4MiB, Defaulting to "
					"old value (%"PRIu64")",
					cache_size_new, table->cache_size);
			goto unlock;
		}

		if (cache_size_new > (6 * GF_UNIT_GB)) {
			gf_log (this->name, GF_LOG_ERROR,
					"Reconfiguration"
					"'option cache-size (%"PRIu64")' failed , "
					"Max value can be 6GiB, Defaulting to "
					"old value (%"PRIu64")",
					cache_size_new, table->cache_size);
			goto unlock;
		}
		gf_log (this->name, GF_LOG_DEBUG, "Reconfiguring "
				" cache-size %"PRIu64"", cache_size_new);
                table->cache_size = cache_size_new;

		GF_OPTION_RECONF("no-cache-throttle", table->nocache_throttle, 
				options, size_uint64, unlock);

		if (dict_get (options, "priority")) {
			char *option_list = data_to_str (dict_get (options,
						"priority"));
			gf_log (this->name, GF_LOG_TRACE,
					"option path %s", option_list);
			/* parse the list of pattern:priority */
			table->max_pri = ioc_get_priority_list (option_list,
					&table->priority_list);

			if (table->max_pri == -1) {
				ret = -1;
				goto out;
			}
			table->max_pri ++;
		}

		GF_OPTION_RECONF ("max-file-size", table->max_file_size,
				options, int64, unlock);

		GF_OPTION_RECONF ("min-file-size", table->min_file_size,
				options, int64, unlock);

		if ((table->max_file_size >= 0) && (table->min_file_size > table->max_file_size)) {
			gf_log ("io-cache", GF_LOG_ERROR, "minimum size (%"
					PRIu64") of a file that can be cached is "
					"greater than maximum size (%"PRIu64"). "
					"Hence Defaulting to old value",
					table->min_file_size, table->max_file_size);
			goto out;
		}

	}
unlock:
	ioc_table_unlock (table);
out:
	return ret;
}

/*
 * init -
 * @this:
 *
 */
	int32_t
init (xlator_t *this)
{
	ioc_table_t     *table             = NULL;
	dict_t          *xl_options        = this->options;
	uint32_t         index             = 0;
	int32_t          ret               = -1;
	char            *cache_size_string = NULL;
	glusterfs_ctx_t      *ctx               = NULL;
	data_t          *data              = 0;

	xl_options = this->options;

	if (!this->children || this->children->next) {
		gf_log (this->name, GF_LOG_ERROR,
				"FATAL: io-cache not configured with exactly "
				"one child");
		goto out;
	}

	if (!this->parents) {
		gf_log (this->name, GF_LOG_WARNING,
				"dangling volume. check volfile ");
	}

	table = (void *) GF_CALLOC (1, sizeof (*table), gf_ioc_mt_ioc_table_t);
	if (table == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "out of memory");
		goto out;
	}

	table->xl = this;
	table->page_size = this->ctx->page_size;
	table->cache_size = IOC_CACHE_SIZE;
#ifdef PERF_STATS
	table->elapsed = 0.0;
#endif
	GF_OPTION_INIT ("max-streams", table->max_streams, uint32, out);
	GF_OPTION_INIT ("ioc-multistreams", table->fetch_status, bool, out);
	GF_OPTION_INIT ("cache-size", table->cache_size, size_uint64, out);
	GF_OPTION_INIT ("water-mark", table->water_mark, size_uint64, out);
	GF_OPTION_INIT ("cache-timeout", table->cache_timeout, int32, out);
	GF_OPTION_INIT ("prefetch-page-count", table->ra_pagecnt, uint32, out);
	GF_OPTION_INIT ("min-file-size", table->min_file_size, int64, out);
	GF_OPTION_INIT ("max-file-size", table->max_file_size, int64, out);
	GF_OPTION_INIT ("no-cache-throttle", table->nocache_throttle, size_uint64, out);

        gf_log (this->name, GF_LOG_TRACE,
                        "using page-size %"PRIu64"", table->page_size);
        gf_log (this->name, GF_LOG_INFO,"ioc-fetch multistreams %s ", table->fetch_status > 0 ? "enabel" :"disable");
	gf_log(this->name,GF_LOG_INFO,"table->ra_pagecnt = %u",table->ra_pagecnt);
	if  (!check_cache_size_ok (this, table->cache_size)) {
		ret = -1;
		goto out;
	}


	if (table->water_mark >= (table->cache_size / 2)) {
		gf_log ("io-cache", GF_LOG_ERROR,
				"invalid number \"%s\" of "
				"\"option water-mark\", it should not"
				"exceed half of cache_size",
				cache_size_string);

	}
	gf_log (this->name, GF_LOG_TRACE,
			"using water mark %"PRIu64"", table->water_mark);

	INIT_LIST_HEAD (&table->priority_list);
	table->max_pri = 1;
	data = dict_get (xl_options, "priority");
	if (data) {
		char *option_list = data_to_str (data);
		gf_log (this->name, GF_LOG_TRACE,
				"option path %s", option_list);
		/* parse the list of pattern:priority */
		table->max_pri = ioc_get_priority_list (option_list,
				&table->priority_list);

		if (table->max_pri == -1) {
			goto out;
		}
	}
	table->max_pri ++;

	INIT_LIST_HEAD (&table->inodes);

	if ((table->max_file_size >= 0)
			&& (table->min_file_size > table->max_file_size)) {
		gf_log ("io-cache", GF_LOG_ERROR, "minimum size (%"
				PRIu64") of a file that can be cached is "
				"greater than maximum size (%"PRIu64")",
				table->min_file_size, table->max_file_size);
		goto out;
	}

        table->inode_lru = GF_CALLOC (table->max_pri,
                        sizeof (struct list_head),
                        gf_ioc_mt_list_head);
        if (table->inode_lru == NULL) {
                goto out;
        }

        for (index = 0; index < (table->max_pri); index++)
                INIT_LIST_HEAD (&table->inode_lru[index]);

        this->local_pool = mem_pool_new (ioc_local_t, 64);
        if (!this->local_pool) {
                ret = -1;
                gf_log (this->name, GF_LOG_ERROR,
                                "failed to create local_t's memory pool");
                goto out;
        }
        pthread_mutex_init (&table->table_lock, NULL);
        this->private = table;

        ret = 0;

        ctx = this->ctx;
        ioc_log2_page_size = log_base2 (ctx->page_size);

out:
        if (ret == -1) {
                if (table != NULL) {
                        GF_FREE (table->inode_lru);
                        GF_FREE (table);
                }
        }
        return ret;

}

	int
ioc_priv_dump (xlator_t *this)
{
        ioc_table_t *priv                            = NULL;
        char         key_prefix[GF_DUMP_MAX_BUF_LEN] = {0, };
        char         key[GF_DUMP_MAX_BUF_LEN]        = {0, };

        if (!this || !this->private)
                goto out;

        priv = this->private;
        gf_proc_dump_build_key (key_prefix, "xlator.performance.io-cache",
                                "priv");
        gf_proc_dump_add_section (key_prefix);

        gf_proc_dump_build_key (key, key_prefix, "page_size");
        gf_proc_dump_write (key, "%ld", priv->page_size);
        gf_proc_dump_build_key (key, key_prefix, "cache_size");
        gf_proc_dump_write (key, "%ld", priv->cache_size);
        gf_proc_dump_build_key (key, key_prefix, "cache_used");
        gf_proc_dump_write (key, "%ld", priv->cache_used);
        gf_proc_dump_build_key (key, key_prefix, "inode_count");
        gf_proc_dump_write (key, "%u", priv->inode_count);
        gf_proc_dump_build_key (key, key_prefix, "fetch_page_count");
        gf_proc_dump_write (key, "%u", priv->ra_pagecnt);
#ifdef PERF_STATS
        gf_proc_dump_build_key (key, key_prefix, "fault_count");
        gf_proc_dump_write (key, "%u", priv->faultcnt);
        gf_proc_dump_build_key (key, key_prefix, "readv_count");
        gf_proc_dump_write (key, "%u", priv->readcnt);
        gf_proc_dump_build_key (key, key_prefix, "hit_count");
        gf_proc_dump_write (key, "%u", priv->hitcnt);
        gf_proc_dump_build_key (key, key_prefix, "conti_count");
        gf_proc_dump_write (key, "%u", priv->conticnt);
        gf_proc_dump_build_key (key, key_prefix, "wait_count");
        gf_proc_dump_write (key, "%u", priv->waitcnt);
        gf_proc_dump_build_key (key, key_prefix, "cache_timeout_count");
        gf_proc_dump_write (key, "%u", priv->timeoutcnt);
        gf_proc_dump_build_key (key, key_prefix, "wasted_prefetch_count");
        gf_proc_dump_write (key, "%u", priv->wasteracnt);
        gf_proc_dump_build_key (key, key_prefix, "page_count");
        gf_proc_dump_write (key, "%u", priv->pagecnt);
        gf_proc_dump_build_key (key, key_prefix, "elapsed");
        gf_proc_dump_write (key, "%f", priv->elapsed);
        gf_proc_dump_build_key (key, key_prefix, "average elapsed");
        gf_proc_dump_write (key, "%f", priv->elapsed / priv->faultcnt);
        priv->elapsed = 0;
        priv->wasteracnt = 0;
        priv->faultcnt = 0;
	priv->hitcnt = 0;
	priv->waitcnt = 0;
	priv->readcnt = 0;
	priv->conticnt = 0;
	priv->faultcnt = 0;
#endif

out:
        return 0;
}

/*
 * fini -
 *
 * @this:
 *
 */
void
fini (xlator_t *this)
{
        ioc_table_t *table = NULL;

        table = this->private;

        if (table == NULL)
                return;

        if (table->mem_pool != NULL) {
                mem_pool_destroy (table->mem_pool);
                table->mem_pool = NULL;
        }

        pthread_mutex_destroy (&table->table_lock);
        GF_FREE (table);

        this->private = NULL;
        return;
}

struct xlator_fops fops = {
        .open        = ioc_open,
        .create      = ioc_create,
        .readv       = ioc_readv,
        .writev      = ioc_writev,
        .truncate    = ioc_truncate,
        .ftruncate   = ioc_ftruncate,
        .lookup      = ioc_lookup,
        .lk          = ioc_lk,
        .setattr     = ioc_setattr,
        .mknod       = ioc_mknod
};


struct xlator_dumpops dumpops = {
        .priv        = ioc_priv_dump,
};

struct xlator_cbks cbks = {
        .forget      = ioc_forget,
        .release     = ioc_release
};

struct volume_options options[] = {
        { .key  = {"priority"},
          .type = GF_OPTION_TYPE_ANY,
          .default_value = "",
          .description = "Assigns priority to filenames with specific "
                         "patterns so that when a page needs to be ejected "
                         "out of the cache, the page of a file whose "
                         "priority is the lowest will be ejected earlier"
        },
        { .key  = {"cache-timeout", "force-revalidate-timeout"},
          .type = GF_OPTION_TYPE_INT,
          .min  = 0,
          .max  = 60,
          .default_value = "5",
          .description = "The cached data for a file will be retained till "
                         "'cache-refresh-timeout' seconds, after which data "
                         "re-validation is performed."
        },
        { .key  = {"cache-size"},
          .type = GF_OPTION_TYPE_SIZET,
          .min  = 4 * GF_UNIT_MB,
          .max  = 6 * GF_UNIT_GB,
          .default_value = "64MB",
          .description = "Size of the read cache."
        },
        { .key  = {"no-cache-throttle"},
          .type = GF_OPTION_TYPE_SIZET,
          .min  = 0,
          .max  = 128 * GF_UNIT_KB,
          .default_value = "32KB",
          .description = "When read request length is less than the throttle "
			 "if detects non-sequential read, disable io-cache for "
	                 "the read request."
        },
        { .key  = {"water-mark"},
          .type = GF_OPTION_TYPE_SIZET,
          .min = 0,
          .max = 32 * GF_UNIT_MB,
          .default_value = "8MB",
          .description = "Size of the cache low water mark."
        },
        { .key  = {"prefetch-page-count"},
          .type = GF_OPTION_TYPE_INT,
          .min  = 1,
          .max  = 16,
          .default_value = "4",
          .description = "Page count of the prefetch."
			 "if the value is 0, the prefetch "
			 "is disabled."
        },
        { .key  = {"min-file-size"},
          .type = GF_OPTION_TYPE_SIZET,
          .default_value = "0",
          .description = "Minimum file size which would be cached by the "
                         "io-cache translator."
        },
        { .key  = {"max-file-size"},
          .type = GF_OPTION_TYPE_SIZET,
          .default_value = "0",
          .description = "Maximum file size which would be cached by the "
                         "io-cache translator."
        },
        { .key  = {"max-streams"},
          .type = GF_OPTION_TYPE_SIZET,
          .default_value = "16",
          .description = "Maximum  streams which  "
                         "io-cache translator."
        },
        { .key  = {"ioc-multistreams"},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "off",
          .description = " ioc-fetch multistreams which  "
                         "io-cache translator default disable"
        },
        { .key = {NULL} },
};
