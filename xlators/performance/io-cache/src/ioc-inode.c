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

#include "io-cache.h"
#include "ioc-mem-types.h"

extern int ioc_log2_page_size;

/*
 * str_to_ptr - convert a string to pointer
 * @string: string
 *
 */
void *
str_to_ptr (char *string)
{
        void *ptr = NULL;

        GF_VALIDATE_OR_GOTO ("io-cache", string, out);

        ptr = (void *)strtoul (string, NULL, 16);

out:
        return ptr;
}


/*
 * ptr_to_str - convert a pointer to string
 * @ptr: pointer
 *
 */
char *
ptr_to_str (void *ptr)
{
        int   ret = 0;
        char *str = NULL;

        GF_VALIDATE_OR_GOTO ("io-cache", ptr, out);

        ret = gf_asprintf (&str, "%p", ptr);
        if (-1 == ret) {
                gf_log ("io-cache", GF_LOG_WARNING,
                        "asprintf failed while converting ptr to str");
                str = NULL;
                goto out;
        }

out:
        return str;
}


void
ioc_inode_wakeup (call_frame_t *frame, ioc_inode_t *ioc_inode,
                  struct iatt *stbuf)
{
        ioc_waitq_t *waiter            = NULL, *waited = NULL;
        ioc_waitq_t *page_waitq        = NULL;
        int8_t       cache_still_valid = 1;
        ioc_local_t *local             = NULL;
        int8_t       need_fault        = 0;
        ioc_page_t  *waiter_page       = NULL;
        ioc_table_t *table             = NULL;
	uint64_t    generation	       = 0;

        GF_VALIDATE_OR_GOTO ("io-cache", frame, out);

        local = frame->local;
        GF_VALIDATE_OR_GOTO (frame->this->name, local, out);

        if (ioc_inode == NULL) {
                local->op_ret = -1;
                local->op_errno = EINVAL;
                gf_log (frame->this->name, GF_LOG_WARNING, "ioc_inode is NULL");
                goto out;
        }

        table = ioc_inode->table;
        if(!table){
           gf_log(frame->this->name,GF_LOG_ERROR,"table is NULL");
        }

        if (stbuf)
                cache_still_valid = ioc_cache_still_valid (ioc_inode, stbuf);
        else
                cache_still_valid = 0;

        ioc_inode_lock (ioc_inode);
        {
                waiter = ioc_inode->waitq;
                if (!waiter) {
                        gf_log (frame->this->name, GF_LOG_WARNING,
                                        "cache validate called without any "
                                        "page waiting to be validated");
                        ioc_inode_unlock (ioc_inode);
                        goto out;
                }

                while (waiter) {
                        waiter_page = waiter->data;
                        ioc_inode->waitq = waiter->next;
                        page_waitq = NULL;
                        generation = waiter->generation;

                        if (waiter_page) {
                                if (cache_still_valid) {
                                        /* cache valid, wake up page */

                                        page_waitq =
                                                __ioc_page_wakeup (waiter_page,
                                                                generation);

                                        if (page_waitq) {
                                                ioc_inode_unlock (ioc_inode);
                                                ioc_waitq_return (page_waitq);
                                                ioc_inode_lock (ioc_inode);
                                        }

                                } else {
                                        /* cache invalid, generate page fault and set
                                         * page state to in transit, to avoid double
                                         * faults
                                         */

                                        switch (waiter_page->state) {
                                                case IOC_PAGE_STATE_CLEAN:
                                                        atomic_inc_and_fetch(&waiter_page->gen);
                                                        /*
                                                         * Fall through, change state and
                                                         * set need_fault.
                                                         */
                                                case IOC_PAGE_STATE_DIRTY:
                                                        waiter_page->state = IOC_PAGE_STATE_INTRAN;
                                                        generation = waiter_page->gen;
                                                        need_fault = 1;
                                                        break;
                                                case IOC_PAGE_STATE_INTRAN:
                                                        gf_log (frame->this->name,
                                                                        GF_LOG_TRACE,
                                                                        "validate frame(%p) is "
                                                                        "waiting for "
                                                                        "in-transit page = %p",
                                                                        frame, waiter_page);
                                                        /*
                                                         * Fall through
                                                         */
                                                default:
                                                        break;
                                        }

                                        if (need_fault) {
                                                need_fault = 0;
                                                ioc_inode_unlock (ioc_inode);
                                                ioc_page_fault (ioc_inode, frame,
                                                                local->fd,
                                                                waiter_page->offset,
                                                                generation, 2);
                                                ioc_inode_lock (ioc_inode);
                                        }
                                }
                        }

                        waited = waiter;
                        waiter = ioc_inode->waitq;

                waited->data = NULL;
                GF_FREE (waited);
        }
        }
        ioc_inode_unlock (ioc_inode);

out:
        return;
}


/*
 * ioc_inode_update - create a new ioc_inode_t structure and add it to
 *                    the table table. fill in the fields which are derived
 *                    from inode_t corresponding to the file
 *
 * @table: io-table structure
 * @inode: inode structure
 *
 * not for external reference
 */
ioc_inode_t *
ioc_inode_update (ioc_table_t *table, inode_t *inode, uint32_t weight)
{
        ioc_inode_t     *ioc_inode   = NULL;

        GF_VALIDATE_OR_GOTO ("io-cache", table, out);

        ioc_inode = GF_CALLOC (1, sizeof (ioc_inode_t), gf_ioc_mt_ioc_inode_t);
        if (ioc_inode == NULL) {
                goto out;
        }

        ioc_inode->table = table;
        INIT_LIST_HEAD (&ioc_inode->cache.page_lru);
        pthread_mutex_init (&ioc_inode->inode_lock, NULL);
        ioc_inode->weight = weight;

        ioc_table_lock (table);
        {
                table->inode_count++;
                list_add (&ioc_inode->inode_list, &table->inodes);
                list_add_tail (&ioc_inode->inode_lru,
                               &table->inode_lru[weight]);
        }
        ioc_table_unlock (table);

	INIT_LIST_HEAD (&ioc_inode->streams);
        pthread_rwlock_init (&ioc_inode->stream_lock, NULL);
	ioc_inode->stream_cnt = 0;

        gf_log (table->xl->name, GF_LOG_TRACE,
                "adding to inode_lru[%d]", weight);

out:
        return ioc_inode;
}


/*
 * ioc_inode_destroy - destroy an ioc_inode_t object.
 *
 * @inode: inode to destroy
 *
 * to be called only from ioc_forget.
 */
void
ioc_inode_destroy (ioc_inode_t *ioc_inode)
{
        ioc_table_t *table = NULL;

        GF_VALIDATE_OR_GOTO ("io-cache", ioc_inode, out);

        table = ioc_inode->table;

        ioc_table_lock (table);
        {
                table->inode_count--;
                list_del (&ioc_inode->inode_list);
                list_del (&ioc_inode->inode_lru);
        }
        ioc_table_unlock (table);

        ioc_inode_flush (ioc_inode);
        rbthash_table_destroy (ioc_inode->cache.page_table);
	ioc_fetch_free(ioc_inode);
	pthread_rwlock_destroy(&ioc_inode->stream_lock);
        pthread_mutex_destroy (&ioc_inode->inode_lock);
        GF_FREE (ioc_inode);
out:
        return;
}
