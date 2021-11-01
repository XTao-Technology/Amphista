/*
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

static void
_ioc_fetch_stream_remove(ioc_inode_t *ioc_inode, ioc_stream_t *stream)
{
	list_del(&stream->list);
	ioc_inode->stream_cnt--;
}

static int
_ioc_fetch_streams_cmp(ioc_stream_t *s1, ioc_stream_t *s2)
{
	if (s1->offset != s2->offset)
		return (1);

	if (s1->len != s2->len)
		return (1);

	if (s1->stride != s2->stride)
		return (1);

	if (s1->direction != s2->direction)
		return (1);

	return (0);
}

static int
ioc_fetch_stream_insert(ioc_inode_t *ioc_inode, ioc_stream_t *stream)
{
	ioc_stream_t *walk = NULL;

	pthread_rwlock_wrlock(&ioc_inode->stream_lock);
	list_for_each_entry (walk, &ioc_inode->streams, list) {
		if (!_ioc_fetch_streams_cmp(walk, stream)) {
			return (0);
		}
	}
	list_add_tail(&stream->list, &ioc_inode->streams);
	ioc_inode->stream_cnt++;
        gf_log("gaoyanping",GF_LOG_INFO,"stream insert ioc_inode->stream_cnt = %d",ioc_inode->stream_cnt);
	pthread_rwlock_unlock(&ioc_inode->stream_lock);
	return (1);
}

static ioc_stream_t *
ioc_fetch_stream_reclaim (ioc_inode_t *ioc_inode)
{
	ioc_stream_t *st = NULL;
	ioc_stream_t *walk = NULL;
	struct timeval now = {0, };

	/*
	 * grap stream write lock since it could remove
	 * entry from the list.
	 */
	if (pthread_rwlock_trywrlock(&ioc_inode->stream_lock)) {
		return st;
	}

	list_for_each_entry (walk, &ioc_inode->streams, list) {
		gettimeofday (&now, NULL);
		if(now.tv_sec - walk->last.tv_sec > 2){
			st = walk;
			break;
		}
	}

	if (st) {
		_ioc_fetch_stream_remove(ioc_inode, st);
		pthread_mutex_destroy(&st->lock);
		memset(st, 0, sizeof(ioc_stream_t));
	}
	pthread_rwlock_unlock(&ioc_inode->stream_lock);
	return st;
}

static int
ioc_fetch_colinear (ioc_inode_t *ioc_inode, ioc_stream_t *stream)
{
	int fetched = 0;
	ioc_stream_t *walk = NULL;
	ioc_stream_t *comp = NULL;
	ioc_stream_t *n1 = NULL;
	ioc_stream_t *n2 = NULL;
        ioc_table_t *table = ioc_inode->table;
	uint64_t ra_size = table->page_size * table->ra_pagecnt;
	int diff = 0;

	/*
	 * could merge two stream into colinear one, we need
	 * grab write lock for the ioc_inode->stream_lock
	 */
	if (pthread_rwlock_trywrlock(&ioc_inode->stream_lock))
		return fetched;

	list_for_each_entry_safe (walk, n1, &ioc_inode->streams, list) {
		list_for_each_entry_safe (comp, n2, &ioc_inode->streams, list) {
			/*
			 * if stream->len has already not equal to stride which
			 * means the stream has already been merged previously.
			 */
			if ((walk->len != walk->stride) ||
			    (comp->len != comp->stride))
				continue;

			/*
			 * The distance between two streams.
			 */

			/*
			 *            <stride>           <stride>
			 * comp stream--------walk stream--------new stream
			 *
			 * above is stride stream, we need remove comp stream
			 * and update walk's offset and stride.
			 */

			diff = walk->offset - comp->offset;

			if (walk->offset + diff == stream->offset) {
				walk->offset = stream->offset;
				stream->direction = walk->direction = diff < 0 ?
				    -1 : 1;
				stream->stride = walk->stride =
				    diff * walk->direction;
				walk->poffset = stream->offset +
				    walk->stride;
				/*stream->poffset = floor(walk->poffset,
				    table->page_size);
                                 */
				if((walk->direction == -1) && (stream->offset < walk->stride)){
					stream->poffset = floor(walk->poffset,
							table->page_size);
				}else{
					stream->poffset = floor((stream->offset + walk->stride * walk->direction),
							table->page_size);
				}
				gf_log("ioc-fetch",GF_LOG_TRACE," colinear 1 stream->offset = %"PRIu64" "
					" walk->stride = %"PRIu64" ,walk->direct = %d "
					"stream->poffset = %"PRIu64" ",stream->offset, walk->stride, walk->direction,
					stream->poffset);
				stream->len = walk->len > ra_size ?
					walk->len : ra_size;
				_ioc_fetch_stream_remove(ioc_inode, comp);
				pthread_mutex_destroy(&comp->lock);
				GF_FREE(comp);
				fetched = 1;
				gettimeofday (&walk->last, NULL);
				goto out;
			}
			/*
			 *            <stride>           <stride>
			 * walk stream--------comp stream--------new stream
			 *
			 * above is stride stream, we need remove walk stream
			 * and update comp's offset and stride.
			 */

			diff = comp->offset - walk->offset;
			if (comp->offset + diff == stream->offset) {
				walk->offset = stream->offset;
				stream->direction = walk->direction = diff < 0
				    ? -1: 1;
				stream->stride = walk->stride = diff *
				    walk->direction;
				walk->poffset =	stream->offset + walk->stride;
				/*stream->poffset = floor(walk->poffset,
				    table->page_size);
                                 */
				if((walk->direction == -1) && (stream->offset < walk->stride)){
					stream->poffset = floor(walk->poffset,
							table->page_size);
				}else{
					stream->poffset = floor((stream->offset + walk->stride * walk->direction),
							table->page_size);
				}
				gf_log("ioc-fetch",GF_LOG_TRACE," colinear 2 stream->offset = %"PRIu64" "
				"walk->stride = %"PRIu64" ,walk->direct = %d stream->poffset = %"PRIu64" ",                                               stream->offset, walk->stride, walk->direction, stream->poffset);
				stream->len = walk->len > ra_size ?
					walk->len : ra_size;

				_ioc_fetch_stream_remove(ioc_inode, comp);
				pthread_mutex_destroy(&comp->lock);
				GF_FREE(comp);
				gettimeofday (&walk->last, NULL);
				fetched = 1;
				goto out;
			}
		}
	}
out:
	pthread_rwlock_unlock(&ioc_inode->stream_lock);
	return fetched;
}

static int
ioc_fetch_find (ioc_inode_t *ioc_inode, ioc_stream_t *stream)
{
	int fetched = 0;
	ioc_stream_t *walk = NULL;
        ioc_table_t *table = ioc_inode->table;
	int64_t diff = 0;
	uint64_t ra_size = table->page_size * table->ra_pagecnt;

	/*
	 * grab read lock for ioc_inode->streams list
	 */
	pthread_rwlock_rdlock (&ioc_inode->stream_lock);
top:
	list_for_each_entry (walk, &ioc_inode->streams, list) {
		if (walk->len == 0)
			continue;
		/*
		 * multiple threads could grab the read lock
		 * of the ioc_inode->stream_lock, so we need
		 * grab a mutex for specific stream.
		 */
		if (stream->offset == walk->offset + walk->len) {
			/*
			 * stream forward
			 */
			if (pthread_mutex_trylock(&walk->lock)) {
				goto out;
			}

			if (stream->offset != walk->offset + walk->len) {
				pthread_mutex_unlock(&walk->lock);
				goto top;
			}
			walk->len += stream->len;

			diff = walk->len - IOC_STREAM_CAP;
			if (diff > 0) {
				walk->offset += diff;
				walk->len = walk->len > diff ? walk->len - diff : 0;
			}
			walk->poffset = walk->offset + walk->len;
			stream->poffset = floor(walk->poffset, table->page_size);

			gf_log("ioc-fetch",GF_LOG_TRACE," stream forward stream->offset = %"PRIu64" "
					"walk->stride = %"PRIu64" walk->direction = %d stream->poffset = %"PRIu64"",
                                         stream->offset, walk->stride, walk->direction, stream->poffset);
			stream->len = ra_size;
			walk->direction = GFFETCH_FORWARD;
			gettimeofday (&walk->last, NULL);
			walk->stride = walk->stride > walk->len ?
			    walk->stride : walk->len;
			pthread_mutex_unlock(&walk->lock);
			fetched = 1;
			break;
		} else if (stream->offset == walk->offset - walk->len){
			/*
			 * stream backward
			 */
			if (pthread_mutex_trylock(&walk->lock)) {
				goto out;
			}

			if (stream->offset != walk->offset - walk->len) {
				pthread_mutex_unlock(&walk->lock);
				goto top;
			}
			walk->offset = walk->offset > walk->len ?
			    walk->offset - walk->len : 0;
			walk->poffset = walk->offset > walk->len ?
			    walk->offset - walk->len : 0;
			stream->poffset = walk->offset > ra_size ?
			    floor(walk->offset - ra_size, table->page_size) : 0;

			gf_log("ioc-fetch",GF_LOG_TRACE," stream backward stream->offset = %"PRIu64""
                                            "walk->stride = %"PRIu64" walk->direction = %d stream->poffset = %"PRIu64"",
                                            stream->offset, walk->stride, walk->direction,stream->poffset);
			stream->len = walk->offset > ra_size ? ra_size :
			    walk->offset;
			walk->len += stream->len;
			diff = walk->len - IOC_STREAM_CAP;
			if (diff > 0) {
				walk->offset += diff;
				walk->len = walk->len > diff ? walk->len - diff : 0;
			}
			walk->direction = GFFETCH_BACKWARD;
			gettimeofday (&walk->last, NULL);
			walk->stride = walk->stride > walk->len ?
			    walk->stride : walk->len;
			pthread_mutex_unlock(&walk->lock);
			fetched = 1;
			break;
		} else if ((walk->len != walk->stride) && (stream->offset -
		    walk->offset - walk->stride < walk->len)) {
			/*
			 * stride forward pattern
			 */
			if (pthread_mutex_trylock(&walk->lock)) {
				goto out;
			}

			if ((walk->len == walk->stride) || (stream->offset -
			    walk->offset - walk->stride >= walk->len)) {
				pthread_mutex_unlock(&walk->lock);
				goto top;
			}

			walk->offset += walk->stride;
			stream->poffset = stream->offset + walk->stride;
			stream->poffset = floor(stream->poffset,
					table->page_size);

			gf_log("ioc-fetch",GF_LOG_TRACE,"stride forward pattern stream->offset = %"PRIu64" "
                               " walk->stride = %"PRIu64" walk->direction = %d stream->poffset = %"PRIu64" ",
                                stream->offset, walk->stride, walk->direction, stream->poffset);
			stream->len = stream->poffset + ra_size >
				walk->offset + walk->len ? ra_size:
			    walk->offset + walk->len - stream->poffset;
			walk->direction = GFFETCH_FORWARD;
			walk->stride = walk->stride > walk->len ?
			    walk->stride : walk->len;
			gettimeofday (&walk->last, NULL);
			pthread_mutex_unlock(&walk->lock);
			fetched = 1;
			break;

		} else if ((walk->len != walk->stride) && (stream->offset -
		    walk->offset + walk->stride < walk->len)) {
			/*
			 * stride backward pattern
			 */
			if (pthread_mutex_trylock(&walk->lock)) {
				goto out;
			}

			if ((walk->len == walk->stride) ||
			    (stream->offset - walk->offset + walk->stride >=
			    walk->len)) {
				pthread_mutex_unlock(&walk->lock);
				goto top;
			}
			walk->offset = walk->offset > walk->stride ?
			    walk->offset - walk->stride : 0;
			walk->poffset = walk->offset > walk->stride ?
                            walk->offset - walk->stride : 0;
			stream->poffset = floor(walk->poffset,
			    table->page_size);

			gf_log("ioc-fetch",GF_LOG_TRACE,"stride backward pattern stream->offset = %"PRIu64" "
				     	"walk->stride = %"PRIu64" walk->direction = %d stream->poffset = %"PRIu64" ",
                                         stream->offset, walk->stride, walk->direction, stream->poffset);
			stream->len = walk->len < ra_size ? walk->len :
			    ra_size;
			walk->direction = GFFETCH_BACKWARD;
			fetched = 1;
			walk->stride = walk->stride > walk->len ?
			    walk->stride : walk->len;
			gettimeofday (&walk->last, NULL);
			pthread_mutex_unlock(&walk->lock);
			break;
		}
	}

out:
	pthread_rwlock_unlock(&ioc_inode->stream_lock);
	return fetched;
}


/* detect the stream pattern */
int
ioc_fetch (ioc_inode_t *ioc_inode, ioc_stream_t *st)
{
        ioc_table_t *table = NULL;
	ioc_stream_t *newst = NULL;
        size_t        ra_start = 0;
	int fetched = 0;
	int inserted = 0;

        table = ioc_inode->table;

        if (table  && table->fetch_status) {
                ra_start = roof (st->offset + st->len, table->page_size);
                st->len = table->page_size * table->ra_pagecnt;
                st->poffset = ra_start;

                return 1;
        }

        /* check wether the request belong to exist streaming */
        fetched = ioc_fetch_find(ioc_inode, st);
        if (fetched){
		goto out;
	} else {
               
		/* check wether the request belong to stride streaming */
		fetched = ioc_fetch_colinear(ioc_inode, st);
	}

	if (!fetched) {
		/*
		 * no existing streaming and streams count more than max streams half,
		 * we check all streams modified time,  reclaim stream and fetching st
		 * poffset when stream time out
		 */
		if(ioc_inode->stream_cnt > (table->max_streams /2)){
			newst = ioc_fetch_stream_reclaim(ioc_inode);
                }
		if (!newst) {
			if (ioc_inode->stream_cnt >= table->max_streams)
				goto out;
			newst = GF_CALLOC (1, sizeof (struct ioc_stream),
					gf_ioc_mt_ioc_stream_t);
		}
                fetched = 1;
		newst->offset = st->offset;
		newst->len = st->len;
		newst->stride = st->len;
		newst->poffset = st->len + st->offset;
		newst->direction = GFFETCH_FORWARD;
		gettimeofday (&newst->last, NULL);
		pthread_mutex_init(&newst->lock, NULL);

		inserted = ioc_fetch_stream_insert(ioc_inode, newst);
		if (!inserted) {
			pthread_mutex_destroy(&newst->lock);
			GF_FREE(newst);
			goto out;
		}
                st->poffset = st->offset + st->len;
		st->poffset = floor(st->poffset, table->page_size);
                st->len =  table->page_size * table->ra_pagecnt;

	}
out:
	return fetched;
}

void
ioc_fetch_free(ioc_inode_t *ioc_inode)
{
	ioc_stream_t *walk = NULL;
	ioc_stream_t *n = NULL;

	pthread_rwlock_wrlock(&ioc_inode->stream_lock);

	list_for_each_entry_safe (walk, n, &ioc_inode->streams, list) {
		list_del(&walk->list);
		pthread_mutex_destroy(&walk->lock);
		GF_FREE(walk);
	}

	pthread_rwlock_unlock(&ioc_inode->stream_lock);
}
