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

#ifndef __DIRSTAT_CACHE_H
#define __DIRSTAT_CACHE_H

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
#include <sys/time.h>

struct dsc_priv;
struct dsc_inode;
struct dsc_local;

/*
 * frame local for rename
 */
struct dsc_local {
    inode_t *inode;
    inode_t *parg_inode;
    inode_t *new_inode; /* for rename */
    inode_t *new_parg_inode; /* for rename */
};

struct dsc_inode {
        struct iatt stat;
        struct timeval    tv;          /*
                                        * time-stamp at last re-validate
										*/
};

/*
 * dirstat-cache xlator private
 */
struct dsc_priv {
        gf_boolean_t     active;
        gf_boolean_t     special_client_active;
        int32_t          cache_timeout;
};

typedef struct dsc_priv dsc_priv_t;
typedef struct dsc_inode dsc_inode_t;
typedef struct dsc_local dsc_local_t;

#define DSC_STACK_UNWIND(fop, frame, params ...) do {           \
                if (frame) {                                    \
                        frame->local = NULL;                    \
                }                                               \
                STACK_UNWIND_STRICT (fop, frame, params);       \
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

#endif /* __DIRSTAT_CACHE_H */
