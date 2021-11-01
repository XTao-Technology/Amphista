/*
  Copyright (c) 2017 XTAO Technology, Inc. <http://www.xtaotech.com>

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/


#ifndef __READDIR_PRELOAD_MEM_TYPES_H__
#define __READDIR_PRELOAD_MEM_TYPES_H__

#include "mem-types.h"

enum gf_rdp_mem_types_ {
        gf_rdp_mt_rdp_local   = gf_common_mt_end + 1,
		gf_rdp_mt_rdp_inode,
		gf_rdp_mt_rdp_stream,
		gf_rdp_mt_rdp_priv,
        gf_rdp_mt_end
};

#endif
