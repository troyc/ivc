// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/*
 * File: wintypes.h
 *
 * Contains various typedefs for windows to understand
 * linux types.  For example, uint32_t.
 *
 */

#ifndef WINTYPES_H
#define WINTYPES_H

#define uint8_t   UINT8
#define uint16_t   UINT16
#define uint32_t  UINT32
#define uint64_t  UINT64
#define int8_t	  INT8
#define int16_t   INT16
#define int32_t   INT32
#define int64_t   INT64
#define ssize_t   LONG
#define domid_t   uint16_t
#define atomic_t  LONG

#ifndef ENXIO
#define ENXIO  6
#define EACCES 13
#define ENOMEM 12
#define EINVAL 22
#define ECONNREFUSED 111
#define EADDRINUSE 98
#define EADDRNOTAVAIL 99
#define EAGAIN 11
#define ENOSPC 28
#define ENOTCONN 107
#define ENOTRECOVERABLE  131
#define ENODATA 61
#define ETIMEDOUT 110
#define ENOSYS 38
#endif

#ifndef EUNATCH
#define EUNATCH 49
#endif

//FIXME: these warnings shouldn't occur in the first place
#pragma warning( disable : 4127 4267 )

#endif
