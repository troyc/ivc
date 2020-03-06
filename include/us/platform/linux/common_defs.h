// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/*
 * File:   common_defs.h
 * Author: user
 *
 * Created on April 2, 2015, 11:12 AM
 */

#ifndef COMMON_DEFS_H
#define	COMMON_DEFS_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <ivc_ioctl_defs.h> // for ioctl number definitions common to platforms.

#ifndef KERNEL
#include <errno.h>
#include <stdint.h>
#else
#include <linux/types.h>
#endif

#ifdef KERNEL
#ifndef malloc
#define malloc(x) kzalloc((x),GFP_KERNEL)
#define free(x) kfree((x))
#endif
#endif

#define IVC_DRIVER_IOC_MAGIC 'K'

#define IVC_CONNECT _IOWR(IVC_DRIVER_IOC_MAGIC,IVC_CONNECT_IOCTL,struct libivc_client)
#define IVC_RECONNECT _IOWR(IVC_DRIVER_IOC_MAGIC,IVC_RECONNECT_IOCTL,struct libivc_client)
#define IVC_DISCONNECT _IOWR(IVC_DRIVER_IOC_MAGIC, IVC_DISCONNECT_IOCTL, struct libivc_client)
#define IVC_NOTIFY_REMOTE _IOWR(IVC_DRIVER_IOC_MAGIC, IVC_NOTIFY_REMOTE_IOCTL, struct libivc_client)
#define IVC_SERVER_ACCEPT _IOWR(IVC_DRIVER_IOC_MAGIC, IVC_SERVER_ACCEPT_IOCTL, struct libivc_client)

#define IVC_REG_SVR_LSTNR _IOWR(IVC_DRIVER_IOC_MAGIC, IVC_REG_SVR_LSNR_IOCTL, struct libivc_server)
#define IVC_UNREG_SVR_LSTNR _IOWR(IVC_DRIVER_IOC_MAGIC, IVC_UNREG_SVR_LSNR_IOCTL, struct libivc_server)
#define IVC_PV_MMAP_STAGE2 _IOWR(IVC_DRIVER_IOC_MAGIC, IVC_PV_MMAP_STAGE2_IOCTL, struct libivc_client)
#define IVC_MUNMAP _IOWR(IVC_DRIVER_IOC_MAGIC, IVC_MUNMAP_IOCTL, struct libivc_client)
#ifdef	__cplusplus
}
#endif

#endif	/* COMMON_DEFS_H */

