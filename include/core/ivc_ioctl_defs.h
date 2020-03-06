// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/*
 * File:   ivc_ioctl_defs.h
 *
 * Created on April 3, 2015, 3:57 PM
 */

#ifndef IVC_IOCTL_DEFS_H
#define	IVC_IOCTL_DEFS_H

#ifdef	__cplusplus
extern "C"
{
#endif

    // client connect
#define IVC_CONNECT_IOCTL 10
    // client disconnect
#define IVC_DISCONNECT_IOCTL 20
    // fire remote event.
#define IVC_NOTIFY_REMOTE_IOCTL 30
    // accept client connection.
#define IVC_SERVER_ACCEPT_IOCTL 40
    // register server listener on port.
#define IVC_REG_SVR_LSNR_IOCTL 50
    // unregister server listener on port.
#define IVC_UNREG_SVR_LSNR_IOCTL 60
    // Workaround for pv user space grant mapping
#define IVC_PV_MMAP_STAGE2_IOCTL       70
    // Special MUNMAP for IVC mappings; this is the recommended way
    // of clearing an IVC mapping in the platform sections. (This is eqvuialent
    // to munmap on platforms that have MMU notifiers, but is the only proper
    // way of unmapping on systems without.)
#define IVC_MUNMAP_IOCTL  71
    // client recconnect
#define IVC_RECONNECT_IOCTL 80

#ifdef	__cplusplus
}
#endif

#endif	/* IVC_IOCTL_DEFS_H */

