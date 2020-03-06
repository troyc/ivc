// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/*
 * File:   libivc_types.h
 * Author: user
 *
 * Created on April 16, 2015, 1:27 PM
 */

#ifndef LIBIVC_TYPES_H
#define	LIBIVC_TYPES_H

#ifdef	__cplusplus
extern "C"
{
#endif

    // it is up to the platform libraries to define libivc
    struct libivc_client;
    struct libivc_server;

    typedef enum LISTENER_TYPE
    {
        LNONE, PORT_L, EVENT_L, MAX_L
    } LISTENER_TYPE_T;

    typedef enum SHARE_TYPE
    {
        TNONE, GRANT_REF_SHARE, POSIX_SHARE, MAX_T
    } SHARE_TYPE_T;

    typedef enum MESSAGE_TYPE
    {
        MNONE, CONNECT, DISCONNECT, ACK, EVENT, NOTIFY_ON_DEATH, DOMAIN_DEAD, MMAX
    } MESSAGE_TYPE_T;

    typedef enum STATUS_TYPE
    {
        SNONE, INIT, READY, DOWN, SMAX
    } STATUS_TYPE_T;

    // Callback style event notification
    typedef void (*libivc_client_event_fired)(void *, struct libivc_client *);
    typedef void (*libivc_client_disconnected)(void *, struct libivc_client *);
    typedef void (*libivc_client_connected)(void *, struct libivc_client *);

#ifdef _WIN32
    // these will need to be converted to NTSTATUS codes
    // for return through the driver to the userspace layer.
#include "wintypes.h"
#endif

#define SUCCESS 0
#define ACCESS_DENIED -EACCES
#define OUT_OF_MEM -ENOMEM
#define INVALID_PARAM -EINVAL
#define CONNECTION_REFUSED -ECONNREFUSED
#define ADDRESS_IN_USE -EADDRINUSE
#define ADDRESS_NOT_AVAIL -EADDRNOTAVAIL
#define ERROR_AGAIN -EAGAIN
#define NO_SPACE -ENOSPC
#define NOT_CONNECTED -ENOTCONN
#define INTERNAL_ERROR -ENOTRECOVERABLE
#define NO_DATA_AVAIL -ENODATA
#define IVC_UNAVAILABLE -EUNATCH
#define TIMED_OUT -ETIMEDOUT
#define NOT_IMPLEMENTED -ENOSYS

#ifdef	__cplusplus
}
#endif

#endif	/* LIBIVC_TYPES_H */

