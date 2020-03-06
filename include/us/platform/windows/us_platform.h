#pragma once

// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

#include <ivc_ioctl_defs.h>
#include <libivc.h>
#include <libivc_types.h>
#ifndef KERNEL
#include <stdint.h>
#endif

typedef struct remote_event
{
    uint16_t remoteDomId;
    uint16_t port;
    MESSAGE_TYPE_T eventType;
} remote_event_t;

/*The following value is arbitrarily chosen from the space defined by Microsoft
 as being "for non-Microsoft use"*/
#define FILE_DEVICE_IVC 0xCF54

/* Microsoft reserves all IOCTLs below 0x800 for themselves, 0x800 - 0x1000 are
   available for the rest of us.  IOCTLS may not exceed 0x1000*/
#define STARTING_CTL_CODE 0x800

#define IVC_DRIVER_CONNECT CTL_CODE(FILE_DEVICE_IVC,STARTING_CTL_CODE + IVC_CONNECT_IOCTL, \
                                    METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IVC_DRIVER_DISCONNECT CTL_CODE(FILE_DEVICE_IVC, STARTING_CTL_CODE + IVC_DISCONNECT_IOCTL, \
                                       METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IVC_DRIVER_NOTIFY_REMOTE CTL_CODE(FILE_DEVICE_IVC, STARTING_CTL_CODE + IVC_NOTIFY_REMOTE_IOCTL, \
        METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IVC_DRIVER_SERVER_ACCEPT CTL_CODE(FILE_DEVICE_IVC, STARTING_CTL_CODE + IVC_SERVER_ACCEPT_IOCTL, \
        METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IVC_DRIVER_REG_SVR_LSNR CTL_CODE(FILE_DEVICE_IVC, STARTING_CTL_CODE + IVC_REG_SVR_LSNR_IOCTL, \
        METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IVC_DRIVER_UNREG_SVR_LSNR CTL_CODE(FILE_DEVICE_IVC, \
        STARTING_CTL_CODE + IVC_UNREG_SVR_LSNR_IOCTL, \
        METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_INVERTED_CALLBACK (STARTING_CTL_CODE + IVC_UNREG_SVR_LSNR_IOCTL + 1)
/**
* Adds an overlapped IOCTL to be used as an inverted call back from the driver back to user space.
*/
#define IVC_DRIVER_ADD_USER_NOTIFICATION CTL_CODE(FILE_DEVICE_IVC, \
        IOCTL_INVERTED_CALLBACK, \
        METHOD_BUFFERED, FILE_ANY_ACCESS)

// convenience function to extract the function code from above IOCTL definitions.
__inline uint8_t get_ioctl_function(ULONG ioctl)
{
    uint8_t rc;
    // The CTL_CODE macro produces an unsigned 32 bit number
    // Full details are at:
    // https://msdn.microsoft.com/en-us/library/windows/hardware/ff543023(v=vs.85).aspx
    // lower two bits are transfer type, so shift off 2 bits,
    // function code is next 12 bits, so mask off everything but those 12,
    // 111111111111 = 0xFFF
    // then subtract the starting control code we add onto our IOCTL numbers
    rc = (uint8_t)(((ioctl >> 2) & 0xFFF) - STARTING_CTL_CODE);
    return rc;
}
