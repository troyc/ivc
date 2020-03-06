// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/*++

Module Name:

driver.h

Abstract:

This file contains the driver definitions.

Environment:

Kernel-mode Driver Framework

--*/
#ifndef __PLATFORM_H__
#define __PLATFORM_H__

#define INITGUID
// tag used in all memory allocations when debugging the string is reversed
// so you'll see Pivc (Pointer to ivc) memory tags
#define MEM_TAG 'cviP'

#include <ntifs.h>
#include <wdf.h>
#include <ks_platform.h>
#include <ks_ivc_core.h>
#include <us_platform.h>
#include <ivc_ioctl_defs.h>

#define UNUSED UNREFERENCED_PARAMETER

typedef uint32_t grant_handle_t;

typedef struct shareable_mem_alloc
{
    list_head_t listHead; // used in list of shared pages.
    uint32_t numPages; // the number of pages being shared.
    PMDL mdls; // memory descriptor list.
    mapped_grant_ref_t *grantHandles; // matching grant refs to each page.
    void *kAddress; //the virtually contiguous address to the pages.
    uint16_t remoteDomId;
    PXENBUS_GNTTAB_CACHE grantCache;
} shareable_mem_alloc_t;

typedef struct mapped_mem_descriptor
{
    list_head_t listHead; // used in list of mapped memory
    uint32_t numGrants; // the number of grants the remote domain shared to us.
    PMDL mdls; // the xen ballooned pages.
    struct grant_map_detail *details;
    void *kAddress; // the virtually contiguous kernel address to the pages.
    uint16_t remoteDomId;
} mapped_mem_descriptor_t;


#define rmb KeMemoryBarrier
#define wmb KeMemoryBarrier

#define ABSOLUTE(wait) (wait)

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos) \
    (((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
    (((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
    (((signed __int64)(milli)) * MICROSECONDS(1000L))

_inline void msleep(uint32_t msecs)
{
    LARGE_INTEGER waitTime;
    waitTime.QuadPart = MILLISECONDS(msecs);
    KeDelayExecutionThread(KernelMode, TRUE, &waitTime);
}

_inline int xen_initial_domain(void)
{
    return 0;
}

typedef struct evtchn_data
{
    uint32_t fakeEventNo;
} evtchn_data_t;

typedef struct worker_item_context
{
    event_channel_info_t *cInfo;
} worker_item_context_t, *pworker_item_context_t;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(worker_item_context_t, workItemGetContext);

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(file_context_t, getFileContext);

NTSTATUS ks_platform_load();
NTSTATUS ks_platform_unload();

//
// WDFDRIVER Events
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_OBJECT_CONTEXT_CLEANUP ks_platform_device_unload;
EVT_WDF_OBJECT_CONTEXT_DESTROY ks_platform_device_destroy;
EVT_WDF_DRIVER_DEVICE_ADD ks_platform_device_add;

// user space event callbacks.
EVT_WDF_DEVICE_FILE_CREATE ivcEvtDeviceFileCreate; // callback when a user space process opens the driver.
EVT_WDF_FILE_CLEANUP ivcEvtDeviceFileCleanup;	// callback when a user space process closes (or crashes) out of the driver.
// WDFIOQUEUE events (IOCTLs)
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL ks_platform_ioctl;

EVT_WDF_WORKITEM local_ivc_watch_wh;

#endif