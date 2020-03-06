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

#define INITGUID
// tag used in all memory allocations when debugging the string is reversed
// so you'll see Pivc (Pointer to ivc) memory tags
#define MEM_TAG 'cviP'

#include <ntifs.h>
#include <wdf.h>


#include <xenplatform_link.h>
#include <ks_platform.h>
#include <ks_ivc_core.h>
#include <us_platform.h>

typedef struct evtchn_data
{
    uint32_t fakeEventNo;
    EVTCHN_PORT realEventPort;
} evtchn_data_t;

typedef struct worker_item_context
{
    event_channel_info_t *cInfo;
} worker_item_context_t, *pworker_item_context_t;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(worker_item_context_t, workItemGetContext);

//
// Device protection string
// This is the ACL used for the device object created by the driver.
//
DECLARE_CONST_UNICODE_STRING(IVC_DEVICE_PROTECTION, L"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)");
extern const UNICODE_STRING  IVC_DEVICE_PROTECTION;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(file_context_t, getFileContext);

// Global variable which will store the
// function pointers to XEN API calls.
struct XenPlatformApiCalls *xenApi = NULL;


//
// WDFDRIVER Events
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD ivcEvtDriverUnload;
EVT_WDF_DRIVER_DEVICE_ADD ivcEvtDeviceAdd;

// user space event callbacks.
EVT_WDF_DEVICE_FILE_CREATE ivcEvtDeviceFileCreate; // callback when a user space process opens the driver.
EVT_WDF_FILE_CLEANUP ivcEvtDeviceFileCleanup;	// callback when a user space process closes (or crashes) out of the driver.
// WDFIOQUEUE events (IOCTLs)
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL ivcEvtIoDeviceControl;


EVT_WDF_WORKITEM local_ivc_watch_wh;