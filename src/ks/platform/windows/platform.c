// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

#include <platform.h>
#include <ks_ivc_core.h>
#include <libivc_debug.h>
#include <list.h>
#include <debug_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <store_interface.h>

// Device protection string
// This is the ACL used for the device object created by the driver.
//
DECLARE_CONST_UNICODE_STRING(IVC_DEVICE_PROTECTION, L"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)");
extern const UNICODE_STRING  IVC_DEVICE_PROTECTION;

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#endif

/* TODO: Drop all statics in this module (together) */
static XENBUS_DEBUG_INTERFACE DebugInterface;
static XENBUS_EVTCHN_INTERFACE EvtchnInterface;
static XENBUS_STORE_INTERFACE StoreInterface;
static XENBUS_GNTTAB_INTERFACE GnttabInterface;
static PXENBUS_EVTCHN_CHANNEL Channel;
static PXENBUS_GNTTAB_ENTRY SringGrantRef;
static BOOLEAN XenInterfacesAcquired = FALSE;

static LIST_HEAD(sharedMemoryList);
static LIST_HEAD(mappedMemoryList);
static LIST_HEAD(eventCallbacks);

static mutex_t eventCallbackMutex;
static struct xenbus_watch_handler *localWatch = NULL;
static BACKEND_STATUS_T lastStat = DISCONNECTED;
static WDFDEVICE device = 0;
static list_head_t eventChannels;
static mutex_t eventChannelMutex;
static ULONG32 fakeIrq = 0; // windows xen api's don't give us a real irq number, so fake it.

/**
* Given the ivc error code, converts it to an NTSTATUS equivalent for returning back to the user
* space, keeping the platform happy on ioctl return codes that make sense to it.
*/
static NTSTATUS 
convertIvcCode(int code)
{
	NTSTATUS rc = STATUS_UNSUCCESSFUL;

	switch(code)
	{
		case SUCCESS:
			rc = STATUS_SUCCESS;
			break;
		case OUT_OF_MEM:
			rc = STATUS_NO_MEMORY;
			break;
		case INVALID_PARAM:
			rc = STATUS_INVALID_PARAMETER;
			break;
		case ACCESS_DENIED:
			rc = STATUS_ACCESS_DENIED;
			break;
		case ERROR_AGAIN:
			rc = STATUS_RETRY;
			break;
		case ADDRESS_IN_USE:
			rc = STATUS_ADDRESS_ALREADY_EXISTS;
			break;
		case ADDRESS_NOT_AVAIL:
			rc = STATUS_INVALID_ADDRESS;
			break;
		case NO_SPACE:
			rc = STATUS_ALLOTTED_SPACE_EXCEEDED;
			break;
		case INTERNAL_ERROR:
			rc = STATUS_INTERNAL_ERROR;
			break;
	}

	return rc;
}
/**
* DriverEntry
* Called by Windows when the driver is first loaded.  Creates the WDFDRIVER
* @param: DriverObject - Address of the DRIVER_OBJEcT created by Windows for this driver.
* @param: RegistryPath - UNICODE_STRING which represents this drivers key in the Registry.
* @return: STATUS_SUCCESS, or appropriate error indicating why the driver could not load.
*/
__pragma(warning(push))
__pragma(warning(disable:4127))
NTSTATUS
DriverEntry(
_In_ PDRIVER_OBJECT  DriverObject,
_In_ PUNICODE_STRING RegistryPath
)
{
#if 0
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    return STATUS_ACCESS_DENIED;
#else
    WDF_DRIVER_CONFIG config;
	NTSTATUS status;
	WDF_OBJECT_ATTRIBUTES attribs;

    libivc_trace("====>\n");

	libivc_debug_init();
	libivc_info("In Driver Entry of platform.c\n");

	libivc_info("Init list head for events.\n");
	INIT_LIST_HEAD(&eventCallbacks);
	libivc_info("Initializing mutex\n");
	mutex_init(&eventCallbackMutex);
	libivc_info("Init event channels.\n");
	INIT_LIST_HEAD(&eventChannels);
	libivc_info("Init event channel mutex\n");
	mutex_init(&eventChannelMutex);

	libivc_info("Config.\n");
	// provide pointer to our EvtDeviceAdd event processing callback function.
	WDF_DRIVER_CONFIG_INIT(&config,	ks_platform_device_add);
	// setup the callback to handle cleanup when the driver is unloaded.
	WDF_OBJECT_ATTRIBUTES_INIT(&attribs);
	attribs.EvtCleanupCallback = ks_platform_device_unload;
	
	// create our WDFDriver instance.
	libivc_info("Calling driver create.\n");

	status = WdfDriverCreate(DriverObject,
		RegistryPath,
		&attribs,
		&config,
		WDF_NO_HANDLE
		);

	if (!NT_SUCCESS(status))
	{
		libivc_info("[ivc]: WdfDriverCreate failed 0x%0x\n", status);
	}

    libivc_trace("<====\n");
	return status;
#endif
}
__pragma(warning(pop))

static int
acquire_xen_interfaces(WDFDEVICE Device)
{
    NTSTATUS status;

    libivc_trace("====>\n");

    if (!Device)
    {
        libivc_info("Ivc device not yet created.");
        goto fail;
    }

    // DEBUG_INTERFACE

    status = WdfFdoQueryForInterface(Device,
        &GUID_XENBUS_DEBUG_INTERFACE,
        (PINTERFACE)&DebugInterface,
        sizeof(DebugInterface),
        XENBUS_DEBUG_INTERFACE_VERSION_MAX,
        NULL);

    if (!NT_SUCCESS(status))
    {
        libivc_info("Failed to query xenbus debug interface: 0x%x\n", status);
        goto fail;
    }

    status = XENBUS_DEBUG(Acquire, &DebugInterface);

    if (!NT_SUCCESS(status))
    {
        libivc_info("Failed to query xenbus debug interface: 0x%x\n", status);
        goto fail;
    }

    libivc_info("successfully acquired xenbus debug interface\n");

    // EVTCHN_INTERFACE

    status = WdfFdoQueryForInterface(Device,
        &GUID_XENBUS_EVTCHN_INTERFACE,
        (PINTERFACE)&EvtchnInterface,
        sizeof(EvtchnInterface),
        XENBUS_EVTCHN_INTERFACE_VERSION_MAX,
        NULL);

    if (!NT_SUCCESS(status))
    {
        libivc_info("Failed to query xenbus evtchn interface: 0x%x\n", status);
        goto fail_evtchn;
    }

    status = XENBUS_EVTCHN(Acquire, &EvtchnInterface);

    if (!NT_SUCCESS(status))
    {
        libivc_info("Failed to query xenbus evtchn interface: 0x%x\n", status);
        goto fail_evtchn;
    }

    libivc_info("successfully acquired xenbus evtchn interface\n");

    // GNTTAB_INTERFACE

    status = WdfFdoQueryForInterface(Device,
        &GUID_XENBUS_GNTTAB_INTERFACE,
        &GnttabInterface.Interface,
        sizeof(GnttabInterface),
        XENBUS_GNTTAB_INTERFACE_VERSION_MAX,
        NULL);

    if (!NT_SUCCESS(status))
    {
        libivc_info("Failed to query xenbus gnttab interface: 0x%x\n", status);
        goto fail_gnttab;
    }

    status = XENBUS_GNTTAB(Acquire, &GnttabInterface);

    if (!NT_SUCCESS(status))
    {
        libivc_info("Failed to acquire xenbus gnttab interface: 0x%x\n", status);
        goto fail_gnttab;
    }

    libivc_info("successfully acquired xenbus gnttab interface\n");

    // STORE_INTERFACE

    status = WdfFdoQueryForInterface(Device,
        &GUID_XENBUS_STORE_INTERFACE,
        &StoreInterface.Interface,
        sizeof(StoreInterface),
        XENBUS_STORE_INTERFACE_VERSION_MAX,
        NULL);

    if (!NT_SUCCESS(status))
    {
        libivc_info("Failed to query xenbus store interface: 0x%x\n", status);
        goto fail_store;
    }

    status = XENBUS_STORE(Acquire, &StoreInterface);

    if (!NT_SUCCESS(status))
    {
        libivc_info("Failed to acquire xenbus store interface: 0x%x\n", status);
        goto fail_store;
    }

    libivc_info("successfully acquired xenbus store interface\n");

    XenInterfacesAcquired = TRUE;

    libivc_trace("<====\n");
    return SUCCESS;

fail_store:
    XENBUS_GNTTAB(Release, &GnttabInterface);
fail_gnttab:
    XENBUS_EVTCHN(Release, &EvtchnInterface);
fail_evtchn:
    XENBUS_DEBUG(Release, &DebugInterface);
fail:
    return INTERNAL_ERROR;
}

static VOID
release_xen_interfaces(VOID)
{
    libivc_trace("====>\n");

    if (!XenInterfacesAcquired)
        return;

    XenInterfacesAcquired = FALSE;

    // DEBUG_INTERFACE

    XENBUS_DEBUG(Release, &DebugInterface);

    libivc_info("successfully released xenbus debug interface\n");

    // EVTCHN_INTERFACE

    XENBUS_EVTCHN(Release, &EvtchnInterface);

    libivc_info("successfully released xenbus evtchn interface\n");

    // GNTTAB_INTERFACE

    XENBUS_GNTTAB(Release, &GnttabInterface);

    libivc_info("successfully released xenbus gnttab interface\n");

    // STORE_INTERFACE

    XENBUS_STORE(Release, &StoreInterface);

    libivc_info("successfully released xenbus store interface\n");
}

NTSTATUS
ks_platform_load()
{
	int rc;
	libivc_info("Acquiring xen interfaces...\n");
	rc = acquire_xen_interfaces(device);

	if (rc != SUCCESS)
	{
		libivc_info("Acquiring xen interfaces failed\n");
		return convertIvcCode(rc);
	}

	// initialize the IVC core common driver.
	libivc_info("Initializing ivc core.\n");
	rc = ks_ivc_core_init();

	// if the core failed to initialize, it doesn't make sense to let the driver
	// continue loading.  Undo the watches and driver linking.
	if (rc != SUCCESS)
	{
		libivc_info("core init failed. rc = %d\n", rc);
		release_xen_interfaces();
		return convertIvcCode(rc);
	}
	return STATUS_SUCCESS;
}

NTSTATUS
ks_platform_unload()
{
	ks_ivc_core_uninit();
	release_xen_interfaces();
	return STATUS_SUCCESS;
}

/**
* Called by the KMDF framework when a device of the type we support is found in the system.
* @param: DriverObject Our WDFDRIVER object
* @param: DeviceInit - The device initialization structure we'll be using to create our WDFDEVICE
* @return: STATUS_SUCCESS or appropriate error.
* IRQL: called at PASSIVE_LEVEL
*/
NTSTATUS
ks_platform_device_add(
_In_    WDFDRIVER       Driver,
_Inout_ PWDFDEVICE_INIT DeviceInit
)
{
	NTSTATUS status;
	WDF_IO_QUEUE_CONFIG queueConfig;
	WDF_FILEOBJECT_CONFIG fileConfig;
	WDF_OBJECT_ATTRIBUTES fileConfigAttributes;
	int rc;
	// create internal native and user-accessible device names
	DECLARE_CONST_UNICODE_STRING(nativeDeviceName, L"\\Device\\ivc");
	DECLARE_CONST_UNICODE_STRING(userDeviceName, L"\\Global??\\ivc");
	UNREFERENCED_PARAMETER(Driver);

    libivc_trace("====>\n");

	// for proper tracking and cleanup of user space calls into the driver, we need to enable 
	// the callbacks in the KMDF framework, as well as let it know we'll be storing some data
	// in the context of each process.
	WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, ivcEvtDeviceFileCreate, NULL, ivcEvtDeviceFileCleanup);
	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&fileConfigAttributes, file_context_t);
	// enable the callbacks in the device itself.
	WdfDeviceInitSetFileObjectConfig(DeviceInit, &fileConfig, &fileConfigAttributes);

	// no need for ANY Pnp/Power event processing callbacks, we don't have physical hardware,
	// so don't need EvtPrepareHardware or EvtReleaseHardware.  No Power state to worry about, so 
	// don't need EvtD0Entry or EvtD0Exit either.

	// setup the device object name.
	status = WdfDeviceInitAssignName(DeviceInit, &nativeDeviceName);
	if (!NT_SUCCESS(status))
	{
		libivc_info("WdfDeviceInitAssignName failed 0x%0x\n", status);
		return(status);
	}

	// set up the device so ANYone can read or write to the device, the os or the administrator
	// can change the protection after they take ownership of it.
	status = WdfDeviceInitAssignSDDLString(DeviceInit, &IVC_DEVICE_PROTECTION);

	if (!NT_SUCCESS(status))
	{
		libivc_info("WdfDeviceInitAssignSDDLString failed 0x%0x\n", status);
		return(status);
	}
	// create the device now.
	status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);

	if (!NT_SUCCESS(status))
	{
		libivc_info("WdfDeviceCreate failed 0x%0x\n", status);
		return status;
	}

	// create a symbolic link for the control object so that user-mode apps can open
	// the device by name.
	libivc_info("Setting symbolic link\n");
	status = WdfDeviceCreateSymbolicLink(device, &userDeviceName);
	if (!NT_SUCCESS(status))
	{
		libivc_info("WdfDeviceCreateSymbolicLink failed 0x%0x\n", status);
		return(status);
	}

	// configure our queue to handle incoming IOCTL requests.
	// We are only using the default Queue to receive requests from the framework
	// and set it for parallel processing so that the driver can have multiple requests
	// outstanding from this queue simultaneously.
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
	// declare our I/O event processing callback.  This driver only handles IOCTLS
	queueConfig.EvtIoDeviceControl = ks_platform_ioctl;
	// because this is a queue for a software only device, let the framework know it
	// doesn't need to be power managed.
	queueConfig.PowerManaged = WdfFalse;
	// create the queue
	libivc_info("Setting up default QUEUE\n");
	status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
	if (!NT_SUCCESS(status))
	{
		libivc_info("WdfIoQueueCreate for default queue failed 0x%0x\n", status);
        return(status);
	}

    libivc_trace("<====\n");
	return status;
}

/**
* Framework callback that occurs when driver is unloaded.
*/
_Function_class_(EVT_WDF_OBJECT_CONTEXT_CLEANUP)
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ks_platform_device_unload(_In_ WDFOBJECT Driver)
{
	UNREFERENCED_PARAMETER(Driver);

    libivc_trace("====>\n");

    ks_ivc_core_uninit();

    libivc_trace("<====\n");
}

/**
* KMDF callback that occurs when a user space process opens the driver.
*/
VOID
ivcEvtDeviceFileCreate(_In_ WDFDEVICE l_device, _In_ WDFREQUEST request, 
					   _In_ WDFFILEOBJECT fileObject)
{
	file_context_t *fileContext = NULL;
	WDF_IO_QUEUE_CONFIG queueConfig;
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(l_device);

    libivc_trace("====>\n");

	// get the file_context_t that is assicated with the new fileobject.
	fileContext = getFileContext(fileObject);
	// tie the process to the context.
	fileContext->file = fileObject;
	// configure notification queue for delayed events from the driver to the user space.
	WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
	// turn off power management for the queue.
	queueConfig.PowerManaged = WdfFalse;
	// complete the request with appropriate status.  If not called userspace will just hang.
	WdfRequestComplete(request, status);

    libivc_trace("<====\n");
}


/**
* KMDF framework callback that happens when a user space process that opened the driver
* closes the file or crashes.  This call occurs in the context of the userspace even if it crashes
* whereas the close callback does not.  this makes it safer from memory unmapping operations.
*/
VOID
ivcEvtDeviceFileCleanup(_In_ WDFFILEOBJECT fileObject)
{
	file_context_t * context = NULL;

    libivc_trace("====>\n");

	// get the file context that was associated with the process when it opened the driver.
	context = getFileContext(fileObject);
	// let the ivc core know that the user space has exited and
	// it can release any resouces associated with it.
	ks_ivc_core_file_closed(context);

    libivc_trace("<====\n");
}

/**
* KMDF ioctl callback.
*/
VOID
ks_platform_ioctl(_In_ WDFQUEUE queue, _In_ WDFREQUEST request, _In_ size_t outputBufferLength,
					  _In_ size_t inputBufferLength, _In_ ULONG ioControlCode)
{
	uint8_t ioctl;
	struct libivc_client_ioctl_info usClient;
	struct libivc_server_ioctl_info usServer;
	PVOID inBuff = NULL;
	PVOID outBuff = NULL;
	WDFFILEOBJECT file;
	file_context_t * fileContext = NULL;
	NTSTATUS status;
	size_t buffSize;
	int rc = SUCCESS;
	UNREFERENCED_PARAMETER(queue);

    libivc_trace("====>\n");

	// convert the ioctl to the original function code.  Doesn't really need to be done this way,
	// but it's convenient to just pass it on to the IVC core vs tons of switch case statements.
	ioctl = get_ioctl_function(ioControlCode);
	if (ioctl > IVC_UNREG_SVR_LSNR_IOCTL + 1)
	{
		WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
		return;
	}
	if (!(ioctl <= IVC_UNREG_SVR_LSNR_IOCTL))
	{
		WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
		return;
	}

	libivc_info("[ivc]: ioctl = %d\n", ioctl);
	// get the file_context_t associated with the user space process that opened us.
	file = WdfRequestGetFileObject(request);
	fileContext = getFileContext(file);

	
	switch (ioctl)
	{
	case IVC_CONNECT_IOCTL:
	case IVC_DISCONNECT_IOCTL:
	case IVC_NOTIFY_REMOTE_IOCTL:
	case IVC_SERVER_ACCEPT_IOCTL:
	{
		if (outputBufferLength != sizeof(struct libivc_client_ioctl_info) || inputBufferLength != sizeof(struct libivc_client_ioctl_info))
		{
			WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
			return;
		}
		// read in the ioctls payload.
		status = WdfRequestRetrieveInputBuffer(request, sizeof(struct libivc_client_ioctl_info), &inBuff, &buffSize);
		if (!NT_SUCCESS(status))
		{
			WdfRequestComplete(request, STATUS_ACCESS_DENIED);
			return;
		}

		if (memcpy_s(&usClient, sizeof(struct libivc_client_ioctl_info), inBuff, sizeof(struct libivc_client_ioctl_info)))
		{
			libivc_error("Failed to copy memory from user space.\n");
			WdfRequestComplete(request, STATUS_ACCESS_DENIED);
			return;
		}
		rc = ks_ivc_core_client_ioctl(ioctl, &usClient, fileContext);
		if (rc == SUCCESS)
		{
			status = WdfRequestRetrieveOutputBuffer(request, sizeof(struct libivc_client_ioctl_info), &outBuff, &buffSize);
			if (!NT_SUCCESS(status))
			{
				libivc_error("Failed to get buffer to write back to user space.\n");
				WdfRequestComplete(request, STATUS_ACCESS_DENIED);
				return;
			}
			if (memcpy_s(outBuff, sizeof(struct libivc_client_ioctl_info), &usClient, sizeof(struct libivc_client_ioctl_info)))
			{
				libivc_error("Failed to copy data back to user space.\n");
				WdfRequestComplete(request, STATUS_ACCESS_DENIED);
				return;
			}
			WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, sizeof(struct libivc_client_ioctl_info));
			return;
		}
		else
		{
			WdfRequestComplete(request, convertIvcCode(rc));
			return;
		}
	}
	break;
	case IVC_REG_SVR_LSNR_IOCTL:
	case IVC_UNREG_SVR_LSNR_IOCTL:
	{
		if (outputBufferLength != sizeof(struct libivc_server_ioctl_info) || inputBufferLength != sizeof(struct libivc_server_ioctl_info))
		{
			WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
			return;
		}
		// read in the ioctls payload.
		status = WdfRequestRetrieveInputBuffer(request, sizeof(struct libivc_server_ioctl_info), &inBuff, &buffSize);
		if (!NT_SUCCESS(status))
		{
			libivc_error("Weird error we don't think is happening.\n");
			WdfRequestComplete(request, STATUS_ACCESS_DENIED);
			return;
		}

		if (memcpy_s(&usServer, sizeof(struct libivc_server_ioctl_info), inBuff, sizeof(struct libivc_server_ioctl_info)))
		{
			libivc_error("Failed to copy memory from user space.\n");
			WdfRequestComplete(request, STATUS_ACCESS_DENIED);
			return;
		}
		rc = ks_ivc_core_server_ioctl(ioctl, &usServer, fileContext);
		if (rc == SUCCESS)
		{
			status = WdfRequestRetrieveOutputBuffer(request, sizeof(struct libivc_server_ioctl_info), &outBuff, &buffSize);
			if (!NT_SUCCESS(status))
			{
				libivc_error("Failed to get buffer to write back to user space.\n");
				WdfRequestComplete(request, STATUS_ACCESS_DENIED);
				return;
			}
			if (memcpy_s(outBuff, sizeof(struct libivc_server_ioctl_info), &usServer, sizeof(struct libivc_server_ioctl_info)))
			{
				libivc_error("Failed to copy data back to user space.\n");
				WdfRequestComplete(request, STATUS_ACCESS_DENIED);
				return;
			}
			WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, sizeof(struct libivc_server_ioctl_info));
			return;
		}
		else
		{
			libivc_error("Other strange error blah\n");
			WdfRequestComplete(request, convertIvcCode(rc));
			return;
		}
	}
	break;
	}

    libivc_trace("<====\n");
} 

//*********************************************************************
// IVC platform specific implementation for core functions
//*********************************************************************

/**
* Allocate memory and return a pointer to it.
* @param memSize size of memory to allocate
* @return a pointer to the allocated memory, or NULL if we are all out.
*/
void*
ks_platform_alloc(size_t memSize)
{
	void * data = NULL;

    libivc_trace("====>\n");

	libivc_assert(memSize > 0, NULL);

	data = ExAllocatePoolWithTag(NonPagedPool, memSize, MEM_TAG);
	// if we had a successful memory allocation, zero out the memory to make sure
	// sensitive data doesn't make its way back to userspace or across domains.
	if (data)
	{
		RtlZeroMemory(data, memSize);
	}

    libivc_trace("<====\n");
	return data;
}

/**
* Free previously allocated memory.
* @param mem the memory previously allocated.
*/
void
ks_platform_free(void *mem)
{
    libivc_trace("====>\n");
	libivc_checkp(mem);
	ExFreePoolWithTag(mem, MEM_TAG);
    libivc_trace("<====\n");
}

static int
ks_platform_permit_grant_ref(PFN_NUMBER pfn, USHORT domain, PXENBUS_GNTTAB_CACHE cache, mapped_grant_ref_t *gref)
{
    NTSTATUS status;

    libivc_trace("====>\n");

    if (!XenInterfacesAcquired)
    {
        libivc_info("failed to permit grant ref without xen interfaces\n");
        return INVALID_PARAM;
    }

    status = XENBUS_GNTTAB(PermitForeignAccess,
        &GnttabInterface,
        cache,
        TRUE,
        domain,
        pfn,
        FALSE,
        &gref->entry);

    if (!NT_SUCCESS(status))
    {
        libivc_info("failed to permit foreign access for pfn=0x%x\n", (int)pfn);
        gref->valid = FALSE;
        return INTERNAL_ERROR;
    }

    libivc_info("successfully granted memory pfn=0x%x\n", (int)pfn);

    gref->ref = XENBUS_GNTTAB(GetReference, &GnttabInterface, gref->entry);
    gref->cache = cache;
    gref->valid = TRUE;

    libivc_trace("<====\n");
    return SUCCESS;
}

static void
ks_platform_revoke_grant_ref(mapped_grant_ref_t *gref)
{
    libivc_trace("====>\n");

    if (!XenInterfacesAcquired)
    {
        libivc_info("failed to revoke grant ref without xen interfaces\n");
        return;
    }

    if (!gref->valid)
    {
        libivc_info("request to revoke invalid grant ref\n");
        return;
    }

    XENBUS_GNTTAB(RevokeForeignAccess,
        &GnttabInterface,
        gref->cache,
        TRUE,
        gref->entry);

    gref->valid = FALSE;
    gref->cache = NULL;
    gref->entry = NULL;
    gref->ref = 0;

    libivc_trace("<====\n");
}

static KSPIN_LOCK GnttabLock;

static VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
gnttab_spinlock_acquire(
    IN  PVOID       Argument
)
{
    UNREFERENCED_PARAMETER(Argument);

    libivc_trace("====>\n");

    KeAcquireSpinLockAtDpcLevel(&GnttabLock);

    libivc_trace("<====\n");
}

static VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
gnttab_spinlock_release(
    IN  PVOID       Argument
)
{
    UNREFERENCED_PARAMETER(Argument);

    libivc_trace("====>\n");

    KeReleaseSpinLockFromDpcLevel(&GnttabLock);

    libivc_trace("<====\n");
}

static int
gnttab_cache_init(uint16_t remoteDomId, PXENBUS_GNTTAB_CACHE *cache)
{
    NTSTATUS status;
    char cacheName[128];
    static int cacheCounter = 0;

    libivc_trace("====>\n");

    if (!XenInterfacesAcquired)
    {
        libivc_error("failed to initialize cache without xen interfaces...\n");
        return INVALID_PARAM;
    }

    KeInitializeSpinLock(&GnttabLock);

    _snprintf_s(cacheName, sizeof(cacheName), sizeof(cacheName), "ivc_%d_%d", remoteDomId, cacheCounter++);

    status = XENBUS_GNTTAB(CreateCache,
        &GnttabInterface,
        cacheName,
        remoteDomId,
        gnttab_spinlock_acquire,
        gnttab_spinlock_release,
        NULL,
        cache);

    if (!NT_SUCCESS(status))
    {
        libivc_error("Failed to create gnttab cache.\n");
        return ACCESS_DENIED;
    }

    libivc_trace("<====\n");

    return SUCCESS;
}

static VOID
gnttab_cache_release(PXENBUS_GNTTAB_CACHE cache)
{
    libivc_trace("====>\n");

    if (!XenInterfacesAcquired)
    {
        libivc_error("failed to release cache without xen interfaces...\n");
        return;
    }

    if (!cache)
    {
        libivc_error("request to release invalid cache...\n");
        return;
    }

    XENBUS_GNTTAB(DestroyCache, &GnttabInterface, cache);

    libivc_trace("<====\n");
}

/**
* Allocates memory for sharing to a remote domain and grants it.
* @param numPages The number of pages to share
* @param remoteDomId The remote domain id being shared to.
* @param readOnly Non zero for read only memory to the remote dom.
* @param mem Pointer to receive address into.
* @param grantRefs pointer to receive list of grant refs into.  Should not be
* modified outside of platform itself.
* @return SUCCESS or appropriate error message.
*/
__pragma(warning(push))
__pragma(warning(disable:4127))
int
ks_platform_alloc_shared_mem(uint32_t numPages, uint16_t remoteDomId,
							 char **mem, mapped_grant_ref_t ** mappedGrants)
{
	int rc = INVALID_PARAM;
	uint32_t pageNo = 0;
	PPFN_NUMBER mdlPfn;
	shareable_mem_alloc_t * allocMem = NULL;

    libivc_trace("====>\n");

	libivc_assert(numPages > 0, rc);
	libivc_checkp(mem, rc);
	libivc_checkp(mappedGrants,rc);
	// do share to ourselves, things get unhappy when unsharing in the guest otherwise.
	libivc_assert(remoteDomId != ks_ivc_core_get_domain_id(),rc);

    // allocate structure to track and later release memory allocation.
	allocMem = ks_platform_alloc(numPages * PAGE_SIZE);

    INIT_LIST_HEAD(&allocMem->listHead);

	libivc_checkp(allocMem, OUT_OF_MEM);

	// allocate the memory that will be shared to the remote domain.  Windows nicely
	// page aligns the memory for us if the sizes are correct.
	*mem = allocMem->kAddress = ks_platform_alloc(numPages * PAGE_SIZE);
	// make sure we have allocated the space requested.
	libivc_checkp(*mem, OUT_OF_MEM);
	// set return code until we are sure all allocations are done.
	rc = OUT_OF_MEM;
	// allocate the memory descriptors which are used during the sharing.  If you're coming
	// from the Linux side, you can sort of think of these as the struct page array for the memory.
	allocMem->mdls = IoAllocateMdl(allocMem->kAddress, (ULONG)numPages * PAGE_SIZE,
		FALSE, FALSE, NULL);
	libivc_checkp_goto(allocMem->mdls, ERROR);
	// fill in the memory descriptors for the allocated pool.
	MmBuildMdlForNonPagedPool(allocMem->mdls);
	// allocate space to store the grant references generated when sharing.
	// these are needed to undo the sharing later.
	*mappedGrants = allocMem->grantHandles = ks_platform_alloc(numPages * sizeof(mapped_grant_ref_t));
	libivc_checkp_goto(allocMem->grantHandles, ERROR);

	allocMem->grantCache = NULL;
	gnttab_cache_init(remoteDomId, &allocMem->grantCache);

	// get the array of memory descriptors
	mdlPfn = MmGetMdlPfnArray(allocMem->mdls);
	// for each memory descriptor (page of memory) share it to the remote domain.
	// set the read write access for the pages based on the readOnly parameter.
	rc = ACCESS_DENIED; // in case we error.
	for (pageNo = 0; pageNo < numPages; pageNo++)
	{
        rc = ks_platform_permit_grant_ref(mdlPfn[pageNo], remoteDomId, allocMem->grantCache, &allocMem->grantHandles[pageNo]);
        libivc_assert_goto(rc == SUCCESS, ERROR);
	}
	rc = SUCCESS;
    allocMem->numPages = numPages;
	list_add(&allocMem->listHead, &sharedMemoryList);
	goto END;
	
ERROR:
	if (allocMem)
	{
		// our undo it all section.
		if (allocMem->grantHandles)
		{
			// undo the granted memory.
            if (allocMem->grantCache)
            {
                for (pageNo = 0; pageNo < numPages; pageNo++)
                {
                    if (!allocMem->grantHandles[pageNo].valid)
                        break;

                    ks_platform_revoke_grant_ref(&allocMem->grantHandles[pageNo]);
                }

                gnttab_cache_release(allocMem->grantCache);
                allocMem->grantCache = NULL;
            }

			// free the array where the grants were being stored.
			ks_platform_free(allocMem->grantHandles);
			allocMem->grantHandles = NULL;
		}
	}

	// free the allocated buffer that was supposed to be shared.
	if (allocMem->kAddress)
	{
		// free the memory descriptors.
		IoFreeMdl(allocMem->mdls);
		allocMem->mdls = NULL;
		// free the buffer.
		ks_platform_free(allocMem->kAddress);
		*mem = allocMem->kAddress = NULL;
	}
END:
    libivc_trace("<====\n");
	return rc;
}
__pragma(warning(pop))

/**
* Free the shared memory previously created by ks_platform_alloc_shared_mem.
* @param mem - Non NULL pointer returned in ks_platform_alloc_shared_mem
* @return SUCCESS or appropriate error number.
*/
int
ks_platform_free_shared_mem(char *mem)
{
	int rc = INVALID_PARAM;
	list_head_t *pos = NULL, *temp = NULL;
	shareable_mem_alloc_t *allocMem = NULL;
	uint32_t pageNo = 0;
	//PEPROCESS current;
	//KAPC_STATE apcState;

    libivc_trace("====>\n");
	
	libivc_checkp(mem, rc);

	list_for_each_safe(pos, temp, &sharedMemoryList)
	{
		allocMem = container_of(pos, shareable_mem_alloc_t, listHead);
		if (allocMem->kAddress == mem)
		{
			list_del(&allocMem->listHead);
			break; // found it.
		}
		else
		{
			allocMem = NULL; // not found yet.
		}
	}

	// if it wasn't found, we didn't share anything with this address.
	libivc_checkp(allocMem, rc);

	// for each memory descriptor (page) end the access to the remote domain.
	// which may be delayed as there is no way to force the remote domain to let go of it.
	for (pageNo = 0; pageNo <allocMem->numPages; pageNo++)
	{
        ks_platform_revoke_grant_ref(&allocMem->grantHandles[pageNo]);
	}
	gnttab_cache_release(allocMem->grantCache);
	allocMem->grantCache = NULL;

	// free the array used to store the grants.
	ks_platform_free(allocMem->grantHandles);
	allocMem->grantHandles = NULL;
	allocMem->numPages = 0;
	// free the array of memory descriptors.
	IoFreeMdl(allocMem->mdls);
	// free the buffer that was shared.
	ks_platform_free(allocMem->kAddress);
	allocMem->kAddress = NULL;
	ks_platform_free(allocMem);

    libivc_trace("<====\n");
	return SUCCESS;
}

static VOID
_Function_class_(EVT_WDF_WORKITEM)
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
EvtchnPassiveHandler(IN WDFWORKITEM workItem)
{
	pworker_item_context_t context = NULL;
	event_channel_info_t * cInfo = NULL;

    libivc_trace("====>\n");

	context = workItemGetContext(workItem);
	cInfo = context->cInfo;

	if (cInfo != NULL && cInfo->callback != NULL)
	{
		libivc_info("Calling core callback for event notification.\n");
		cInfo->callback(cInfo->irq);
	}
	else
	{
		libivc_info("Didn't find anyone to callback for on event channel notification.\n");
	}
   WdfObjectDelete(workItem);
}

/**
* Callback directly on event channel irq context.  This function takes the notification and moves it to
* a thread so that it completes as quickly as possible and provides safety to the rest of the driver
* during mutex locks, etc.
*/
static VOID
_Function_class_(KDEFERRED_ROUTINE)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(DISPATCH_LEVEL)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
EvtchnDpcHandler(
    _In_ struct _KDPC *Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    UNREFERENCED_PARAMETER(Dpc); 
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

	NTSTATUS status = STATUS_SUCCESS;
	pworker_item_context_t context;
	WDF_OBJECT_ATTRIBUTES attributes;
	WDF_WORKITEM_CONFIG workItemConfig;
	WDFWORKITEM workItem;
	event_channel_info_t * cInfo = NULL;

    libivc_trace("====>\n");

	cInfo = (event_channel_info_t *)DeferredContext;

	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, worker_item_context_t);
	
	attributes.ParentObject = device;
	WDF_WORKITEM_CONFIG_INIT(&workItemConfig, EvtchnPassiveHandler);

	status = WdfWorkItemCreate(&workItemConfig,
		&attributes, &workItem);
	if (!NT_SUCCESS(status))
	{
		libivc_info("Failed to create work item to handle event callback.\n");
		return;
	}

	context = workItemGetContext(workItem);
	context->cInfo = cInfo;
	libivc_info("[ivc]: enqueueing work item.\n");
	WdfWorkItemEnqueue(workItem);

    libivc_trace("<====\n");
}


static BOOLEAN
_Function_class_(KSERVICE_ROUTINE)
_IRQL_requires_(HIGH_LEVEL) // HIGH_LEVEL is best approximation of DIRQL
_IRQL_requires_same_
EvtchnDirqlHandler(
    _In_ struct _KINTERRUPT *Interrupt,
    _In_opt_ PVOID ServiceContext
)
{
    UNREFERENCED_PARAMETER(Interrupt);

    event_channel_info_t *info = (event_channel_info_t *)ServiceContext;

    libivc_trace("====>\n");

    if (!info)
    {
        libivc_info("EvtchnCallback with NULL context?\n");
        return FALSE;
    }

    KeInsertQueueDpc(&info->dpc, NULL, NULL);

    libivc_trace("<====\n");
    return TRUE;
}

/**
* Create an unbound inter-domain channel for communication with a given domain.
* @param remoteDomId remote domain to create channel to.
* @param eventPort variable to receive event port
* @return SUCCESS, or appropriate error number.
*/
int
ks_platform_createUnboundEvtChn(uint16_t remoteDomId, evtchn_port_t *eventPort)
{
	int rc = INVALID_PARAM;
	event_channel_info_t * info = NULL;

    libivc_trace("====>\n");

    if (!XenInterfacesAcquired)
        return INVALID_PARAM;

	libivc_info("Creating unbound channel to %u\n", remoteDomId);
	info = ks_platform_alloc(sizeof(event_channel_info_t));
	if(!info) 
	{
		return OUT_OF_MEM;
	}

    KeInitializeDpc(&info->dpc, EvtchnDpcHandler, info);
    
    /* TODO: winPort vs. event_channel semantics are backwards, will fix after port */
    info->winPort = XENBUS_EVTCHN(Open,
        &EvtchnInterface,
        XENBUS_EVTCHN_TYPE_UNBOUND,
        EvtchnDirqlHandler,
        info,
        remoteDomId,
        FALSE);

    if (!info->winPort)
    {
        rc = ACCESS_DENIED;
        goto ERROR;
    }

    info->event_channel = XENBUS_EVTCHN(GetPort, &EvtchnInterface, info->winPort);

	// now add it to our list so we can retrieve it later to close it properly.
	mutex_lock(&eventChannelMutex);
	list_add(&info->listHead, &eventChannels);
	mutex_unlock(&eventChannelMutex);
	*eventPort = info->event_channel;
	libivc_info("Event channel %u created.\n", *eventPort);
    libivc_trace("<====\n");
	return SUCCESS;

ERROR:
	if (info->winPort)
	{
        XENBUS_EVTCHN(Close, &EvtchnInterface, info->winPort);
        info->winPort = NULL;
        info->event_channel = 0;
	}

    libivc_trace("<====\n");
	return rc;
}

/**
* Closes a previously open channel.
* @param eventChannel channel created by ks_platform_createUnboundEvtChn.
* @return SUCCESS, or appropriate error number.
*/
int
ks_platform_closeEvtChn(evtchn_port_t eventChannel)
{
	int rc = INVALID_PARAM;
	list_head_t *pos = NULL, *tmp = NULL;
	event_channel_info_t *cInfo = NULL;

    libivc_trace("====>\n");

    if (!XenInterfacesAcquired)
        return INVALID_PARAM;

	mutex_lock(&eventChannelMutex);
	list_for_each_safe(pos, tmp, &eventChannels)
	{
		cInfo = container_of(pos, event_channel_info_t, listHead);
		if (cInfo->event_channel == eventChannel)
		{
			list_del(pos);
			break;
		}
		else
		{
			cInfo = NULL;
		}
	}
	mutex_unlock(&eventChannelMutex);

	if (cInfo == NULL)
	{
		return rc;
	}

    XENBUS_EVTCHN(Close, &EvtchnInterface, cInfo->winPort);
	RtlZeroMemory(cInfo, sizeof(event_channel_info_t));
	ks_platform_free(cInfo);
	cInfo = NULL;

    libivc_trace("<====\n");
	return SUCCESS;
}


/**
* given a xen event channel port number, bind it to a local irq number
* and a callback that will be called when the event is fired in the platform driver.
* @param port - the remote xen event channel number.
* @param localIrq - Pointer to receive the local number bound to .
* @param callback - the callback that will be triggered on the event firing.
* @return SUCCESS or appropriate error number.
*/
int
ks_platform_bind_event_callback(evtchn_port_t port, uint32_t *localIrq, event_channel_callback callback)
{
	int rc = INVALID_PARAM;
	event_channel_info_t * cInfo = NULL;
	list_head_t * pos;

    libivc_trace("====>\n");

	libivc_assert(port > 0, rc);
	libivc_checkp(localIrq, rc);
	libivc_checkp(callback, rc);

	mutex_lock(&eventChannelMutex);
	list_for_each(pos, &eventChannels)
	{
		cInfo = container_of(pos, event_channel_info_t, listHead);
		if(cInfo->event_channel == port) 
		{
			break;
		} else 
		{
			cInfo = NULL;
		}
	}
	mutex_unlock(&eventChannelMutex);

    if (!cInfo)
    {
        libivc_error("failed to find event channel with port=%d\n", (int)port);
        return rc;
    }

	*localIrq = ++fakeIrq;
	if (*localIrq == 0)
	{
		*localIrq = ++fakeIrq;
	}
	cInfo->callback = callback;
	cInfo->event_channel = port;
	cInfo->irq = *localIrq;

    XENBUS_EVTCHN(Unmask,
        &EvtchnInterface,
        cInfo->winPort,
        FALSE,
        TRUE);

    libivc_trace("<====\n");
	return SUCCESS;
}

/**
* Given a remote domains inter-domain event channel, binds it to a local irq
* for event notifications and when triggered calls the event callback.
* @param remoteDomId - Id of remote domain
* @param port - event channel port number.
* @param localIrq - NON null pointer to receive the local irq number.
* @param callback - function to be called back when event fires.
* @return SUCCESS, or appropriate error number.
*/
__pragma(warning(push))
__pragma(warning(disable:4127))
int
ks_platform_bind_interdomain_evt(uint16_t remoteDomId, evtchn_port_t port,
								 uint32_t *localIrq, event_channel_callback callback)
{
    //PAGED_CODE();
#if 0
    libivc_error("Creating servers not currently supported on windows.\n");
    libivc_error("Continue at your own risk.\n");

	event_channel_info_t * info = NULL;
	int rc = INVALID_PARAM;

	libivc_assert(port > 0, INVALID_PARAM);
	libivc_checkp(localIrq, INVALID_PARAM);
	libivc_checkp(callback, INVALID_PARAM);

	info = ks_platform_alloc(sizeof(event_channel_info_t));
	libivc_checkp(info, OUT_OF_MEM);

	INIT_LIST_HEAD(&info->listHead);
	mutex_lock(&eventCallbackMutex);
	list_add(&info->listHead, &eventCallbacks);
	mutex_unlock(&eventCallbackMutex);

	info->event_channel = port;
	info->callback = callback; 
	winEvt = wrap_ALIEN_EVTCHN_PORT(port);
	info->winPort = xenApi->EvtchnConnectRemotePort(wrap_DOMAIN_ID(remoteDomId), winEvt, xen_event_handler_cb, info);
	if (is_null_EVTCHN_PORT(info->winPort))
	{
		libivc_info("Binding to remote event port %u failed.\n", port);
		mutex_lock(&eventCallbackMutex);
		list_del(&info->listHead);
		mutex_unlock(&eventCallbackMutex);
		rc = ACCESS_DENIED; 
	}
	else
	{
		rc = SUCCESS;
	}

	return rc;
#endif
    UNREFERENCED_PARAMETER(localIrq);
    UNREFERENCED_PARAMETER(callback);
    UNREFERENCED_PARAMETER(port);
    UNREFERENCED_PARAMETER(remoteDomId);

    libivc_error("ks_platform_bind_interdomain_evt not supported on this platform.\n");
    return NOT_IMPLEMENTED;
}
__pragma(warning(pop))

int ks_platform_unbind_event_callback(int localIrq)
{
	list_head_t *pos = NULL, *temp = NULL;
	event_channel_info_t * eInfo = NULL;
	int rc = INVALID_PARAM;

    libivc_trace("====>\n");

	mutex_lock(&eventCallbackMutex);

	list_for_each_safe(pos, temp, &eventChannels)
	{
		eInfo = container_of(pos, event_channel_info_t, listHead);
		if (eInfo->irq == localIrq)
		{
			list_del(pos);
            XENBUS_EVTCHN(Close, &EvtchnInterface, eInfo->winPort);
            eInfo->event_channel = 0;
			eInfo->callback = NULL;
			eInfo->irq = 0;
			ks_platform_free(eInfo);
			eInfo = NULL;
			rc = SUCCESS;
			break;
		}
	}

	mutex_unlock(&eventCallbackMutex);

    libivc_trace("<====\n");
	return rc;
}

int
ks_platform_start_xenbus_transaction(xenbus_transaction_t *trans)
{
    NTSTATUS status;

    libivc_trace("====>\n");

    if (!XenInterfacesAcquired)
        return INVALID_PARAM;

	libivc_checkp(trans, INVALID_PARAM);

    status = XENBUS_STORE(TransactionStart, &StoreInterface, trans);
    
    if (!NT_SUCCESS(status))
        return INTERNAL_ERROR;

    libivc_trace("<====\n");
	return SUCCESS;
}

int
ks_platform_end_xenbus_transaction(xenbus_transaction_t trans)
{
	NTSTATUS status;
	int rc;

    libivc_trace("====>\n");

    if (!XenInterfacesAcquired)
        return INVALID_PARAM;

    status = XENBUS_STORE(TransactionEnd, &StoreInterface, trans, TRUE);

    if (NT_SUCCESS(status))
	{
		rc = SUCCESS;
	}
	else if (status == STATUS_RETRY)
	{
		rc = ERROR_AGAIN;
	}
	else
	{
		libivc_info("failed to end transaction with status 0X%0X\n", status);
		rc = ACCESS_DENIED;
	}

    libivc_trace("<====\n");
	return rc;
}

int
ks_platform_xenstore_rm(const char *path, const char *node)
{
    UNREFERENCED_PARAMETER(node); 
    
    int rc = INVALID_PARAM;
	NTSTATUS status;

    libivc_trace("====>\n");

    if (!XenInterfacesAcquired)
        return INVALID_PARAM;

	libivc_checkp(path, rc);
	
	libivc_info("Removing path %s\n", path);

	status = XENBUS_STORE(Remove, &StoreInterface, NULL, (PCHAR)path, (PCHAR)node);

    if (!NT_SUCCESS(status))
	{
		libivc_info("Failed to remove path %s - error: %d\n", path, status);
		rc = ACCESS_DENIED;
	}
	else
	{
		libivc_info("Removed path.\n");
		rc = SUCCESS;
	}

    libivc_trace("<====\n");
	return rc;
}

/**
* Maps in memory grants from a remote domain
* @param domId - domain id of remote domain
* @param grants - array of grant references from remote domain
* @param numGrants - number of grant references in grants array
* @param mem - pointer to receive virtually contigous address.
* @param readOnly - non zero for writable, but ensure the remote shared
* it that way unless you like VMs freezing.
* @return SUCCESS or appropriate error number.
*/
__pragma(warning(push))
__pragma(warning(disable:4127))
int
ks_platform_map_grants(uint16_t domId, uint16_t port, uint64_t connection_id, grant_ref_t *grants,
                        uint32_t numGrants, char **mem, file_context_t *f
                       )
{
#if 0
	(void)port;
	(void)f;
	(void)connection_id;

    int rc = INVALID_PARAM;

	uint32_t grantIndex;
	NTSTATUS status;
	mapped_grant_ref_t *grantHandles = NULL;
	mapped_mem_descriptor_t *mappedMem = NULL;
	//PAGED_CODE();

	libivc_checkp(grants, rc);
	libivc_assert(numGrants > 0, rc);
	libivc_checkp(mem, rc);

	mappedMem = ks_platform_alloc(sizeof(mapped_mem_descriptor_t));
	libivc_checkp(mappedMem, OUT_OF_MEM);
	INIT_LIST_HEAD(&mappedMem->listHead);
	mappedMem->numGrants = numGrants;

	// sadly the API won't take just the xen grant ref, it needs to be stuck
	// in the very annoying wrapper struct and passed on. so temporarily allocate
	// space for the wrappers.
	rc = OUT_OF_MEM;
    grantHandles = ks_platform_alloc(numGrants * sizeof(mapped_grant_ref_t));
	libivc_checkp_goto(grantHandles, ERROR);

	// for each grant ref, wrap it up.
	for (grantIndex = 0; grantIndex < numGrants; grantIndex++)
	{
        grantHandles[grantIndex].ref = wrap_ALIEN_GRANT_REF(grants[grantIndex]);
	}
	// make sure details is null before calling map, or it will blue screen the VM.
	mappedMem->details = NULL;
	// batch map in the grants
	libivc_info("Mapping in %d grants from %u\n", numGrants, domId);
	status = xenApi->GntmapMapGrants(wrap_DOMAIN_ID(domId), numGrants, refs, 
									(GRANT_MODE_RW), &mappedMem->details);
	// free the temporary wrapped up grants.
	ks_platform_free(refs);
	refs = NULL;
	// if we successfully mapped in the grants, turn the individual mapped in pages
	// into virtually contiguous memory.
	if (NT_SUCCESS(status))
	{
		// get the virtually contiguous memory descriptor list.
		libivc_info("mapping mdls.\n");
		mappedMem->mdls = xenApi->GntmapMdl(mappedMem->details);
		// get the base address of the memory descriptor list.
		//mInfo->kAddress = MmGetSystemAddressForMdlSafe(mInfo->mdls, NormalPagePriority);
		*mem = mappedMem->kAddress = MmMapLockedPagesSpecifyCache(mappedMem->mdls, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
		if(mappedMem->kAddress == NULL)
		{
			libivc_error("Failed to get system address for mapped in grants.\n");
			rc = ACCESS_DENIED;
			xenApi->GntmapUnmapGrants(mappedMem->details);
			mappedMem->details = NULL;
			mappedMem->numGrants = 0;
			ks_platform_free(mappedMem);
			mappedMem = NULL;
		} else
		{
			list_add(&mappedMem->listHead, &mappedMemoryList);
			rc = SUCCESS;
		}
	}
	else
	{
		libivc_error("Failed to map in grants from remote domain. status = 0X%0X\n", status);
		rc = ACCESS_DENIED;
		goto ERROR;
	}

	goto END;
ERROR:

	if (mappedMem)
	{
		ks_platform_free(mappedMem);
		mappedMem = NULL;
	}
END:
	return rc;
#endif
    UNREFERENCED_PARAMETER(port);
    UNREFERENCED_PARAMETER(connection_id);
    UNREFERENCED_PARAMETER(domId);
    UNREFERENCED_PARAMETER(mem);
    UNREFERENCED_PARAMETER(grants);
    UNREFERENCED_PARAMETER(numGrants);
    UNREFERENCED_PARAMETER(f);

    libivc_error("ks_platform_map_grants not implemented on this platform.\n");
    return NOT_IMPLEMENTED;
}
__pragma(warning(pop))


/**
* Compatibility stub for local mappings.
*/
int
ks_platform_map_local_memory(void *kernel_address, uint16_t port, 
        char **mem, uint32_t numPages, file_context_t *f)
{
    //PAGED_CODE();

    (void)kernel_address;
    (void)port;
    (void)mem;
    (void)numPages;
    (void)f;

    libivc_error("Same-domain IVC channels are not (yet) supported on this platform.\n");
    return NOT_IMPLEMENTED;
}


/**
 * Maps in shared memory pages from the local domain
 * @param kernel_address The address of the object requesting mapping.
 * @param grants - array of grant references from remote domain
 * @param numGrants - number of grant references in grants array
 * @param mem - pointer to receive virtually contigous address.
 * @param readOnly - non zero for writable, but ensure the remote shared
 * it that way unless you like VMs freezing.
 * @return SUCCESS or appropriate error number.
 */
int ks_platform_unmap_local_memory(char *mem)
{
    (void)mem;
    //PAGED_CODE();

    libivc_error("Same-domain IVC channels are not (yet) supported on this platform.\n");
    return NOT_IMPLEMENTED;
}


/**
 * Notifies any connected local clients that the provided local client 
 * has disconnceted.
 *
 * @param disconnecting_client The client whose counterparts should be notified.
 * @return SUCCESS, or an appropriate error code
 */
int ks_platform_notify_local_disconnect(struct libivc_client * disconnecting_client)
{
    UNREFERENCED_PARAMETER(disconnecting_client);
    //PAGED_CODE();

    libivc_error("Same-domain IVC channels are not (yet) supported on this platform.\n");
    return NOT_IMPLEMENTED;
}


/**
* Unmaps and releases memory from a remote domain.
* @param mem - memory address returned from ks_platform_map_grants.
* @return - SUCCESS or appropriate error number.
*/
int
ks_platform_unmap_remote_grants(char *mem)
{
#if 0
	list_head_t *pos = NULL, *temp = NULL;
	mapped_mem_descriptor_t *memDesc = NULL;
	//PEPROCESS currProcess;
	//KAPC_STATE apcState;
	//PAGED_CODE();

	libivc_checkp(mem, INVALID_PARAM);
	// find our description of the mapped mem.
	list_for_each_safe(pos, temp, &mappedMemoryList)
	{
		memDesc = container_of(pos, mapped_mem_descriptor_t, listHead);
		if (memDesc->kAddress == mem)
		{
			list_del(pos);
			break;
		}
		else
		{
			memDesc = NULL; // not found yet.
		}
	}

	libivc_checkp(memDesc, INVALID_PARAM); // never found a match.

	// if the user address is set, we need to unmap from the user space
	// before releasing the memory.
	/*if(minfo->uAddress && minfo->userProcess)
	{
		currProcess = PsGetCurrentProcess();
		// if we are not within the process of the 
		// user thread that mapped in the memory, we
		// need to attach to it first and then unmap it.
		// seems a little dicey for the user space process....
		// but not doing so will BSOD
		if(currProcess != minfo->userProcess)
		{
			RtlZeroMemory(&apcState, sizeof(KAPC_STATE));
			libivc_info("[ivc]: reconnecting to userspace process.\n");
			KeStackAttachProcess(minfo->userProcess, &apcState);
		}

		// Unmap the userspace address.  This has to be done in the orignal 
		// process context it was mapped into.
		libivc_info("[ivc]: unmapping address from user space.\n");
		MmUnmapLockedPages(minfo->uAddress, minfo->mdls);
		minfo->uAddress = NULL;
		// if we attached to a different process, we need to detach from it
		// or run into deadlock issues.
		if(currProcess != minfo->userProcess)
		{
			libivc_info("[ivc]: detaching from userspace process.\n");
			KeUnstackDetachProcess(&apcState);
		}
	}*/
	// Release the granted memory back to the remote domain.
	libivc_info("unmapping grants.\n");
	MmUnmapLockedPages(memDesc->kAddress, memDesc->mdls);
	xenApi->GntmapUnmapGrants(memDesc->details);
	// NULL out our addresses.
	memDesc->kAddress = NULL;
	memDesc->details = NULL;
	mem = NULL;
	ks_platform_free(memDesc);
	memDesc = NULL;
	return SUCCESS;
#endif
    UNREFERENCED_PARAMETER(mem);

    libivc_error("ks_platform_unmap_remote_grants not implemented on this platform.\n");
    return NOT_IMPLEMENTED;
}


/**
* Fires a XEN event specified by the dom id in client.
* @param client - non null pointer to object that describes connection.
* @return SUCCESS or appropriate error number.
*/
int
ks_platform_fire_remote_event(struct libivc_client *client)
{
	int rc = SUCCESS;
	list_head_t * pos = NULL;
	event_channel_info_t * cInfo = NULL;
    KIRQL irql;

    //libivc_trace("====>\n");

	libivc_checkp(client, INVALID_PARAM);

	// find the matching event channel information so we can get back to the wrapped up
	// windows driver event channel.
	mutex_lock(&eventChannelMutex);
	list_for_each(pos, &eventChannels)
	{
		cInfo = container_of(pos, event_channel_info_t, listHead);
		if(cInfo->event_channel == client->event_channel)
		{
			break;
		} else
		{
			cInfo = NULL;
		}
	}
	mutex_unlock(&eventChannelMutex);

    if (!cInfo)
    {
        libivc_error("failed to find cinfo for firing remote event\n");
        return INVALID_PARAM;
    }

    irql = KeRaiseIrqlToDpcLevel();
    XENBUS_EVTCHN(Send, &EvtchnInterface, cInfo->winPort);
    KeLowerIrql(irql);

    //libivc_trace("<====\n");
	return rc;
}

/**
* Notifies a user space server listener that a new client has connected.
* @param server NON null server to notify.
* @return SUCCESS or appropriate error number.
*/
int
ks_platform_notify_us_client_connect(struct libivc_server *server)
{
    libivc_trace("====>\n");

	libivc_checkp(server, INVALID_PARAM);
	libivc_checkp(server->context, INVALID_PARAM);
	if (server->client_connect_event)
	{
		KeSetEvent((PKEVENT)server->client_connect_event, 0, FALSE);
	}

    libivc_trace("<====\n");
	return SUCCESS;
}

/**
* Notifies a user space ivc client that a remote event was fired to it.
* @param client - NON null ivc client to notify.
* @return SUCCESS or appropriate error number.
*/
int
ks_platform_notify_us_client_event(struct libivc_client *client)
{
    libivc_trace("====>\n");

	libivc_checkp(client, INVALID_PARAM);
	libivc_checkp(client->context, INVALID_PARAM);
	libivc_checkp(client->client_notify_event, INVALID_PARAM);
	KeSetEvent((PKEVENT)client->client_notify_event,0,FALSE);

    libivc_trace("<====\n");
	return SUCCESS;
}

/**
* Notifies a user space ivc client that a remote wants to disconnect.
* @param client - NON null ivc client to notify.
* @return SUCCESS or appropriate error number.
*/
int
ks_platform_notify_us_client_disconnect(struct libivc_client *client)
{
    libivc_trace("====>\n");

	libivc_checkp(client, INVALID_PARAM);
	libivc_checkp(client->context, INVALID_PARAM);
	libivc_checkp(client->client_disconnect_event, INVALID_PARAM);

	KeSetEvent((PKEVENT)client->client_disconnect_event,0,FALSE);

    libivc_trace("<====\n");
	return SUCCESS;
}

/**
* Maps a kernel space address to userspace
* @param kAddress Kernel address
* @param uAddress pointer to receive user space address
* @param memSize Size of memory that is being shared.
* @param context the userspace file context.
* @return SUCCESS or appropriate error number.
*/
int
ks_platform_map_to_userspace(char *kAddress, char **uAddress, size_t memSize, file_context_t *context)
{	
	list_head_t *pos = NULL, *temp = NULL;
	shareable_mem_alloc_t * sharedMem = NULL;
	mapped_mem_descriptor_t *mappedMem = NULL;
	PMDL mMdls = NULL;

    libivc_trace("====>\n");

	libivc_checkp(kAddress, INVALID_PARAM);
	libivc_checkp(uAddress, INVALID_PARAM);
	libivc_assert(memSize > 0, INVALID_PARAM);
	libivc_checkp(context, INVALID_PARAM);

	// find the object assocatiated with the kernel address passed in, it could be memory we allocated and shared, or mapped
	// in from a remote domain.
	list_for_each_safe(pos, temp, &sharedMemoryList)
	{
		sharedMem = container_of(pos, shareable_mem_alloc_t, listHead);
		if (sharedMem->kAddress == kAddress)
		{
			break;
		}
		else
		{
			sharedMem = NULL;
		}
	}

	if (sharedMem == NULL)
	{
		list_for_each_safe(pos, temp, &mappedMemoryList)
		{
			mappedMem = container_of(pos, mapped_mem_descriptor_t, listHead);
			if (mappedMem->kAddress == kAddress)
			{
				break;
			}
			else
			{
				mappedMem = NULL;
			}
		}
	}
	// if both are NULL, we don't know what address this is....
	libivc_assert(!(mappedMem == NULL && sharedMem == NULL), INVALID_PARAM);
	mMdls = mappedMem != NULL ? mappedMem->mdls : sharedMem->mdls;
	// double check...
	libivc_checkp(mMdls, INTERNAL_ERROR);

	// lock pages can throw an exception, which is really the notice that something occurred rather than just returning a NULL
	try
	{
		*uAddress = MmMapLockedPagesSpecifyCache(mMdls, UserMode, 
													   MmNonCached, NULL, FALSE, NormalPagePriority);
		libivc_info("uaddress = %p\n", *uAddress);
	}except(EXCEPTION_EXECUTE_HANDLER)
	{
		libivc_info("Failed to lock into user space.");
		*uAddress = NULL;
		return ACCESS_DENIED; // ? sort of I guess
	}

    libivc_trace("<====\n");
	return SUCCESS;
}

/**
* Reads an integer value from the xenstore
* @param trans - xenbus transaction that was previously started.
* @param path - path where node being read exists.
* @param node - the node or name of value to read.
* @param value - pointer to receive value into.
* @return SUCCESS or appropriate error number.
*/
int
ks_platform_read_int(xenbus_transaction_t trans, char *path, char *node, int *value)
{
	NTSTATUS status;
    PCHAR buffer;

    libivc_trace("====>\n");

    if (!XenInterfacesAcquired)
        return INVALID_PARAM;

	libivc_checkp(node, INVALID_PARAM);
	libivc_checkp(value, INVALID_PARAM);

    status = XENBUS_STORE(Read,
        &StoreInterface,
        trans,
        path,
        node,
        &buffer);

    if (!NT_SUCCESS(status))
    {
        libivc_info("failed to read %s/%s\n", path, node);
        *value = 0;
        return ACCESS_DENIED;
    }

    libivc_info("xenstore read: %s/%s <= %s\n", path ? path : "NULL", node, buffer);

    if (sscanf_s(buffer, "%d", value) != 1)
    {
        libivc_error("failed to convert domid to integer.\n");
        *value = 0;
        return ACCESS_DENIED;
    }

    libivc_info("xenstore read: integer = %d\n", *value);

    XENBUS_STORE(Free, &StoreInterface, buffer);

    libivc_trace("<====\n");
    return SUCCESS;
}

/**
* Writes an int value to node under path.
* @param path - base path where node will be written
* @param node - node or name of value being written.
* @param value - the value
* @param trans - transaction that has been started.
* @return SUCCESS or appropriate error number.
*/
int
ks_platform_xenstore_write_int(const char *path, const char *node, int value, xenbus_transaction_t trans)
{
    NTSTATUS status;

    libivc_trace("====>\n");

    if (!XenInterfacesAcquired)
        return INVALID_PARAM;

	libivc_checkp(path, INVALID_PARAM);
	libivc_checkp(node, INVALID_PARAM);

    status = XENBUS_STORE(Printf, &StoreInterface, trans, (PCHAR)path, (PCHAR)node, "%d", value);

    if (status == STATUS_RETRY)
    {
        return ERROR_AGAIN;
    }
    else if (!NT_SUCCESS(status))
    {
        return ACCESS_DENIED;
    }

    libivc_trace("<====\n");
    return SUCCESS;
}

/**
* Printf style writing to xenstore.
* @param trans - transaction that was started.
* @param path - path which node will be written to.
* @param node - node or name value will be written to.
* @param fmt - printf style format
* @param ... - variable args required by the format.
* @return SUCCESS or appropriate error number
*/
int
ks_platform_xenstore_printf(xenbus_transaction_t trans, const char *path,const char *node, const char * fmt, ...)
{
	char value[IVC_MAX_PATH];
	va_list args;
	NTSTATUS status;

    libivc_trace("====>\n");

    if (!XenInterfacesAcquired)
        return INVALID_PARAM;

	libivc_checkp(path, INVALID_PARAM);
	libivc_checkp(node, INVALID_PARAM);
	libivc_checkp(fmt, INVALID_PARAM);

	memset(value, '\0', IVC_MAX_PATH);
	va_start(args, fmt);
	libivc_info("calling vsnprintf\n");
	_vsnprintf_s(value, IVC_MAX_PATH, IVC_MAX_PATH - 1, fmt, args);

    status = XENBUS_STORE(Printf, &StoreInterface, trans, (PCHAR)path, (PCHAR)node, value);

	if (status == STATUS_RETRY)
	{
		return ERROR_AGAIN;
	}
	else if (!NT_SUCCESS(status))
	{
		return ACCESS_DENIED;
	}

    libivc_trace("<====\n");
    return SUCCESS;
}
