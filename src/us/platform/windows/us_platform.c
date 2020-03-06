#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <winioctl.h>
#include <us_platform.h>
#include <tchar.h>
#include <process.h>
#include <libivc.h>
#include <libivc_private.h>
#include <libivc_debug.h>

/**
* Windows platform specific handler to open the ivc driver and other functions needed
* to support driver callbacks.
* @return SUCCESS, or appropriate error number.
*/
int
us_openDriver(void);

// create the function prototypes for the required platform callbacks that ivc needs.
int
us_register_server_listener(struct libivc_server *server);

int
us_unregister_server_listener(struct libivc_server * server);

int
us_notify_remote(struct libivc_client * ivc);

int
us_ivc_connect(struct libivc_client *ivc);

int
us_ivc_disconnect(struct libivc_client * ivc);

int
libivc_platform_init(platform_functions_t * pf);

void
populate_cli(struct libivc_client_ioctl_info *cli_info, struct libivc_client *client);

void
update_client(struct libivc_client_ioctl_info *cli_info, struct libivc_client *client);

static HANDLE driverHandle = INVALID_HANDLE_VALUE;

void
populate_cli(struct libivc_client_ioctl_info *cli_info, struct libivc_client *client)
{
    cli_info->port = client->port;
    cli_info->connection_id = client->connection_id;
    cli_info->client_disconnect_event = client->client_disconnect_event;
    cli_info->client_notify_event = client->client_notify_event;
    cli_info->buffer = client->buffer;
    cli_info->num_pages = client->num_pages;
    cli_info->remote_domid = client->remote_domid;
    cli_info->callback_list = client->callback_list;
    cli_info->server_side = client->server_side;
}


void
update_client(struct libivc_client_ioctl_info *cli_info, struct libivc_client *client)
{

    client->port = cli_info->port;
    client->connection_id = cli_info->connection_id;
    client->client_disconnect_event = cli_info->client_disconnect_event;
    client->client_notify_event = cli_info->client_notify_event;
    client->buffer = cli_info->buffer;
	client->num_pages = cli_info->num_pages;
    client->remote_domid = cli_info->remote_domid;
    client->callback_list = cli_info->callback_list;
    client->server_side = cli_info->server_side;
}
/**
* Initializes the function callbacks to the LINUX userspace APIs and opens the
* driver.
* @param pf The libivc core platform struct
* @return SUCCESS, or appropriate error number.
*/
int
libivc_platform_init(platform_functions_t * pf)
{
	int rc = SUCCESS;

	// check the pointer and return if NULL;
	libivc_checkp(pf, INVALID_PARAM);

	libivc_info("Initializing Windows userspace platform.\n");
	pf->connect = us_ivc_connect;
	pf->disconnect = us_ivc_disconnect;
	pf->notifyRemote = us_notify_remote;
	pf->registerServerListener = us_register_server_listener;
	pf->unregisterServerListener = us_unregister_server_listener;
	// if the driver hasn't been open, open it.
	if (driverHandle == INVALID_HANDLE_VALUE)
	{
		rc = us_openDriver();
	}
	return rc;
}

static DWORD WINAPI us_client_listen(struct libivc_client * client)
{
	HANDLE waits[2];
	DWORD waitRet = 0;
	libivc_checkp(client, INVALID_PARAM);
	libivc_checkp(client->client_disconnect_event, INVALID_PARAM);
	libivc_checkp(client->client_notify_event, INVALID_PARAM);
	list_head_t * pos = NULL, *temp = NULL;
	callback_node_t * callbacks = NULL;

	waits[0] = client->client_notify_event;
	waits[1] = client->client_disconnect_event;

	while (libivc_isOpen(client))
	{
		waitRet = WaitForMultipleObjects(2, waits, FALSE, 10);
		if (waitRet == WAIT_TIMEOUT)
		{
			continue;
		}
		else if (waitRet == WAIT_OBJECT_0 + 0)
		{
			libivc_info("Got an event.\n");
			list_for_each_safe(pos, temp, &client->callback_list)
			{
				callbacks = container_of(pos, callback_node_t, node);
				if (callbacks->eventCallback)
				{
					callbacks->eventCallback(client->opaque, client);
				}
			}
		}
		else if (waitRet == WAIT_OBJECT_0 + 1)
		{
			libivc_info("Got a disconnect event.\n");
			list_for_each_safe(pos, temp, &client->callback_list)
			{
				callbacks = container_of(pos, callback_node_t, node);
				if (callbacks->disconnectCallback)
				{
					callbacks->disconnectCallback(client->opaque, client);
					// we're disconnected, get out of Dodge.
					goto END_THREAD;
				}
			}
		}
	}
END_THREAD:
	return SUCCESS;
}


static DWORD WINAPI us_server_listener(struct libivc_server * server)
{
	DWORD retSize = 0;
	DWORD waitRet = 0;
	DWORD err;
	struct libivc_client *client = NULL;

	libivc_checkp(server, INVALID_PARAM);
	libivc_checkp(server->client_connect_event, INVALID_PARAM);

	libivc_info("Monitoring ivc server....\n");

	while (server->running)
	{
		waitRet = WaitForSingleObject(server->client_connect_event, 1000);
		if (waitRet == WAIT_OBJECT_0)
		{
			libivc_info("Got a connection.\n");
			client = (struct libivc_client *) malloc(sizeof(struct libivc_client));
			libivc_checkp(client, OUT_OF_MEM);
			memset(client, 0, sizeof(struct libivc_client));
			client->port = server->port;
			// FIXME: Should something be using the client ID / remote domid below?
			mutex_init(&client->mutex);
			INIT_LIST_HEAD(&client->callback_list);
			INIT_LIST_HEAD(&client->node);

			if (!DeviceIoControl(driverHandle, IVC_DRIVER_SERVER_ACCEPT, client, sizeof(struct libivc_client), client, sizeof(struct libivc_client), &retSize, NULL))
			{
				err = GetLastError();
				libivc_info("Failed to get new client. err = %d\n",err);
				free(client);
				client = NULL;
			}
			else
			{
				list_add(&client->node, &server->client_list);
				server->connect_cb(client, client->opaque);
			}
		}
	}
	
	return SUCCESS;
}

/**
* Sets up a listener for incoming connections from remote domains by passing down to the
* ivc driver as well as running thread to monitor events from the driver.
* @param server - server with port number set that it wants to listen on.
* @return SUCCESS, or appropriate error number.
*/
int
us_register_server_listener(struct libivc_server * server)
{
	int rc = SUCCESS;
	DWORD retSize = 0;
	HANDLE thandle;
	struct libivc_server_ioctl_info *serv_info = NULL;
	libivc_info("in %s\n", __FUNCTION__);

	// check that the pointer isn't NULL
	libivc_checkp(server, INVALID_PARAM);
	// make sure the driver is open.
	libivc_assert(driverHandle != INVALID_HANDLE_VALUE, IVC_UNAVAILABLE);
	server->client_connect_event = CreateEvent(NULL, FALSE, FALSE, NULL);
	libivc_checkp(server->client_connect_event, OUT_OF_MEM); // kind of.

	libivc_info("Registering server with driver on port %d\n", server->port);
	serv_info = (struct libivc_server_ioctl_info*) malloc(sizeof(struct libivc_server_ioctl_info));
    libivc_checkp(serv_info, OUT_OF_MEM);

	serv_info->client_connect_event = server->client_connect_event;
	serv_info->port = server->port;
	serv_info->limit_to_connection_id = server->limit_to_connection_id;
	serv_info->limit_to_domid = server->limit_to_domid;
	if (!DeviceIoControl(driverHandle, IVC_DRIVER_REG_SVR_LSNR, serv_info, sizeof(struct libivc_server_ioctl_info), serv_info,
		sizeof(struct libivc_server_ioctl_info),&retSize, NULL))
	{
			libivc_error("Failed to register server listener.\n");
			CloseHandle(server->client_connect_event);
			return ACCESS_DENIED;
	}
	server->client_connect_event = serv_info->client_connect_event;
	server->port = serv_info->port;
	server->limit_to_connection_id = serv_info->limit_to_connection_id;
	server->limit_to_domid = serv_info->limit_to_domid;
	server->running = 1;
	// launch a thread to monitor for events.
	thandle = CreateThread(NULL, 0, us_server_listener, (void*)server, 0, NULL);
	libivc_checkp(thandle, OUT_OF_MEM);
	CloseHandle(thandle);
	rc = SUCCESS;
	if (serv_info != NULL)
		free(serv_info);
	return rc;
}

/**
* Stops the connection thread and sends and ioctl to the driver to clean up the listening port.
* @param server
* @return SUCCESS or appropriate error number.
*/
int
us_unregister_server_listener(struct libivc_server * server)
{
	int rc = SUCCESS;
	DWORD retSize;
	struct libivc_server_ioctl_info *serv_info = NULL;

	libivc_checkp(server, INVALID_PARAM);
	
	server->running = 0; 
	if (server->client_connect_event)
	{
		CloseHandle(server->client_connect_event);
		server->client_connect_event = NULL;
	}
	serv_info = (struct libivc_server_ioctl_info *) malloc(sizeof(struct libivc_server_ioctl_info));
    libivc_checkp(serv_info, OUT_OF_MEM);

	serv_info->client_connect_event = server->client_connect_event;
	serv_info->port = server->port;
	serv_info->limit_to_connection_id = server->limit_to_connection_id;
	serv_info->limit_to_domid = server->limit_to_domid;
	if (!DeviceIoControl(driverHandle, IVC_DRIVER_UNREG_SVR_LSNR, server, sizeof(struct libivc_server_ioctl_info), server,
		sizeof(struct libivc_server_ioctl_info), &retSize, NULL))
	{
			libivc_error("Failed to unregister server listener.\n");
			return ACCESS_DENIED;
	}

	server->client_connect_event = serv_info->client_connect_event;
	server->port = serv_info->port;
	server->limit_to_connection_id = serv_info->limit_to_connection_id;
	server->limit_to_domid = serv_info->limit_to_domid;
	if (serv_info != NULL)
		free(serv_info);
	return rc;
}

/**
* Sends client down to driver so it can perform event notification.
* @param ivc Non null client describing IVC connection.
* @return SUCCESS or appropriate error number.
*/
int
us_notify_remote(struct libivc_client * client)
{
	DWORD retSize = 0;
	struct libivc_client_ioctl_info *cli_info = NULL;
	libivc_checkp(client, INVALID_PARAM);
	cli_info = (struct libivc_client_ioctl_info *) malloc(sizeof(struct libivc_client_ioctl_info));
	populate_cli(cli_info, client);
	if (!DeviceIoControl(driverHandle, IVC_DRIVER_NOTIFY_REMOTE, cli_info, sizeof(struct libivc_client_ioctl_info), cli_info,
		sizeof(struct libivc_client_ioctl_info), &retSize, NULL))
	{
			libivc_error("Failed to notify remote.\n");
			return ACCESS_DENIED;
	}
	update_client(cli_info, client);
	free(cli_info);
	return SUCCESS;
}

/**
* Connects the client to the remote domain
* @param client Non null pointer to client describing connection parameters.
* @return SUCCESS or appropriate error number.
*/
int
us_ivc_connect(struct libivc_client *client)
{
	int rc = INVALID_PARAM;
	DWORD retSize = 0;
	HANDLE cHandle = NULL;
	struct libivc_client_ioctl_info *cli_info = NULL;

	// make sure client is not null
	libivc_checkp(client, rc);
	client->client_disconnect_event = CreateEvent(NULL, FALSE, FALSE, NULL);
	libivc_checkp(client->client_disconnect_event, OUT_OF_MEM); // sort of.
	client->client_notify_event = CreateEvent(NULL, FALSE, FALSE, NULL);
	rc = OUT_OF_MEM;
	libivc_checkp_goto(client->client_notify_event, ERR);
	// send it down to the driver for connection
	cli_info = (struct libivc_client_ioctl_info *) malloc(sizeof(struct libivc_client_ioctl_info));
	populate_cli(cli_info, client);

	if (!DeviceIoControl(driverHandle, IVC_DRIVER_CONNECT, cli_info, sizeof(struct libivc_client_ioctl_info), cli_info,
		sizeof(struct libivc_client_ioctl_info), &retSize, NULL))
	{	
			libivc_error("Failed to connect to remote domain.\n");
			rc = ACCESS_DENIED;
			goto ERR;
	}
	update_client(cli_info, client);

	cHandle = CreateThread(NULL, 0, us_client_listen, (void *)client, 0, NULL);
	libivc_checkp(cHandle, OUT_OF_MEM);
	CloseHandle(cHandle);

	rc = SUCCESS;
	goto END;
ERR:
	if (client->client_notify_event)
	{
		CloseHandle(client->client_notify_event);
		client->client_notify_event = NULL;
	}

	if (client->client_disconnect_event)
	{
		CloseHandle(client->client_disconnect_event);
		client->client_disconnect_event = NULL;
	}
END:
	if(cli_info != NULL)
		free(cli_info);

	return rc;
}

/**
* Disconnects the client and closes event descriptors
* @param client - NON null pointer describing the connected client.
* @return SUCCESS or appropriate error number.
*/
int
us_ivc_disconnect(struct libivc_client * client)
{
	int rc = INVALID_PARAM;
	DWORD retSize;

	libivc_checkp(client, rc);
	libivc_info("Disconnecting %d:%d\n", client->remote_domid, client->port);
	if (client->client_disconnect_event)
	{
		CloseHandle(client->client_disconnect_event);
		client->client_disconnect_event = NULL;
	}

	if (client->client_notify_event)
	{
		CloseHandle(client->client_notify_event);
		client->client_notify_event = NULL;
	}


	client->buffer = NULL;

	// send it down to the driver for connection
	if (!DeviceIoControl(driverHandle, IVC_DRIVER_DISCONNECT, client, sizeof(struct libivc_client), client,
		sizeof(struct libivc_client), &retSize, NULL))
	{
		libivc_error("Failed to unregister server listener.\n");
		return ACCESS_DENIED;
	}

	return SUCCESS;
}


/**
* Windows platform specific handler to open the ivc driver and other functions needed
* to support driver callbacks.
* @return SUCCESS, or appropriate error number.
*/
int 
us_openDriver(void)
{
	int rc = SUCCESS;
	DWORD retSize = 0;

	// make sure we are not being asked to double open the driver from the same process.
	if(driverHandle == INVALID_HANDLE_VALUE)
	{
		// since the driver is going to be using the "inverted callback" method
		// for event handling, it needs to be opened in overlapped mode.
		// this is the recommended way of doing callbacks from the driver
		// per OSR.
		driverHandle = CreateFile(_T("\\\\.\\ivc"), GENERIC_READ | GENERIC_WRITE, 
			0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		// make sure we were successfull.
		if(driverHandle == NULL)
		{
			rc = GetLastError();
			printf("opening ivc driver failed with code 0x%0x\n", rc);
			rc = ACCESS_DENIED;
			driverHandle = INVALID_HANDLE_VALUE;
		}
		
	}
	return rc;
}

/**
* Windows platform specific method to close the driver and undo any operations started 
* in the us_openDriver call.
* @return SUCCESS or appropriate error message.
*/
int us_closeDriver(void)
{
	int rc = SUCCESS;
	// if the driver was opened, close it.
	if(driverHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(driverHandle);
		driverHandle = INVALID_HANDLE_VALUE;
	}

	return rc;
}

/**
* convenience call to check if driver is open.
* @return TRUE if it's open, FALSE otherwise.
*/
int us_isDriverOpen(void)
{
	return driverHandle != INVALID_HANDLE_VALUE;
}
