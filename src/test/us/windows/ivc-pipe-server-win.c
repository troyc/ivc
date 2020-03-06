/**
 * IVC Example Code: Pipe Server
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Kyle J. Temkin <temkink@ainfosec.com>
 *
 * This simple example server listens for data from any remote domain, and prints
 * it to the standard out. It is meant to illustrate a simple libivc connection.
 */

#include <stdio.h>
#include <libivc.h>
#include <signal.h>

#define RECIPROCATE_CHANNEL 1

/**
 * Holds a reference to the current IVC server object, which is used to
 * receive communications.
 */
static struct libivc_server *server = 0;

/**
 * The port to use for IVC communications. In many cases, this would be autonegotiated,
 * rather than fixed, as it is here.
 */
static const int ivc_port = 10;

/**
 * Handle a client disconnect.
 */
void handle_client_disconnect(struct libivc_client *client)
{
    //Process the disconnect...
    fprintf(stderr, "Client is requesting a disconnect. Disconnecting.\n");
    libivc_disconnect(client);
}

/**
 * Handle client events.
 */
void handle_client_event(struct libivc_client *client)
{
    int rc;
    size_t bytes_to_rx;
    char *rx_buffer = 0;

    //Attempt to get the amount of bytes to recieve.
#ifdef __linux
    sleep(1);
#else
	Sleep(1);
#endif
    rc = libivc_getAvailableData(client, &bytes_to_rx);
    libivc_assert(rc == SUCCESS);

    printf("available data %d\n", bytes_to_rx);

    //If we have no data to recieve, bail out; we'll
    //recieve it on the next event.
    if(!bytes_to_rx)
    {
        return;
    }

    //Try to allocate a buffer sized for recieve.
    rx_buffer = malloc(bytes_to_rx);
    libivc_checkp(rx_buffer);

    //Recieve the collection of available bytes.
    rc = libivc_recv(client, rx_buffer, bytes_to_rx);

    //If all went well, print the recieved data to the stdout.
    if(rc == SUCCESS)
    {
        fwrite(rx_buffer, sizeof(char), bytes_to_rx, stdout);
    }

    //Otherwise, let the user know.
    else
    {
        fprintf(stderr, "Error! Failed to read from the target!");
    }

    free(rx_buffer);
}


/**
 * Handle an asychronous client connection.
 */
void handle_client_connected(struct libivc_client *newClient)
{
    uint16_t remote_domid, remote_port;

    //Gather some data from the remote client, and log it.
    libivc_getRemoteDomId(newClient, &remote_domid);
    libivc_getPortNumber(newClient,  &remote_port);
    fprintf(stderr, "New connection from %u on port %u.\n", remote_domid, remote_port);

    //... and register a pair of events that should occur on each client interaction.
    libivc_register_event_callbacks(newClient, handle_client_event, handle_client_disconnect);

    libivc_enable_events(newClient);
}

/**
 * Clean up the server. Typically called when the user attempts to interrupt this program
 * with CTRL+C.
 */
void clean_up_server()
{
    libivc_shutdownIvcServer(server);
}


/**
 * Handle a signal that would normally terminate this application,
 * such as if the user presses CTRL+C, sending SIGINT.
 */
void handle_interrupt_signal(int raised_signal)
{
    //Perform the core server cleanup...
    clean_up_server();

    //... restore the original signal handler...
    signal(raised_signal, SIG_DFL);

    //... and re-raise it, allowing the application to terminate itself.
    raise(raised_signal);
}


/**
 * Set up the main pipe server.
 */
int main(int argc, char *argv[])
{
    int rc;

    //Start the main IVC server.
    rc = libivc_startIvcServer(&server, ivc_port, RECIPROCATE_CHANNEL, handle_client_connected);

    //Start the main IVC server.
    rc = libivc_startIvcServer(&server, ivc_port+1, RECIPROCATE_CHANNEL, handle_client_connected);

    //Start the main IVC server.
    rc = libivc_startIvcServer(&server, ivc_port+2, RECIPROCATE_CHANNEL, handle_client_connected);

    //Start the main IVC server.
    rc = libivc_startIvcServer(&server, ivc_port+3, RECIPROCATE_CHANNEL, handle_client_connected);

    //Start the main IVC server.
    rc = libivc_startIvcServer(&server, ivc_port+4, RECIPROCATE_CHANNEL, handle_client_connected);


    if(rc)
    {
        fprintf(stderr, "Unable to start the IVC server: %s\n", strerror(rc));
        exit(rc);
    }

    //On application termination, clean up our server.
    signal(SIGINT, handle_interrupt_signal);
    signal(SIGTERM, handle_interrupt_signal);

    //Wait forever, allowing our events full control.
    while(1);

    return 0;
}
