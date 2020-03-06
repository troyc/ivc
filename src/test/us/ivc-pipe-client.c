/**
 * IVC Example Code: Pipe Client
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
#include <inttypes.h>

/**
 * Stores data about the currently active IVC client connection.
 */
static struct libivc_client *client = 0;

/**
 * The port to use for IVC communications. In many cases, this would be autonegotiated,
 * rather than fixed, as it is here.
 */
static const int ivc_port = 10;


/**
 * The remote domid to connect to.
 */
static int remote_domid = 0;


/**
 * Clean up the server. Typically called when the user attempts to interrupt this program
 * with CTRL+C.
 */
void clean_up_client()
{
    libivc_disconnect(client);
}


/**
 * Handle a client disconnect.
 */
void handle_client_disconnect(void *opaque, struct libivc_client *client)
{
    //Process the disconnect...
    fprintf(stderr, "Server has disconnected. Now would be a good time to send SIGUSR1.\n");
}

/**
 * Handle client events.
 */
void handle_client_event(void *opaque, struct libivc_client *client)
{
    fprintf(stderr, "Received an event from the other side -- unexpected!\n");
}

/**
 * Handle a signal that would normally terminate this application,
 * such as if the user presses CTRL+C, sending SIGINT.
 */
void handle_interrupt_signal(int raised_signal)
{
    //Perform the core server cleanup...
    clean_up_client();

    //... restore the original signal handler...
    signal(raised_signal, SIG_DFL);

    //... and re-raise it, allowing the application to terminate itself.
    raise(raised_signal);
}

void attempt_reconnect(int raised_signal)
{   
    int rc;

    if(!client)
        return;

    printf("Attempting reconnect to domain %d...\n", remote_domid);

    //Finally, connect to the remote server, if possible.
    rc = libivc_reconnect(client, remote_domid, ivc_port);

    if(rc != SUCCESS)
        printf("Failed to connect to the remote server: %s\n", strerror(rc));
    else 
        printf("Reconnected!\n");

}

void usage()
{
    printf("Usage: ivc-pipe-client <dom-id> <pages> [<connection-id>]\n\n");
}

/**
 * Core utility which reads from the stdin and pipes the data to the other VM.
 */
void read_and_send()
{
    static char buffer[32];
    int bytes_to_tx = sizeof(buffer);
    size_t available_space;
    int rc;

    //Read the total amount of space available in the buffer.
    rc = libivc_getAvailableSpace(client, &available_space);
    libivc_assert(rc == SUCCESS);

    //If there's no space available, don't read during this iteration.
    if(!available_space)
    {
        return;
    }

    //If there's not enough space in the buffer to transmit the desired
    //buffer, trim down the desired read size.
    if(available_space < bytes_to_tx)
    {
        bytes_to_tx = available_space;
    }

    //Attempt to read a block of bytes from the standard input.
    //If we read less than the desired read size, trim down the amount to send.
    bytes_to_tx = fread(buffer, sizeof(char), bytes_to_tx, stdin);

    //If we don't yet have any bytes to transmit, return.
    if(!bytes_to_tx)
    {
        return;
    }

    //Attempt to send the given block of bytes...
    rc = libivc_send(client, buffer, bytes_to_tx);
    printf("Sent %d bytes\n", bytes_to_tx);
    libivc_assert(rc == SUCCESS);
}


/**
 * Set up the main pipe server.
 */
int main(int argc, char *argv[])
{
    int rc, read_count = 0;
    int pages_to_share = 1;
    int64_t connection_id;

    //If we have a connection ID, use it!
    if(argc == 4)
    {
        read_count = sscanf(argv[3], "%" SCNu64, &connection_id);
    }
    //Otherwise, if we have valid other arguments, use NONE.
    else if(argc == 3)
    {
        connection_id = LIBIVC_ID_NONE;
        read_count = 1;
    }

    //If we didn't determine a connection ID, print the usage.
    if(!read_count)
    {
        usage();
        return EINVAL;
    }

    //Attempt to read the remote domain ID from our command line argument.
    read_count = sscanf(argv[1], "%d", &remote_domid);
    if(read_count != 1)
    {
        usage();
        return EINVAL;
    }

    //And attmept to read the number of pages to share.
    read_count = sscanf(argv[2], "%d", &pages_to_share);
    if(read_count != 1)
    {
        usage();
        return EINVAL;
    }

    printf("Establishing connection to domain %d from connection ID %" PRIu64 ".\n", remote_domid, connection_id);

    //Finally, connect to the remote server, if possible.
    rc = libivc_connect_with_id(&client, remote_domid, ivc_port, pages_to_share, connection_id);

    if(rc != SUCCESS)
    {
        printf("Failed to connect to the remote server: %s\n", strerror(rc));
        return rc;
    }

    //Register event handlers.
    libivc_register_event_callbacks(client, handle_client_event, handle_client_disconnect, NULL);

    //On application termination, clean up our server.
    signal(SIGINT, handle_interrupt_signal);
    signal(SIGTERM, handle_interrupt_signal);
    signal(SIGUSR1, attempt_reconnect);

    printf("Send a SIGUSR1 at any time to stimulate a reconnect.\n");

    while(1)
    {
        read_and_send();
    }

    return 0;
}
