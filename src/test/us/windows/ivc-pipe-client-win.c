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

#define RECIPROCATE_CHANNEL 1

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
 * The number of pages that should be shared with the receving server.
 */
static int pages_to_share = 1;


/**
 * Clean up the server. Typically called when the user attempts to interrupt this program
 * with CTRL+C.
 */
void clean_up_client()
{
    libivc_disconnect(client);
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


//int libivc_connect(struct libivc_client ** ivc, uint16_t remote_dom_id, uint16_t remote_port, uint32_t numPages, uint8_t channeled, SHARE_TYPE_T shareType);

void usage()
{
    printf("Usage: ivc-pipe-client <dom-id> <pages>\n\n");
}

/**
 * Core utility which reads from the stdin and pipes the data to the other VM.
 */
void read_and_send()
{
    static char buffer[32];
    size_t bytes_to_tx = sizeof(buffer);
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
    //bytes_to_tx = fread(buffer, sizeof(char), bytes_to_tx, stdin);
	for (int i = 0; i < 31; i++){
		buffer[i] = 'a';
	}
	buffer[31] = '\n';
	bytes_to_tx = 32;
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

void handle_disconnect(struct libivc_client * client)
{
	printf("Disconnected!");
}


void test_func(struct libivc_client * client)
{
	printf("Yippie we did the thing.\n");
}
/**
 * Set up the main pipe server.
 */
int main(int argc, char *argv[])
{
    int rc, read_count, remote_domid;

    if(argc != 3)
    {
        usage();
        return EINVAL;
    }

    //Attempt to read the remote domain ID from our command line argument.
    read_count = sscanf_s(argv[1], "%d", &remote_domid);
    read_count = sscanf_s(argv[2], "%d", &pages_to_share);

    //If we couldn't, display the usage and exit.
    if(read_count != 1)
    {
        usage();
        return EINVAL;
    }

    printf("Establishing connection to remote domain %d.\n", remote_domid);

    //Finally, connect to the remote server, if possible.
    rc = libivc_connect(&client, remote_domid, ivc_port, pages_to_share, RECIPROCATE_CHANNEL, GRANT_REF_SHARE);
	libivc_register_event_callbacks(client, test_func, handle_disconnect);
	printf("Got connected!\n");

    if(rc != SUCCESS)
    {
        printf("Failed to connect to the remote server: %d\n", rc);
        return rc;
    }

    //On application termination, clean up our server.
	read_and_send();
	for (int i = 0; i < 100; i++) {
		Sleep(30000);
	}
	clean_up_client();
    return 0;
}
