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
#include <inttypes.h>
#include <stdbool.h>

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

static FILE * outfile = NULL;
static bool connected = false;
/**
 * Handle a client disconnect.
 */
void handle_client_disconnect(void *opaque, struct libivc_client *client)
{
    //Process the disconnect...
    fprintf(stderr, "Client is requesting a disconnect. Disconnecting.\n");
    libivc_disconnect(client);
    fclose(outfile);

    exit(0);
}

/**
 * Handle client events.
 */
void handle_client_event(void *opaque, struct libivc_client *client)
{
    int rc;
    size_t bytes_to_rx;
    char *rx_buffer = 0;

    //Attempt to get the amount of bytes to recieve.
    //sleep(1);
    rc = libivc_getAvailableData(client, &bytes_to_rx);
    libivc_assert(rc == SUCCESS);

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
        if (outfile != NULL) {
            if (fwrite(rx_buffer, sizeof(char), bytes_to_rx, outfile)) {
                fflush(outfile);
            }
            else {
                fprintf(stderr, "Failed to write %d bytes to file: %i.\n", bytes_to_rx, errno);
            }
        }
        else {
            fwrite(rx_buffer, sizeof(char), bytes_to_rx, stdout);
        }
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
void handle_client_connected(void *opaque, struct libivc_client *newClient)
{
    uint16_t remote_domid, remote_port;
    uint64_t remote_id;
    bool * poll = (bool *)opaque;

    if (connected) {
        fprintf(stderr, "Client attempted to connect, but this pipe is already in use!\n");
        libivc_disconnect(newClient);
        return;
    }
    else {
        connected = true;
    }

    //Gather some data from the remote client, and log it.
    libivc_getRemoteDomId(newClient, &remote_domid);
    libivc_getport(newClient,  &remote_port);
    remote_id = libivc_get_connection_id(newClient);
    fprintf(stderr, "New connection from %u on port %u; id: %d.\n", remote_domid, remote_port, (int)remote_id);

    //... and register a pair of events that should occur on each client interaction.
    if (poll && *poll) {
        libivc_register_event_callbacks(newClient, NULL, NULL, NULL);
        client_poll(newClient);
    }
    else {
        libivc_register_event_callbacks(newClient, handle_client_event, handle_client_disconnect, NULL);
        libivc_enable_events(newClient);
    }
}

//32 pages should be enough. I hope.
#define BUFSIZE 32*4096

//Runs for as long as the client is connected.
int client_poll(struct libivc_client * client) {

    int rc, bytes_to_rx;
    char * rx_buffer;

    rx_buffer = (char *)malloc(BUFSIZE);

    while(1) {
        if (!libivc_isOpen(client)) {
            fprintf(stderr, "Disconnect detected. Closing...\n");
            break;
        }

        rc = libivc_getAvailableData(client, &bytes_to_rx);
        if (rc != SUCCESS) {
            fprintf(stderr, "Couldn't get available data: %i\n", rc);
            break;
        }
    
        if(!bytes_to_rx) {
            usleep(10000);
            continue;
        }
        else {
            //printf("%d bytes available.\n", bytes_to_rx);
        }
    
        //Receive the collection of available bytes.
        memset(rx_buffer, 0, BUFSIZE);
        rc = libivc_recv(client, rx_buffer, bytes_to_rx);
        if(rc == SUCCESS) {
            if (outfile != NULL) {
                if (fwrite(rx_buffer, sizeof(char), bytes_to_rx, outfile)) {
                    fflush(outfile);
                    //printf("Wrote %d bytes to file.\n", bytes_to_rx);
                }
                else {
                    fprintf(stderr, "Failed to write %d bytes to file: %i.\n", bytes_to_rx, errno);
                }
            }
            else {
                fwrite(rx_buffer, sizeof(char), bytes_to_rx, stdout);
            }
        }
        else {
            fprintf(stderr, "Error! Failed to read from the target!");
        }
    }

    free(rx_buffer);
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

void usage(char * argv0) {
    fprintf(stderr, "Usage: %s [-p port] [-i connectionID] [-f file] [-P]\n", argv0);
}
/**
 * Set up the main pipe server.
 */
int main(int argc, char *argv[])
{
    char * path;
    int i, rc, read_count = 0;
    char flag;
    uint64_t connection_id = LIBIVC_ID_ANY;
    uint16_t port = 10;
    bool use_default_connection_id = true;
    bool poll = false;


    for (i = 1; i < argc; i++) {
        read_count = sscanf(argv[i], "-%c", &flag);
        i++;
        if (read_count > 0 && (i <= argc)) {
            switch(flag) {
            case 'p':
                read_count = sscanf(argv[i], "%" PRIu16, &port);
                if (read_count < 1)
                    fprintf(stderr, "-p expects a uint16.\n");
                break;
            case 'i':
                read_count = sscanf(argv[i], "%" PRIu64, &connection_id);
                if (read_count < 1)
                    fprintf(stderr, "-i expects an int64\n.");
                else
                    use_default_connection_id = false;
                break;
            case 'f':
                outfile = fopen(argv[i], "wb");
                if (!outfile)
                    fprintf(stderr, "Couldn't open %s.", argv[i]);
                break;
            case 'P':
                poll = true;
                i--;
                break;
            default:
                fprintf(stderr, "Invalid flag: -%c\n", flag);
                read_count = 0;
            }
            if (read_count < 1) {
                usage(argv[0]);
                exit(-1);
            }
        }
    }
    //wat
    if (use_default_connection_id) {
        connection_id = LIBIVC_ID_ANY;
    }

    fprintf(stderr, "Listening for connections on port %" PRIu16 " from connection ID %" PRIu64 " in %s mode.\n", port, connection_id, poll ? "polling" : "non-polling");

    //Start the main IVC server.
    rc = libivc_start_listening_server(&server, port, LIBIVC_DOMID_ANY, 
        connection_id, handle_client_connected, &poll);

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
