/**
 * Server side of the binary networking example.
 *
 * In our binary networking protocol, the client sends a number twice in a
 * single message, and the server increments the number and sends it back twice.
 * If the client sends a zero, it means the communication is over.  If the
 * client sends a -1, it means the server should shut down.
 */
#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <errno.h>
#include <libgen.h>
#include <string>
#include <sys/time.h>
#include <unistd.h>

/**
 * Display a help message to explain how the command-line parameters for this
 * program work
 *
 * @progname The name of the program
 */
void usage(char *progname) {
  printf("%s: Server half of a client/server program to demonstrate "
         "sending binary data over a network.\n",
         basename(progname));
  printf("  -p [int]    Port number of the server\n");
  printf("  -h          Print help (this message)\n");
}

/** arg_t is used to store the command-line arguments of the program */
struct arg_t {
  /** The port on which the program will listen for connections */
  size_t port = 0;

  /** Is the user requesting a usage message? */
  bool usage = false;
};

/**
 * Parse the command-line arguments, and use them to populate the provided args
 * object.
 *
 * @param argc The number of command-line arguments passed to the program
 * @param argv The list of command-line arguments
 * @param args The struct into which the parsed args should go
 */
void parse_args(int argc, char **argv, arg_t &args) {
  long opt;
  while ((opt = getopt(argc, argv, "p:h")) != -1) {
    switch (opt) {
    case 'p':
      args.port = atoi(optarg);
      break;
    case 'h':
      args.usage = true;
      break;
    }
  }
}

int main(int argc, char *argv[]) {
  // parse the command line arguments
  arg_t args;
  parse_args(argc, argv, args);
  if (args.usage) {
    usage(argv[0]);
    exit(0);
  }

  // Set up the server socket for listening.  This will exit the program on
  // any error.
  int serverSd = create_server_socket(args.port);

  // We will keep going until we get a client who sends a -1 as its first
  // value
  bool keep_going = true;
  while (keep_going) {
    // use accept() to wait for a client to connect
    printf("Waiting for a client to connect...\n");
    sockaddr_in clientAddr;
    socklen_t clientAddrSize = sizeof(clientAddr);
    int connSd = accept(serverSd, (sockaddr *)&clientAddr, &clientAddrSize);
    if (connSd < 0) {
      close(serverSd);
      error_message_and_exit(0, errno, "Error accepting request from client: ");
    }
    char clientname[1024];
    printf("Connected to %s\n", inet_ntop(AF_INET, &clientAddr.sin_addr,
                                          clientname, sizeof(clientname)));
    // NB: binary_server closes the connection before returning
    keep_going = binary_server(connSd);
  }
  close(serverSd);
  return 0;
}

/**
 * Receive binary integers over the network, increment them, and send them back.
 * Exit upon receiving a zero.  Return false upon receiving a -1.
 *
 * @param sd The socket file descriptor to use for the binary data server
 */
bool binary_server(int sd) {
  // vars for tracking connection duration, round trips
  int round_trips = 0;
  struct timeval start_time, end_time;
  gettimeofday(&start_time, nullptr);

  // We'll use C streams (i.e., FILE*) instead of raw reads/writes.
  // We will also use binary I/O here, not text I/O.  Note that we still need to
  // handle errors.  Also note that FILE* is a bad choice for nonblocking I/O,
  // but we're not doing that yet :)
  FILE *socket = fdopen(sd, "r+b");

  // read data for as long as there is data, and act on it
  while (true) {
    // Get the data from the client
    int data[2] = {0, 0};
    int num_remain = 2;
    int *next_xmit = data;
    while (num_remain) {
      size_t recd = fread(next_xmit, sizeof(int), 2, socket);
      if (recd > 0) {
        // we received some data
        num_remain -= recd;
        next_xmit += recd;
      } else if (feof(socket)) {
        // Remote end of socket was closed, so terminate
        fclose(socket);
        return true;
      } else if (ferror(socket)) {
        // If the error wasn't EINTR, then terminate
        if (errno != EINTR) {
          perror("binary_server::fread()");
          clearerr(socket);
          fclose(socket);
          return true;
        }
      }
    }

    // validate the data
    assert(data[0] == data[1]);

    // On -1, terminate
    if (data[0] == -1) {
      fclose(socket);
      return false;
    }

    // On 0, close this client and wait for another
    if (data[0] == 0) {
      gettimeofday(&end_time, nullptr);
      printf("Completed %d increments in %ld seconds\n", round_trips,
             (end_time.tv_sec - start_time.tv_sec));
      fclose(socket);
      return true;
    }

    // prepare response by incrementing
    for (int i = 0; i < 2; ++i) {
      ++data[i];
    }

    // now transmit to client
    num_remain = 2;
    int *next_write = data;
    while (num_remain) {
      size_t sent = fwrite(next_write, sizeof(int), 2, socket);
      if (sent > 0) {
        // we sent some data!
        num_remain -= sent;
        next_write += sent;
      } else if (feof(socket)) {
        // Remote end of socket was closed, so terminate
        fclose(socket);
        return true;
      } else if (ferror(socket)) {
        // Terminate unless EINTR
        if (errno != EINTR) {
          perror("binary_server::fwrite()");
          clearerr(socket);
          fclose(socket);
          return true;
        }
      }
    }
    round_trips++;
  }
}