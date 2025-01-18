#!/usr/bin/python3
import cse303

# Configure constants and users
cse303.indentation = 80
cse303.verbose = cse303.check_args_verbose()
alice = cse303.UserConfig("alice", "alice_is_awesome")
afile1 = "solutions/err.o"
afile2 = "common/err.h"
allfile = "allfile"
k1 = "k1"
k1file1 = "solutions/net.o"
k1file2 = "server/server.cc"
k2 = "second_key"
k2file1 = "server/parsing.h"
k2file2 = "server/storage.h"
k3 = "third_key"
k3file1 = "solutions/file.o"
k3file2 = "common/pool.h"

# Create objects with server and client configuration
server = cse303.ServerConfig(
    "./obj64/server.exe", "9999", "rsa", "company.dir", "4", "1024"
)
client = cse303.ClientConfig("./obj64/client.exe", "localhost", "9999", "localhost.pub")

# Check if we should use solution server or client
cse303.override_exe(server, client)

# Set up a clean slate before getting started
cse303.line()
print("Getting ready to run tests")
cse303.line()
cse303.clean_common_files(server, client)  # .pub, .pri, .dir files
cse303.killprocs()

print()
cse303.line()
print("Test #1: REG should persist without SAV")
cse303.line()
server.pid = cse303.do_cmd_a(
    "Starting server:",
    [
        "Listening on port "
        + server.port
        + " using (key/data) = (rsa, "
        + server.dirfile
        + ")",
        "Generating RSA keys as ("
        + server.keyfile
        + ".pub, "
        + server.keyfile
        + ".pri)",
        "File not found: " + server.dirfile,
    ],
    server.launchcmd(),
)
cse303.waitfor(2)
cse303.do_cmd("Registering new user alice.", "OK__", client.reg(alice), server)
cse303.after(
    server.pid
)  # need an extra cleanup to handle the KEY that was sent by first REG
cse303.do_cmd("Stopping server.", "OK__", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)
expect_size1 = cse303.next4(4 + 4 + len(alice.name) + 4 + 16 + 4 + 32 + 4)
cse303.verify_filesize(server.dirfile, expect_size1)
server.pid = cse303.do_cmd_a(
    "Restarting server:",
    [
        "Listening on port "
        + server.port
        + " using (key/data) = (rsa, "
        + server.dirfile
        + ")",
        "Loaded: " + server.dirfile,
    ],
    server.launchcmd(),
)
cse303.waitfor(2)
cse303.do_cmd(
    "Registering new user alice.", "ERR_USER_EXISTS", client.reg(alice), server
)
cse303.do_cmd(
    "Checking alice's content.", "ERR_NO_DATA", client.getC(alice, alice.name), server
)
cse303.do_cmd("Stopping server.", "OK__", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)

print()
cse303.line()
print("Test #2: SET should persist without SAV")
cse303.line()
server.pid = cse303.do_cmd_a(
    "Restarting server:",
    [
        "Listening on port "
        + server.port
        + " using (key/data) = (rsa, "
        + server.dirfile
        + ")",
        "Loaded: " + server.dirfile,
    ],
    server.launchcmd(),
)
cse303.waitfor(2)
cse303.do_cmd("Setting alice's content.", "OK__", client.setC(alice, afile1), server)
expect_size2 = cse303.next4(
    expect_size1 + 4 + 4 + len("alice") + 4 + cse303.get_len(afile1)
)
cse303.verify_filesize(server.dirfile, expect_size2)
cse303.do_cmd("Stopping server.", "OK__", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)
server.pid = cse303.do_cmd_a(
    "Restarting server:",
    [
        "Listening on port "
        + server.port
        + " using (key/data) = (rsa, "
        + server.dirfile
        + ")",
        "Loaded: " + server.dirfile,
    ],
    server.launchcmd(),
)
cse303.waitfor(2)
cse303.do_cmd(
    "Checking alice's content.", "OK__", client.getC(alice, alice.name), server
)
cse303.check_file_result(afile1, alice.name)
cse303.do_cmd("Re-setting alice's content.", "OK__", client.setC(alice, afile2), server)
expect_size3 = cse303.next4(
    expect_size2 + 4 + 4 + len("alice") + 4 + cse303.get_len(afile2)
)
cse303.verify_filesize(server.dirfile, expect_size3)
cse303.do_cmd("Stopping server.", "OK__", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)

print()
cse303.line()