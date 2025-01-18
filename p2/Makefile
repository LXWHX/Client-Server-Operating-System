# Build a client and server using the student's files

# The executables will have the suffix .exe
EXESUFFIX = exe

# Names for building the client:
CLIENT_MAIN     = client
CLIENT_CXX      =
CLIENT_COMMON   = crypto err file net
CLIENT_PROVIDED = my_crypto client requests

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = server my_storage concurrentmap_factories
SERVER_COMMON   = crypto err file net my_pool
SERVER_PROVIDED = responses parsing my_crypto

# Names for building the benchmark executable
BENCH_MAIN   = bench
BENCH_CXX    = bench

# NB: This Makefile does not add extra CXXFLAGS

# Pull in the common build rules
include common.mk