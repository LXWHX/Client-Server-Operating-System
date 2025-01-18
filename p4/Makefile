# Build a client and server using the student's files

# The executables will have the suffix .exe
EXESUFFIX = exe

# Names for building the client:
CLIENT_MAIN     = client
CLIENT_CXX      = 
CLIENT_COMMON   = 
CLIENT_PROVIDED = crypto err file net my_crypto client requests

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = server my_quota_tracker my_mru my_gatekeeper
SERVER_COMMON   = crypto err file net
SERVER_PROVIDED = responses parsing storage persist concurrentmap_factories \
                  my_pool my_crypto storage

# NB: This Makefile does not add extra CXXFLAGS

# Pull in the common build rules
include common.mk
