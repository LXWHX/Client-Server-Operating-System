# Build a client and server from the reference solution, but use the student's
# server/storage.cc, server/persist.cc, and  table

# The executables will have the suffix p3.persist.exe
EXESUFFIX = p3.persist.exe

# Names for building the client:
CLIENT_MAIN     = client
CLIENT_CXX      = 
CLIENT_COMMON   = 
CLIENT_PROVIDED = client requests crypto err file net my_crypto

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = my_storage persist
SERVER_COMMON   = 
SERVER_PROVIDED = server responses parsing crypto err file net my_pool \
                  my_crypto concurrentmap_factories

# All warnings should be treated as errors
CXXEXTRA = -Werror

# Pull in the common build rules
include common.mk
