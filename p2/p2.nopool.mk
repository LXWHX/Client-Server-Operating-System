# Build a client and server from the reference solution, but use the student's
# concurrenttable and server/storage.cc.

# The executables will have the suffix p2.nopool.exe
EXESUFFIX = p2.nopool.exe

# Names for building the client
CLIENT_MAIN     = client
CLIENT_CXX      = 
CLIENT_COMMON   = 
CLIENT_PROVIDED = client crypto err file net requests my_crypto

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = concurrentmap_factories my_storage
SERVER_COMMON   = 
SERVER_PROVIDED = server responses \
                  crypto err file net my_pool parsing my_crypto

# All warnings should be treated as errors
CXXEXTRA = -Werror

# Pull in the common build rules
include common.mk
