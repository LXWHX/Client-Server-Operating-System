# Build a client and server from the reference solution, but use the student's
# mru tracker

# The executables will have the suffix p4.mru.exe
EXESUFFIX = p4.mru.exe

# Names for building the client:
CLIENT_MAIN     = client
CLIENT_CXX      = 
CLIENT_COMMON   = 
CLIENT_PROVIDED = client requests crypto err file net my_crypto

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = my_gatekeeper my_mru
SERVER_COMMON   = 
SERVER_PROVIDED = server responses parsing concurrentmap_factories storage \
                  my_quota_tracker crypto my_crypto err file net my_pool persist

# All warnings should be treated as errors
CXXEXTRA = -Werror

# Pull in the common build rules
include common.mk
