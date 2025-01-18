# Build a client and server from the reference solution, but use the student's
# server/parsing.cc and client/requests.cc.

# The executables will have the suffix p1.rsa.exe
EXESUFFIX = p1.rsa.exe

# Names for building the client
CLIENT_MAIN     = client
CLIENT_CXX      = requests
CLIENT_COMMON   = # no common/*.cc files needed for this build
CLIENT_PROVIDED = client crypto err file net my_crypto

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = parsing 
SERVER_COMMON   = # no common/*.cc files needed for this build
SERVER_PROVIDED = server responses my_storage  sequentialmap_factories \
                  crypto err file net my_crypto

# All warnings should be treated as errors
CXXEXTRA = -Werror

# Pull in the common build rules
include common.mk
