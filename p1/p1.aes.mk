# Build a client and server from the reference solution, but use the student's
# crypto.cc.

# The executables will have the suffix p1.aestest.exe
EXESUFFIX = p1.aes.exe

# Names for building the client:
CLIENT_MAIN     = client
CLIENT_CXX      = 
CLIENT_COMMON   = my_crypto
CLIENT_PROVIDED = client requests err file net crypto

# Names for building the server:
SERVER_MAIN     = server
SERVER_CXX      = 
SERVER_COMMON   = my_crypto
SERVER_PROVIDED = server responses parsing my_storage sequentialmap_factories \
                  err file net crypto

# All warnings should be treated as errors
CXXEXTRA = -Werror

# Pull in the common build rules
include common.mk