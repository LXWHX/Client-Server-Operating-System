# Build a client and server that use the reference solution for anything related
# to encryption/decryption.

# The executables will have the suffix p1.nocrypt.exe
EXESUFFIX = p1.nocrypt.exe

# Names for building the client
CLIENT_MAIN     = client
CLIENT_CXX      = client
CLIENT_COMMON   = err file net
CLIENT_PROVIDED = crypto requests my_crypto

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = server responses my_storage sequentialmap_factories
SERVER_COMMON   = err file net
SERVER_PROVIDED = parsing crypto my_crypto

# All warnings should be treated as errors
CXXEXTRA = -Werror

# Pull in the common build rules
include common.mk