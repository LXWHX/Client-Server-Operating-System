# Build a client and server from the reference solution, but use the student's
# server/storage.cc and server/sequentialhashtable_impl.h.

# The executables will have the suffix p1.file.exe.
EXESUFFIX = p1.file.exe

# Names for building the client:
CLIENT_MAIN     = client
CLIENT_CXX      = 
CLIENT_COMMON   = 
CLIENT_PROVIDED = client crypto err file net requests my_crypto

# Names for building the server:
SERVER_MAIN     = server
SERVER_CXX      = my_storage sequentialmap_factories
SERVER_COMMON   = 
SERVER_PROVIDED = server responses parsing crypto err file net my_crypto

# All warnings should be treated as errors
CXXEXTRA = -Werror

# Pull in the common build rules
include common.mk