# Assignment #1: Creating a Secure On-Line Service

The purpose of this assignment is to get you thinking about how to compose
different security concepts to create an on-line service with authentication and
encryption.

## Do This First

Immediately after pulling `p1` from Bitbucket, you should start a container,
navigate to the `p1` folder, and type `chmod +x solutions/*.exe`.  This command
only needs to be run once.  It will make sure that certain files from the
assignment have their executable bit set.

## Assignment Overview

During the warm-up assignment, you reviewed many concepts:

- How to load a file from disk as a byte stream
- How to send byte streams to disk as new files
- How to use RSA and AES encryption
- How to send and receive bytes over the network

In this assignment, you will start putting those ideas together to build an
on-line service.

As with any service, you will make two separate programs: a client and a server.
For now, the server will only handle authentication.  The server will manage a
"directory" of users.  Each user can store up to 1MB of data as their "profile
file".

The focus of this assignment is on security, specifically two goals:

- Users should not be able to make unauthorized accesses.  You will need to
  implement a registration mechanism by which users can get an account on the
  system. A user will have permission to read any other user's profile file, and
  to get a list of all user names.  A user will also have permission to change
  her/his own profile file.
- Communication between the client and server must be secure.  Any intermediary
  who intercepts a transmission should not be able to decipher it to figure out
  what is being communicated.  Note that this is not "encryption at rest",
  because you will not storing encrypted data on the server's disk, but it is
  "end to end" encryption. When you have finished this assignment, you should
  have a good sense for what additional effort it would take to achieve
  encryption at rest.

In this assignment, you should not worry about security.  However, you will need
to implement a rudimentary form of persistence where the client can instruct the
server to save all of its data to disk.  This is not a great long-term strategy,
but it will be sufficient for now... and it makes it easier to test your code
and make sure it is behaving correctly.

## The Communication Protocol

The main source of complexity and difficulty in this assignment relates to
understanding the communication protocol and implementing it correctly.  In the
following subsections you can find a discussion of the basic connection
strategy, the encryption policy, and the message request/response formats.

### Connections

Every interaction between a client and server begins with the client initiating
a connection to the server and sending a request message.  The server sends a
response message, and then closes the connection.  To keep things simple, there
is no re-use of connections.  The server should send a response to every message
it receives.

### Encryption

The basic strategy for the protocol is similar to how PGP and other end-to-end
encryption systems work:

- The server will have a public RSA key and a private RSA key
- Clients will be able to get the server's public RSA key
- Client requests will include a newly-generated AES key along with data
  describing the request
- Client requests will be encrypted with the server's public key
- Responses from the server will be encrypted with the AES key that was provided
  by the client who made the request

There is a problem with this approach, however: RSA encryption and decryption
are slow.  Your protocol will differ slightly:

- Every request will begin with a small, fixed-size block that is encrypted with
  RSA.  This block will include the per-connection AES key.
- If a request cannot fit entirely in the fixed-size block, then a second,
  variable-sized block will also be sent.  It will be encrypted via the AES key.

Note that the two blocks should be sent "all at once", so that they appear to be
a single request.

### Types of Requests and Responses

In the discussion below, the `.` operator indicates concatenation (for example,
`"A"."B" == "AB"`).  `@0` is the binary representation of the number 0 in 32
bits.  The function `rsa(x, kr)` indicates that `x` should be encrypted using
the server's public RSA key `kr`.  The function `aes(x, ka)` indicates that `x`
should be encrypted using AES key `ka`. `len(x)` indicates the length of `x`, as
a 32-bit binary value. `pad0(x,y)` indicates that `x` should be padded to a
length of `y` bytes by appending (binary) zeroes.  It is assumed that `rsa(x)`
will pad `x` to a length 256 bytes, by appending random values that are produced
by a cryptographically secure random number generator. For this to work, OpenSSL
requires `len(x) <= 128`.

#### `KEY_`

- Purpose:  Request the server's public key (`@pubkey`)
- Request Format: `pad0("KEY_", 256)`
- Response Formats:
  - `@pubkey` -- The server responds with its 451-byte public key
- Errors: N/A

#### `REG_`

- Purpose:  Attempt to register a new user
- Arguments:
  - @u -- The requested user name (max length 32 bytes)
  - @p -- The requested password (max length 32 bytes)
  - @ka -- A newly-generated AES key (48 bytes)
- Request Format: `rsa("REG_".@ka.len(@u).len(@p).@0.@u.@p)`
- Response Formats:
  - `aes(OK__, @ka)`  -- The request succeeded
  - `ERR_CRYPTO`      -- The server could not decrypt the request
  - `aes(@err, @ka)`  -- The server was unable to process the request
- Errors (`@err`):
  - `ERR_USER_EXISTS` -- The requested user already exists
  - `ERR_REQUEST_FMT` -- The arguments to the request were not valid

#### `EXIT`

- Purpose:  Force the server to stop.  This can only be requested by a valid
  user.  Note that a real server should never let an arbitrary client cause it
  to stop.  This is a convenience request to help with debugging, testing, and
  grading.
- Arguments:
  - @u -- The user's name (max length 32 bytes)
  - @p -- The user's password (max length 32 bytes)
  - @ka -- A newly-generated AES key (48 bytes)
- Request Format: `rsa("EXIT".@ka.len(@u).len(@p).@0.@u.@p)`
- Response Formats:
  - `aes(OK__, @ka)`  -- The request succeeded
  - `ERR_CRYPTO`      -- The server could not decrypt the request
  - `aes(@err, @ka)`  -- The server was unable to process the request
- Errors (`@err`):
  - `ERR_LOGIN`       -- `@u` is not a valid user
  - `ERR_LOGIN`       -- `@p` is not the correct password for user `@u`
  - `ERR_REQUEST_FMT` -- The arguments to the request were not valid

#### `SAVE`

- Purpose: Force the server to send all its data to disk.  This can only be
  requested by a valid user.  Note that a real server should never let an
  arbitrary client cause it to stop.  This is a convenience request to help with
  debugging, testing, and grading.
- Arguments:
  - @u -- The user's name (max length 32 bytes)
  - @p -- The user's password (max length 32 bytes)
  - @ka -- A newly-generated AES key (48 bytes)
- Request Format: `rsa("SAVE".@ka.len(@u).len(@p).@0.@u.@p)`
- Response Formats:
  - `aes(OK__, @ka)`  -- The request succeeded
  - `ERR_CRYPTO`      -- The server could not decrypt the request
  - `aes(@err, @ka)`  -- The server was unable to process the request
- Errors (`@err`):
  - `ERR_LOGIN`       -- `@u` is not a valid user
  - `ERR_LOGIN`       -- `@p` is not the correct password for user `@u`
  - `ERR_REQUEST_FMT` -- The arguments to the request were not valid

#### `SETP`

- Purpose: Update a user's "profile file".  Note that a user can only change
  their own profile file.
- Arguments:
  - @u -- The user's name (max length 32 bytes)
  - @p -- The user's password (max length 32 bytes)
  - @f -- The bytes of data representing the new "profile file" (max length 1MB)
  - @ka -- A newly-generated AES key (48 bytes)
- Temporaries:
  - `@b = aes(len(@f).@f)`
- Request Format: `rsa("SETP".@ka.len(@u).len(@p).len(@b).@u.@p).@b`
- Response Formats:
  - `aes(OK__, @ka)`  -- The request succeeded
  - `ERR_CRYPTO`      -- The server could not decrypt the request
  - `aes(@err, @ka)`  -- The server was unable to process the request
- Errors (`@err`):
  - `ERR_LOGIN`       -- `@u` is not a valid user
  - `ERR_LOGIN`       -- `@p` is not the correct password for user `@u`
  - `ERR_REQUEST_FMT` -- The arguments to the request were not valid

#### `GETP`

- Purpose: Get a user's "profile file".  Note that a user can request the
  profile file for any user.
- Arguments
  - @u -- The user's name (max length 32 bytes)
  - @p -- The user's password (max length 32 bytes)
  - @w -- The name of the user whose file is being requested (max length 32
    bytes)
  - @ka -- A newly-generated AES key (48 bytes)
- Temporaries:
  - `@b = aes(len(@w).@w)`
  - @k -- The profile file for user @w, if @w is a valid user
- Request Format: `rsa("GETP".@ka.len(@u).len(@p).len(@b).@u.@p).@b`
- Response Formats:
  - `aes(OK__.len(@k).@k, @ka)` -- The request succeeded
  - `ERR_CRYPTO`      -- The server could not decrypt the request
  - `aes(@err, @ka)`  -- The server was unable to process the request
- Errors (`@err`):
  - `ERR_LOGIN`       -- `@u` is not a valid user
  - `ERR_LOGIN`       -- `@p` is not the correct password for user `@u`
  - `ERR_NO_USER`     -- `@w` is not a valid user
  - `ERR_NO_DATA`     -- `@w` has a null profile file
  - `ERR_REQUEST_FMT` -- The arguments to the request were not valid

#### `ALL_`

- Purpose: Get a newline-delimited list of the names of all the users.  The list
  will not be sorted, and it will not have a trailing newline.
- Arguments
  - @u -- The user's name (max length 32 bytes)
  - @p -- The user's password (max length 32 bytes)
  - @ka -- A newly-generated AES key (48 bytes)
- Temporaries:
  - @l -- The newline-delimited list of user names
- Request Format: `rsa("ALL_".@ka.len(@u).len(@p).@0.@u.@p)`
- Response Formats:
  - `aes(OK__.len(@l).@l, @ka)` -- The request succeeded
  - `ERR_CRYPTO`      -- The server could not decrypt the request
  - `aes(@err, @ka)`  -- The server was unable to process the request
- Errors (`@err`):
  - `ERR_LOGIN`       -- `@u` is not a valid user
  - `ERR_LOGIN`       -- `@p` is not the correct password for user `@u`
  - `ERR_REQUEST_FMT` -- The arguments to the request were not valid

## Authentication

Your server is required to implement a reasonable password-based authentication.
You should never store passwords as clear text.  Instead, you should hash the
user's password, and save it.  Similarly, you should never hash passwords
directly.  Instead, you should salt the password and hash the result.  Note that
it is sufficient to append the salt to the user's password.

In this assignment, we will use a 16-byte salt, and we will use the SHA-256
algorithm as our hashing algorithm.  Note that while SHA-256 is a strong hash
(it is not easy to reverse), it is not a great hashing algorithm for passwords,
because it is *too fast*, and thus easier to attack via brute-force methods.

## The File Format

Your server will have a single hash table that needs to be persisted to a file:
the "authentication table".  To persist the table to a file, each entry needs to
be written to the file.  The format of each entry as follows:

- Header -- `AUTH` (4 bytes)
- Lengths -- `len(@u).len(@salt).len(@hashpass).len(@profile)`
- Contents -- `@u.@salt.@hashpass.@profile`
- Padding -- Up to three `0` characters, to ensure that the entry's length is
  divisible by 4.

Notes:

- All data should be written as binary
- If the `@profile` is null, then the length should still be written as `0`.

## Getting Started

Your git repository contains a significant portion of the code for the final
solution to this assignment.  The `p1/common/` folder has variants of many of
the useful functions that we created for assignment 0.  The `p1/client/` folder
has code that is specific to the client, and the `p1/server/` folder has code
that is specific to the server.  You should be able to type `make` from the
`p1/` folder to build all of the code, and you should be able to run the basic
tests for the assignment by typing the following from the `p1` folder:

```bash
python3 scripts/p1.py
```

Of course, none of the tests will pass yet.  It will print some errors, and then
the script will crash.

I do not recommend starting by writing code.  Instead, start by making sure you
understand the communication protocol and storage format.  Try to understand how
commands flow through the client, to the server, and how responses flow back.
You can use my solution executables to help in this endeavor.

It is also important to read the documentation (however poor you may think it
is) for AES and RSA encryption.  When you AES-encrypt data, you must make sure
to properly handle the last block.  You should not be using a file as a
temporary storage place for the data you encrypt/decrypt. Consequently, you will
need to redesign the AES encryption code from assignment 0.

## Tips and Reminders

The code that we provide makes use of a number of C++ features.  You should be
sure you understand the way we use `std::vector`.  In particular, you should
know the difference between a declaration like `std::vector<uint8_t> v(1024)`
and the two-instruction sequence `std::vector<uint8_t> v; v.reserve(1024)`.
Also, note that our use of `std::vector` can introduce unnecessary copying,
which should be optimized out in an advanced implementation.  On the other hand,
some copying is necessary. Our use of `const vector<uint8_t>&` parameters helps
to show you where copying needs to happen.

While the collections (`std::vector`, `std::list`, etc.) use the heap, if you
are using them well, you shouldn't have to directly interact with the heap very
much in this assignment.  The reference solution calls `new` only four times,
and two of those times are for managing command-line arguments.  There are five
calls to `delete`, but we provide three of them for you.  Still, you are
expected to ensure your program does not have memory leaks, and to use
`valgrind` to be sure.

As you read through the details of this assignment, keep in mind that subsequent
assignments will build upon this... so as you craft a solution, be sure to think
about how to make it maintainable.  C++ has many features that make it easy to
extend your code.  The `auto` keyword is one.  In-line initialization of arrays
is another.

**Start Early**.  Just reading the code and understanding what is happening
takes time.  If you start reading the assignment early, you'll give yourself
time to think about what is supposed to be happening, and that will help you to
figure out what you will need to do.

When it comes time to implement functions in the client and server, you will
probably want to proceed in the following order: KEY, REG, SAV, BYE, ALL, SET,
GET.  Note that the test script accepts optional `CLIENT`, `SERVER`, and
`VERBOSE` arguments.  The first two will switch to using the solution
executables for the client and server, respectively.  The `VERBOSE` argument
will cause the script to print more information about what it is doing, so that
you can issue the same server and client commands from separate screen sessions
in a single terminal.

As always, please be careful about not committing unnecessary files into your
repository.

Your programs should never require keyboard input. In particular, the client
should get all its parameters from the command line.

Your server should **not** store plain-text passwords in the file.

## Grading

The `scripts` folder has four python scripts that exercise the main portions of
the assignment: basic authentication, file-based persistence, AES encryption,
and RSA encryption.  These scripts use specialized `Makefiles` that integrate
some of the solution code with some of your code, so that you can get partial
credit when certain portions of your code work.  Note that these `Makefiles` are
very strict: they will crash on any compiler warning.  You should *not* turn off
these warnings; they are there to help you.  If your code does not compile with
these scripts, you will not receive any credit.  If you have partial solutions
and you do not know how to coerce the code into being warning-free, you should
ask the professor.

I will also visually inspect your code to ensure you are using salts and
passwords correctly, not accidentally creating TOCTOU vulnerabilities, and so
forth.  While it is my intention to give partial credit, *no credit will be
given for code that does not compile without warnings.*  I also reserve the
right to deduct points for especially poorly written code.  In particular, if
you decide to move functions between files, or add files, or do other things
that break the scripts in the grading folder, then you will lose at least 10%.
If you think some change is absolutely necessary, speak with me first.

Please be sure to use your tools well.  For example, Visual Studio Code (and
emacs, and vim) have features that auto-format your code.  You should use these
features, so that your code is legible.  It is likely that auto-formatting will
help you spot bugs in your code.

Broadly speaking, there are five graded components:

- Is the AES cryptography implemented correctly?
- Do the client and server use RSA cryptography correctly?
- Are requests being authenticated properly
- Is persistence implemented correctly
- Is the implementation of passwords secure and correct?

Remember that the scripts can take VERBOSE, SERVER, and CLIENT arguments.
VERBOSE causes scripts to print output that will be useful when you try to run
the client and server manually.  SERVER and CLIENT cause the scripts to use the
reference solution for the server and client, respectively.  You should use
these to be sure that your implementations are correct.

Note, too, that the graded components are intentionally vague: you need to start
thinking about what it means for code to be "correct".  There are many criteria
that cannot be established through unit testing.

## Notes About the Reference Solution

In the following subsections, you will find some details about the reference
solution.  Note that you should not change any files other than the six that
are listed below.

### `common/my_crypto.cc`

This will probably give more students trouble than any other part of the
assignment, because the OpenSSL documentation is a bit spotty.  The body of
`aes_crypt_message()` is about 20 lines of code.  Knowing when and how to call
`EVP_CipherFinal_ex` is important.  Doing a `CipherUpdate` on a zero-byte block
before calling `CipherFinal` is a bit easier, in terms of the logic, than not.
The code from the tutorial is a good guide, but since that code works on files,
it will need some modification.

### `server/parsing.cc`

In the reference solution, the file is about 140 lines long.  There is one helper
function:

```c++
/// Helper method to check if the provided block of data is a kblock
///
/// @param block The block of data
///
/// @returns true if it is a kblock, false otherwise
bool is_kblock(vec &block);
```

In the reference solution, the `parse_request()` function has about 100 lines of
code.  It employs some nice code-saving techniques, like using an array of
functions when dispatching to the right command:

```c++
  // Iterate through possible commands, pick the right one, run it
  vector<string> s = {REQ_REG, REQ_BYE, REQ_SAV, REQ_SET, REQ_GET, REQ_ALL};
  decltype(handle_reg) *cmds[] = {handle_reg, handle_bye, handle_sav,
                                  handle_set, handle_get, handle_all};
  for (size_t i = 0; i < s.size(); ++i)
    if (cmd == s[i])
      return cmds[i](sd, storage, aes_ctx, ablock);
```

### `client/requests.cc`

In the reference solution, the file is about 275 lines long.  Note that
OpenSSL's RSA code handles padding for you.  My code also has this function,
which is very useful for simplifying `client_get()` and `client_all()`:

```c++
/// If a buffer consists of RES_OK.bbbb.d+, where `.` means concatenation, bbbb
/// is a 4-byte binary integer and d+ is a string of characters, write the bytes
/// (d+) to a file
///
/// @param buf      The buffer holding a response
/// @param filename The name of the file to write
void send_result_to_file(const vector<uint8_t> &buf, const string &filename);
```

The reference solution also has two functions that handle assembling the
client's request.  You are not required to write helper functions, but you will
probably find that they make it easier to build the client requests. Here are
their declarations.  Each has less than 5 lines in its body.  The templates make
it easy to use the same functions with `std::vector` and `std::string`
arguments:

```c++
/// Add the size of a value to a vector as a 4-byte value
///
/// @param res  The vector to add to
/// @param t    The thing whose size should be added
///
/// @tparam T   The type of t
template <class T> void add_size(vector<uint8_t> &res, T t);

/// Add the contents of an iterable to a vector
///
/// @param res  The vector to add to
/// @param t    The thing to add
///
/// @tparam T   The type of t
template <class T> void add_it(vector<uint8_t> &res, T t);
```

The most important helper function is this one.  You'll probably want to
implement something similar:

```c++
/// Send a message to the server, using the common format for secure messages,
/// then take the response from the server, decrypt it, and return it.
///
/// @param sd       The open socket descriptor for communicating with the server
/// @param pub      The server's public key, for encrypting the aes key
/// @param cmd      The command that is being sent
/// @param user     The username for the request
/// @param password The password for the request
/// @param msg      The contents that should be AES-encrypted
///
/// @return a vector with the (decrypted) result, or an empty vector on error
vector<uint8_t> send_cmd(int sd, EVP_PKEY *pub, const string &cmd,
                         const string &user, const string &password,
                         const vector<uint8_t> &msg);
```

The reference implementation is about 80 lines.  You won't want to write it at
first... figure out how to do REG and SET, and then you'll know what needs to go
in it.  Note that the function will help with REG, BYE, SAV, SET, GET, and ALL.
For example, here's the body of `req_get()` when the helper functions are
done:

```c++
  vector<uint8_t> block;
  add_size(block, getname);
  add_it(block, getname);
  auto res = send_cmd(sd, pubkey, REQ_GET, user, pass, block);
  send_result_to_file(res, getname + ".file.dat");
```

(Yes, just 5 lines... the hard work is in `send_cmd` and
`send_result_to_file`).

### `server/responses.cc`

This file has one function for each of the requests that a client can make.
Each function receives unencrypted data, validates it, sends a request to the
`Storage` object, and then transmits a response to the client.

You may want to write a few helper functions here, too, especially for
extracting the parts of a request.  The reference solution takes about 230 lines
of code to complete this file.  There is a fair bit of copy-and-paste from one
command to the next.

### `server/my_storage.cc`

In the reference solution, this file is about 330 lines (this count includes the
150 lines that are given in the handout).  `persist()` and `load()` take the
most code by far, because file I/O is tedious in C++.  The other methods are
relatively straightforward.  You should not need to add any additional fields to
the `MyStorage` class.

### `server/sequentialmap.h`

In subsequent assignments, you will need to implement your own concurrent hash
map.  In this assignment, we use the `SequentialMap` template as a wrapper
around `std::vector`.  This may seem cumbersome, but it means that later on, your
code in `my_storage.cc` won't have to change: you will just replace the sequential
map with a concurrent hash map that has the same interface.

If you are not familiar with `std::vector`, `http://cppreference.com/` is an
excellent resource.  Google will usually send you directly to the correct page.
Note that some of the methods of `SequentialMap` won't be used in this
assignment.  If you figure them out now, then the second assignment will be
easier.  If you skip them, you will not lose points, but you will miss out on
the opportunity to be more prepared for the rest of the semester.

## Collaboration and Getting Help

Students may work in teams of 2 for this assignment.  If you plan to work in a
team, you must notify me by February 2nd, so that I can set up your repository
access.  If you do not send a notification until after that date, I may deduct
10 points.  If you are working in a team, you should **pair program** for the
entire assignment.  After all, your goal is to learn together, not to each learn
half the material.

If you require help, you may seek it from any of the following sources:

- The professors and TAs, via office hours or Piazza
- The Internet, as long as you use the Internet as a read-only resource and do
  not post requests for help to online sites.

It is not appropriate to share code with past or current CSE 303 students,
unless you are sharing code with your teammate.  It is not appropriate to use
ChatGPT or other AI tools to help you write code for this assignment.

If you are familiar with `man` pages, please note that the easiest way to find a
man page is via Google.  For example, typing `man printf` will probably return
`https://linux.die.net/man/3/printf` as one of the first links.  It is fine to
use Google to find man pages.

StackOverflow is a wonderful tool for professional software engineers.  It is a
horrible place to ask for help as a student.  You should feel free to use
StackOverflow, but only as a *read only* resource.  In this class, you should
**never** need to ask a question on StackOverflow.

## Deadline

You should be done with this assignment before 11:59 PM on February 16th, 2024.
Please be sure to `git commit` and `git push` before that time, so that we can
promptly collect and grade your work.

There are many parts to this assignment, so you will probably want to `git push`
frequently.
