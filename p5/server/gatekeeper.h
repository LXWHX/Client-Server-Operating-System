#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "storage.h"

/// Gatekeeper is a wrapper around the Storage object.  It does two things:
///
/// - It has a quota system, to restrict authenticated users from interacting
///   with the storage when it exceeds their usage limits
///
/// - It has a small cache, to make get operations faster.  The cache employs
///   LRU eviction.
///
/// Note that these duties are only applied to the KV store, not to the auth
/// table.
///
/// Note, too, that Gatekeeper *has a* Storage object, so it can pass operations
/// directly to it, rather than do the low-level work itself.
class Gatekeeper {
public:
  /// Destructor for the gatekeeper object.
  virtual ~Gatekeeper() {}

  /// Populate the Gatekeeper object by loading the filename that was provided
  /// to the constructor.  Note that load_file() begins by clearing the maps, so
  /// that when the call is complete, exactly and only the contents of the file
  /// are in the Gatekeeper object.
  ///
  /// @return A result tuple, as described above.  Note that a non-existent file
  ///         is not an error.
  virtual result_t load_file() = 0;

  /// Create a new entry in the Auth table.  If the user already exists, return
  /// an error.  Otherwise, create a salt, hash the password, and then save an
  /// entry with the username, salt, hashed password, and a zero-byte content.
  ///
  /// @param user The user name to register
  /// @param pass The password to associate with that user name
  ///
  /// @return A result tuple, as described above
  virtual result_t add_user(const std::string &user,
                            const std::string &pass) = 0;

  /// Set the data bytes for a user, but do so if and only if the password
  /// matches
  ///
  /// @param user    The name of the user whose content is being set
  /// @param pass    The password for the user, used to authenticate
  /// @param content The data to set for this user
  ///
  /// @return A result tuple, as described above
  virtual result_t set_user_data(const std::string &user,
                                 const std::string &pass,
                                 const std::vector<uint8_t> &content) = 0;

  /// Return a copy of the user data for a user, but do so only if the password
  /// matches
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param who  The name of the user whose content is being fetched
  ///
  /// @return A result tuple, as described above.  Note that "no data" is an
  ///         error
  virtual result_t get_user_data(const std::string &user,
                                 const std::string &pass,
                                 const std::string &who) = 0;

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described above
  virtual result_t get_all_users(const std::string &user,
                                 const std::string &pass) = 0;

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described above
  virtual result_t auth(const std::string &user, const std::string &pass) = 0;

  /// Write the entire Gatekeeper object to the filename that was provided to
  /// the constructor.  To ensure durability, Gatekeeper must be persisted in
  /// two steps.  First, it must be written to a temporary file
  /// (this.filename.tmp). Then the temporary file can be renamed to replace the
  /// older version of the Gatekeeper object.
  ///
  /// @return A result tuple, as described above
  virtual result_t save_file() = 0;

  /// Create a new key/value mapping in the table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being created
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described above
  virtual result_t kv_insert(const std::string &user, const std::string &pass,
                             const std::string &key,
                             const std::vector<uint8_t> &val) = 0;

  /// Get a copy of the value to which a key is mapped
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being fetched
  ///
  /// @return A result tuple, as described above
  virtual result_t kv_get(const std::string &user, const std::string &pass,
                          const std::string &key) = 0;

  /// Delete a key/value mapping
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being deleted
  ///
  /// @return A result tuple, as described above
  virtual result_t kv_delete(const std::string &user, const std::string &pass,
                             const std::string &key) = 0;

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being upserted
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described above.  Note that there are two "OK"
  ///         messages, depending on whether we get an insert or an update.
  virtual result_t kv_upsert(const std::string &user, const std::string &pass,
                             const std::string &key,
                             const std::vector<uint8_t> &val) = 0;

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described above
  virtual result_t kv_all(const std::string &user, const std::string &pass) = 0;

  /// Return all of the keys in the kv_store's MRU cache, as a "\n"-delimited
  /// string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described above
  virtual result_t kv_top(const std::string &user, const std::string &pass) = 0;

  /// Register a .so with the function table
  ///
  /// @param user   The name of the user who made the request
  /// @param pass   The password for the user, used to authenticate
  /// @param mrname The name to use for the registration
  /// @param so     The .so file contents to register
  ///
  /// @return A result tuple, as described above
  virtual result_t register_mr(const std::string &user, const std::string &pass,
                               const std::string &mrname,
                               const std::vector<uint8_t> &so) = 0;

  /// Run a map/reduce on all the key/value tuples of the kv_store
  ///
  /// @param user   The name of the user who made the request
  /// @param pass   The password for the user, to authenticate
  /// @param mrname The name of the map/reduce functions to use
  ///
  /// @return A result tuple, as described above
  virtual result_t invoke_mr(const std::string &user_name,
                             const std::string &pass,
                             const std::string &mrname) = 0;

  /// Shut down the gatekeeper when the server stops.  This method needs to
  /// close any open files related to incremental persistence.  It also needs to
  /// clean up any state related to .so files.  This is only called when all
  /// threads have stopped accessing the Gatekeeper object.
  virtual void shutdown() = 0;
};

/// Create an empty Gatekeeper that contains its own Gatekeeper object.
///
/// @param fname   The name of the file to use for persistence
/// @param buckets The number of buckets in the hash table
/// @param upq     The upload quota
/// @param dnq     The download quota
/// @param rqq     The request quota
/// @param qd      The quota duration
/// @param top     The size of the "top keys" cache
/// @param admin   The administrator's username
Gatekeeper *gatekeeper_factory(const std::string &fname, size_t buckets,
                               size_t upq, size_t dnq, size_t rqq, double qd,
                               size_t top, const std::string &admin);
