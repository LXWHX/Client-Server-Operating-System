#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

#include "../common/constants.h"
#include "../common/contextmanager.h"
#include "../common/err.h"

#include "authtableentry.h"
#include "gatekeeper.h"
#include "map.h"
#include "map_factories.h"
#include "mru.h"
#include "quotas.h"
#include "storage.h"

#include <mutex>
#include <sys/wait.h>

using namespace std;

// Forward-declare the function for building a storage factory, so that we can
// create a storage object from this file, without having the implementation on
// hand.
Storage *storage_factory(const std::string &fname, size_t buckets);

/// MyGatekeeper is the student implementation of the Gatekeeper class
class MyGatekeeper : public Gatekeeper {


  mutex mutexlock;  


  /// The upload quota
  const size_t up_quota;

  /// The download quota
  const size_t down_quota;

  /// The requests quota
  const size_t req_quota;

  /// The number of seconds over which quotas are enforced
  const double quota_dur;

  /// The table for tracking the most recently used keys
  mru_manager *mru;

  /// A table for tracking quotas
  Map<string, Quotas *> *quota_table;

  /// The actual storage object
  Storage *my_storage;

public:
  /// Construct an empty object and specify the file from which it should be
  /// loaded.  To avoid exceptions and errors in the constructor, the act of
  /// loading data is separate from construction.
  ///
  /// @param fname   The name of the file to use for persistence
  /// @param buckets The number of buckets in the hash table
  /// @param upq     The upload quota
  /// @param dnq     The download quota
  /// @param rqq     The request quota
  /// @param qd      The quota duration
  /// @param top     The size of the "top keys" cache
  MyGatekeeper(const std::string &fname, size_t buckets, size_t upq, size_t dnq,
               size_t rqq, double qd, size_t top)
      : up_quota(upq), down_quota(dnq), req_quota(rqq), quota_dur(qd),
        mru(mru_factory(top)), quota_table(quotatable_factory(buckets)),
        my_storage(storage_factory(fname, buckets)) {}

  /// Destructor for the gatekeeper object.
  virtual ~MyGatekeeper() {
    // TODO: be sure to reclaim memory!
    delete mru;
    delete quota_table;
    delete my_storage;
  }

  /// Create a new entry in the Auth table.  If the user already exists, return
  /// an error.  Otherwise, create a salt, hash the password, and then save an
  /// entry with the username, salt, hashed password, and a zero-byte content.
  ///
  /// @param user The user name to register
  /// @param pass The password to associate with that user name
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t add_user(const string &user, const string &pass) {
    return my_storage->add_user(user, pass);
  }

  /// Set the data bytes for a user, but do so if and only if the password
  /// matches
  ///
  /// @param user    The name of the user whose content is being set
  /// @param pass    The password for the user, used to authenticate
  /// @param content The data to set for this user
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t set_user_data(const string &user, const string &pass,
                                 const vector<uint8_t> &content) {
    return my_storage->set_user_data(user, pass, content);
  }

  /// Return a copy of the user data for a user, but do so only if the password
  /// matches
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param who  The name of the user whose content is being fetched
  ///
  /// @return A result tuple, as described in storage.h.  Note that "no data" is
  ///         an error
  virtual result_t get_user_data(const string &user, const string &pass,
                                 const string &who) {
    return my_storage->get_user_data(user, pass, who);
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    return my_storage->get_all_users(user, pass);
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    return my_storage->auth(user, pass);
  }

  /// Create a new key/value mapping in the table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being created
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_insert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {
    // TODO: Use the Quotas and MRU
    //return my_storage->kv_insert(user, pass, key, val, [&]() {});
    unique_lock<mutex> lock(mutexlock);

    //check if in quota table
    bool userexists = quota_table->do_with(user, [](Quotas* qq) { (void)qq; });
    
    //insert new user
    if (!userexists) {
      Quotas* tquota = new Quotas;
      tquota->uploads = quota_factory(up_quota, quota_dur);
      tquota->downloads = quota_factory(down_quota, quota_dur);
      tquota->requests = quota_factory(req_quota, quota_dur);
      quota_table->insert(user, tquota, [](){});
    }

    //check quotas, insert kv pair, insert mru
    result_t returnbuff = {false, RES_ERR_KEY, {}};

    quota_table->do_with(user, [&](Quotas* &qq) {
      if (!qq->requests->check_add(1)) {
        returnbuff = {false, RES_ERR_QUOTA_REQ, {}};
        return;
      }

      if (!qq->uploads->check_add(val.size())) {
        returnbuff = {false, RES_ERR_QUOTA_UP, {}};
        return;
      }

      auto insert_result = my_storage->kv_insert(user, pass, key, val, [&]() {});
      if (insert_result.succeeded) {
        mru->insert(key); //update MRU cache
        returnbuff = {true, RES_OK, {}};
      }
    });
    //
    return returnbuff;

  };

  /// Get a copy of the value to which a key is mapped
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being fetched
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_get(const string &user, const string &pass,
                          const string &key) {
    // TODO: Use the Quotas and MRU
    //return my_storage->kv_get(user, pass, key, [&](size_t s) {});
    //check if in quota table
    bool userexists = quota_table->do_with(user, [](Quotas* qq) { (void)qq; });
    //insert new user
    if (!userexists) {
      Quotas* tquota = new Quotas;
      tquota->uploads = quota_factory(up_quota, quota_dur);
      tquota->downloads = quota_factory(down_quota, quota_dur);
      tquota->requests = quota_factory(req_quota, quota_dur);
      quota_table->insert(user, tquota, [](){});
    }
    //check quotas, insert kv pair, insert mru
    result_t returnbuff;
    quota_table->do_with(user, [&](Quotas* &qq) {
      if (!qq->requests->check_add(1)) {
        returnbuff = {false, RES_ERR_QUOTA_REQ, {}};
        return;
      }

      vector<uint8_t> temp;

      temp = my_storage->kv_get(user, pass, key, [&](size_t s) {}).data;

      if (temp.empty()) {
        returnbuff = {false, RES_ERR_KEY, {}};
        return;
      }

      if (!qq->downloads->check_add(temp.size())) {
        returnbuff = {false, RES_ERR_QUOTA_DOWN, {}};
        return;
      }

      mru->insert(key);
      returnbuff = {true, RES_OK, temp};
    });

    return returnbuff;
    
  };

  /// Delete a key/value mapping
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being deleted
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_delete(const string &user, const string &pass,
                             const string &key) {
    // TODO: Use the Quotas and MRU
    //return my_storage->kv_delete(user, pass, key, [&]() {});
    unique_lock<mutex> lock(mutexlock);

    //check if in quota table
    bool userexists = quota_table->do_with(user, [](Quotas* q){assert(q);});
    //insert new user
    if (!userexists){
      Quotas* tquota = new Quotas;
      tquota->uploads = quota_factory(up_quota, quota_dur);
      tquota->downloads = quota_factory(down_quota, quota_dur);
      tquota->requests = quota_factory(req_quota, quota_dur);
      quota_table->insert(user, tquota, [](){});
    }
    result_t returnbuff;
  
    //check quotas, remove kv pair, remove mru
    quota_table->do_with(user, [&](Quotas* &q){
      if (q->requests->check_add(1)){
        if (my_storage->kv_delete(user, pass, key, [&]() {}).succeeded){
          mru->remove(key);
          returnbuff = {true, RES_OK, {}};
        }
        else{
          returnbuff = {false, RES_ERR_KEY, {}};
        }
      }
      else{
        returnbuff = {false, RES_ERR_QUOTA_REQ, {}};
      }
    });
    return returnbuff;
    
  };

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being upserted
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h.  Note that there are
  ///         two "OK" messages, depending on whether we get an insert or an
  ///         update.
  virtual result_t kv_upsert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {
    // TODO: Use the Quotas and MRU
    //return my_storage->kv_upsert(user, pass, key, val, [&]() {});

    //check if in quota table
    bool userexists = quota_table->do_with(user, [](Quotas* q){assert(q);});
    //insert new user
    if (!userexists){
      Quotas* tquota = new Quotas;
      tquota->uploads = quota_factory(up_quota, quota_dur);
      tquota->downloads = quota_factory(down_quota, quota_dur);
      tquota->requests = quota_factory(req_quota, quota_dur);
      quota_table->insert(user, tquota, [](){});
    }
    result_t returnbuff = {false, RES_ERR_SERVER, {}};
    //check quotas, insert kv pair, insert mru ////or update
    quota_table->do_with(user, [&](Quotas* &q){
      if (q->requests->check_add(1)){
        if (q->uploads->check_add(val.size())){
          returnbuff = my_storage->kv_upsert(user, pass, key, val, [&]() {});
          if (returnbuff.succeeded){
            mru->insert(key);
            //returnbuff = {true, RES_OKUPD, {}};
          }

        }
        else{
          returnbuff = {false, RES_ERR_QUOTA_UP, {}};
        }
      }
      else{
        returnbuff = {false, RES_ERR_QUOTA_REQ, {}};
      }
    });
    return returnbuff;
    
  };

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {
    // TODO: Use the Quotas and MRU
    //return my_storage->kv_all(user, pass, []() {});
    //check if in quota table
    bool userexists = quota_table->do_with(user, [](Quotas* q){assert(q);});
    //insert new user
    if (!userexists){
      Quotas* tquota = new Quotas;
      tquota->uploads = quota_factory(up_quota, quota_dur);
      tquota->downloads = quota_factory(down_quota, quota_dur);
      tquota->requests = quota_factory(req_quota, quota_dur);
      quota_table->insert(user, tquota, [](){});
    }
    result_t returnbuff;

    quota_table->do_with(user, [&](Quotas* &q){
      if (q->requests->check_add(1)){
        
        //Obtain all content
        vector<uint8_t> content;
        content = my_storage->kv_all(user, pass, []() {}).data;
        if (content.size() > 0){
          if (q->downloads->check_add(content.size())){
            returnbuff = {true, RES_OK, content};
          }
          else{
            returnbuff = {false, RES_ERR_QUOTA_DOWN, {}};
          }
        }
        else{
          returnbuff = {false, RES_ERR_NO_DATA, {}};
        }
      }
      else{
        returnbuff = {false, RES_ERR_QUOTA_REQ, {}};
      }
    });
    return returnbuff;
  };

  /// Return all of the keys in the kv_store's MRU cache, as a "\n"-delimited
  /// string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_top(const string &user, const string &pass) {
    // TODO: Implement this method.  Be sure to use Quotas and MRU, as
    //       appropriate
    //return {false, RES_ERR_UNIMPLEMENTED, {}};

    //check if in quota table
    bool userexists = quota_table->do_with(user, [](Quotas* q){assert(q);});
    if (!userexists){
      Quotas* tquota = new Quotas;
      tquota->uploads = quota_factory(up_quota, quota_dur);
      tquota->downloads = quota_factory(down_quota, quota_dur);
      tquota->requests = quota_factory(req_quota, quota_dur);
      quota_table->insert(user, tquota, [](){});
    }
    result_t returnbuff = {false, RES_ERR_SERVER, {}};
    //check quotas, get all keys in mru
    quota_table->do_with(user, [&](Quotas* &q){
      if (q->requests->check_add(1)){
        string s = mru->get();
        vector<uint8_t> vec(s.begin(), s.end());
        if (vec.size() > 0){
          if (q->downloads->check_add(vec.size())){
            returnbuff = {true, RES_OK, vec};
          }
          else{
            returnbuff = {false, RES_ERR_QUOTA_DOWN, {}};
          }
        }
        else{
          returnbuff = {false, RES_ERR_NO_DATA, {}};
        }
      }
      else{
        returnbuff = {false, RES_ERR_QUOTA_REQ, {}};
      }
    });
    return returnbuff;
  };

  /// Shut down the gatekeeper when the server stops.  This method needs to
  /// close any open files related to incremental persistence.  It also needs to
  /// clean up any state related to .so files.  This is only called when all
  /// threads have stopped accessing the Gatekeeper object.
  virtual void shutdown() { my_storage->shutdown(); }

  /// Write the entire Gatekeeper object to the file specified by this.filename.
  /// To ensure durability, Gatekeeper must be persisted in two steps.  First,
  /// it must be written to a temporary file (this.filename.tmp).  Then the
  /// temporary file can be renamed to replace the older version of the
  /// Gatekeeper object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() { return my_storage->save_file(); }

  /// Populate the Gatekeeper object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Gatekeeper object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  ///         non-existent file is not an error.
  virtual result_t load_file() { return my_storage->load_file(); }
};

/// Create an empty Gatekeeper object and specify the file from which it should
/// be loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname   The name of the file to use for persistence
/// @param buckets The number of buckets in the hash table
/// @param upq     The upload quota
/// @param dnq     The download quota
/// @param rqq     The request quota
/// @param qd      The quota duration
/// @param top     The size of the "top keys" cache
Gatekeeper *gatekeeper_factory(const std::string &fname, size_t buckets,
                               size_t upq, size_t dnq, size_t rqq, double qd,
                               size_t top) {
  return new MyGatekeeper(fname, buckets, upq, dnq, rqq, qd, top);
}
