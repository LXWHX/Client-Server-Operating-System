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

#include <mutex>
#include <sys/stat.h>

#include "../common/constants.h"
#include "../common/contextmanager.h"
#include "../common/err.h"

#include "authtableentry.h"
#include "map.h"
#include "map_factories.h"
#include "persist.h"
#include "storage.h"

using namespace std;

/// MyStorage is the student implementation of the Storage class
class MyStorage : public Storage {
  /// The map of authentication information, indexed by username
  Map<string, AuthTableEntry> *auth_table;

  /// The map of key/value pairs
  Map<string, vector<uint8_t>> *kv_store;

  /// The name of the file from which the Storage object was loaded, and to
  /// which we persist the Storage object every time it changes
  const string filename;

  /// The open file
  FILE *storage_file = nullptr;

  //mutex for file operation
  mutex mtxlock;  

public:
  /// Construct an empty object and specify the file from which it should be
  /// loaded.  To avoid exceptions and errors in the constructor, the act of
  /// loading data is separate from construction.
  ///
  /// @param fname   The name of the file to use for persistence
  /// @param buckets The number of buckets in the hash table
  MyStorage(const std::string &fname, size_t buckets)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname) {
    //cout << "my_storage.cc::MyStorage() is not implemented\n";
  }

  /// Destructor for the storage object.
  virtual ~MyStorage() {
    //cout << "my_storage.cc::~MyStorage() is not implemented\n";
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
    //salt
    vector<uint8_t> salt;
    unsigned char temp[LEN_SALT];
    //fill salt
    if (RAND_bytes(temp, LEN_SALT) != 1) {
     fprintf(stderr, "Error in generat salt\n");
     //auto tup = std::make_tuple(false, RES_ERR_SERVER, {});
     //return std::make_tuple(false, RES_ERR_SERVER, {});
     return {false, RES_ERR_SERVER, {}};
    }
    //insert
    salt.insert(salt.end(), &temp[0], &temp[LEN_SALT]);

    //salt add to the password
    vector<uint8_t> passslat;
    passslat.insert(passslat.end(), pass.begin(), pass.end());
    passslat.insert(passslat.end(), salt.begin(), salt.end());

    //hash the passsalt with ctx
    vector<uint8_t> hash(LEN_PASSHASH);
    EVP_MD_CTX *mdctxval = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    //check error in hash process !!not sure
    //EVP_DigestInit_ex check if null
    //EVP_DigestUpdate check if data insert faliure
    // EVP_DigestFinal_ex calculation faliure
    if (mdctxval == NULL|| EVP_DigestInit_ex(mdctxval, md, NULL) <= 0 || EVP_DigestUpdate(mdctxval, passslat.data(), passslat.size()) <= 0 || EVP_DigestFinal_ex(mdctxval, hash.data(), NULL) <= 0) {
      fprintf(stderr, "Error EVP_Digest\n");
      EVP_MD_CTX_free(mdctxval);
      return {false, RES_ERR_SERVER, {}};
    }
    //free memory
    EVP_MD_CTX_free(mdctxval);
    //p3 create entry for authtable
    AuthTableEntry entry;
    entry.username = user;
    entry.pass_hash = hash;
    entry.salt = salt;
    entry.content = {};
    //format in format.h
    if (auth_table->insert(user, entry, [](){})){
        //lock
        lock_guard<mutex> lock(mtxlock);
        size_t inputbytes = 0;
        //
        inputbytes += fwrite(AUTHENTRY.data(), 1, AUTHENTRY.size(), storage_file); 
        //AUTH flag username salt hashedpassword profile
        std::vector<unsigned char> username_data(entry.username.begin(), entry.username.end());
        for (const auto& field : {username_data, entry.salt, entry.pass_hash, entry.content}) {
          size_t field_len = field.size();
          uint32_t len = static_cast<uint32_t>(field_len); // makesure 32 length
          fwrite(&len, 1, 4, storage_file); // write4
          inputbytes += 4; // add4 to totall
          inputbytes += fwrite(field.data(), 1, field.size(), storage_file); // write and renew size
        }
        //append 0 if %4 is not0
        while ((inputbytes % 4) != 0) {
            uint8_t zero = 0;
            inputbytes += fwrite(&zero, 1, 1, storage_file);
        }
        //updates to persistent storage before return
        fflush(storage_file);
        fsync(fileno(storage_file));
        return {true, RES_OK, {}};
    }
    return {false, RES_ERR_USER_EXISTS, {}};
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
        // check size within limit
    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
      return {false, RES_ERR_REQ_FMT, {}};
    }

    //p3
    result_t matched = auth(user, pass);
    if (matched.succeeded) {
        vector<uint8_t> salt, hashed_pass;
        //get data writeupdate to file
        auth_table->do_with_readonly(user, [&](AuthTableEntry ent) {
            salt = ent.salt;
            hashed_pass = ent.pass_hash;
        });
        //upsert to entry
        AuthTableEntry entry{user, salt, hashed_pass, content};
        auth_table->upsert(user, entry, []() {}, []() {});

        //AUTHDIFF flag username salt hashedpassword profile tofile
        vector<uint8_t> temp;
        temp.insert(temp.end(), AUTHDIFF.begin(), AUTHDIFF.end());
        uint32_t userlen = static_cast<uint32_t>(user.length());
        temp.insert(temp.end(), reinterpret_cast<uint8_t*>(&userlen), reinterpret_cast<uint8_t*>(&userlen) + sizeof(userlen));
        temp.insert(temp.end(), user.begin(), user.end());
        uint32_t profilelen = static_cast<uint32_t>(content.size());
        temp.insert(temp.end(), reinterpret_cast<uint8_t*>(&profilelen), reinterpret_cast<uint8_t*>(&profilelen) + sizeof(profilelen));
        if (profilelen > 0) {
            temp.insert(temp.end(), content.begin(), content.end());
        }
        while (temp.size() % 4 != 0) {
            temp.push_back('\0');
}

        //lock
        lock_guard<mutex> lock(mtxlock);
        size_t totalbytesupdate = fwrite(temp.data(), sizeof(uint8_t), temp.size(), storage_file);
        if (totalbytesupdate != temp.size()) {
            cout << "Fail writing auth table to file\n";
        }

        fflush(storage_file);
        fsync(fileno(storage_file));
        return {true, RES_OK, {}};
    } 
    return {false, RES_ERR_LOGIN, {}};
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
    //check user and password length
    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
      return {false, RES_ERR_REQ_FMT, {}};
    }

    //check if match
    result_t authentication_result = auth(user, pass);
    if (!authentication_result.succeeded) {
      return {false, RES_ERR_LOGIN, {}};
    }

    //same as above data of user
    vector<uint8_t> content;
    bool user_exists = auth_table->do_with_readonly(who, [&content](const AuthTableEntry &entry) {
      content = entry.content;
    });
    //check for error
    if (user_exists) {
      if (content.empty()) {
        return {false, RES_ERR_NO_DATA, {}};
      } else {
        //returen when no error
        return {true, RES_OK, content};
      }
    } else {
      return {false, RES_ERR_NO_USER, {}};
    }
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    //check length
    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
      return {false, RES_ERR_REQ_FMT, {}};
    }
    //check if match
    result_t matched = auth(user, pass);
    if (matched.succeeded){
      //get all user data
      vector<uint8_t> content;

      auto temp = [&content](string keyy, AuthTableEntry anotuse){ 
        content.insert(content.end(), keyy.begin(), keyy.end());
        content.push_back('\n');
        //prevent warning of non used
        assert(anotuse.content.size() > 0);
      };
      auth_table->do_all_readonly(temp, [](){}); 
      return {true, RES_OK, content};
    }
    else{
      return matched;
    }
    return {false, RES_ERR_SERVER, {}};
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    // check size within limit
    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
      return {false, RES_ERR_REQ_FMT, {}};
    }
    //get user data
    AuthTableEntry getdata;
    auto get_user = [&getdata](AuthTableEntry temp){ getdata = temp; };
    //no such user
    if(!auth_table->do_with_readonly(user, get_user)){
      return {false, RES_ERR_LOGIN, {}};
    }
    //salt password
    vector<uint8_t> passslat;
    passslat.insert(passslat.end(), pass.begin(), pass.end());
    passslat.insert(passslat.end(), getdata.salt.begin(), getdata.salt.end()); 

    //hash password
    vector<uint8_t> hash(LEN_PASSHASH);
    EVP_MD_CTX *mdctxval = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    //check error in hash process !!not sure
    //EVP_DigestInit_ex check if null
    //EVP_DigestUpdate check if data insert faliure
    // EVP_DigestFinal_ex calculation faliure
    if (mdctxval == NULL|| EVP_DigestInit_ex(mdctxval, md, NULL) <= 0 || EVP_DigestUpdate(mdctxval, passslat.data(), passslat.size()) <= 0 || EVP_DigestFinal_ex(mdctxval, hash.data(), NULL) <= 0) {
      fprintf(stderr, "Error in EVP_Digest2\n");
      EVP_MD_CTX_free(mdctxval);
      return {false, RES_ERR_SERVER, {}};
    }
    EVP_MD_CTX_free(mdctxval);

    // check 2 hashed values
    if (hash == getdata.pass_hash){
      return {true, RES_OK, {}};
    }
    else{
      return {false, RES_ERR_LOGIN, {}};
    }
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
    // check size within limit
    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
      return {false, RES_ERR_REQ_FMT, {}};
    }
    //p3
    result_t matched = auth(user, pass);
    if (!matched.succeeded)
        return {false, matched.msg, {}};

    lock_guard<mutex> lock(mtxlock);
    size_t inputbytes = 0;
    //flag KVENTRY kay and value data
    inputbytes += fwrite(&KVENTRY[0], 1, 4, storage_file);
    int keylength = static_cast<int>(key.size());
    inputbytes += fwrite(&keylength, 1, sizeof(int), storage_file); 
    inputbytes += fwrite(key.data(), 1, key.size(), storage_file);
    int valuelength = static_cast<int>(val.size());
    inputbytes += fwrite(&valuelength, 1, sizeof(int), storage_file); 
    inputbytes += fwrite(val.data(), 1, val.size(), storage_file);

    while (inputbytes % 4 != 0) {
        uint8_t zero = 0;
        inputbytes += fwrite(&zero, sizeof(char), 1, storage_file);
    }

    fflush(storage_file);
    fsync(fileno(storage_file));

    if (kv_store->insert(key, vector(val), []() {}))
    {
      return {true, RES_OK, {}};
    }
    return {false, RES_ERR_KEY, {}};
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
    // check size within limit
    if (user.length() >= LEN_UNAME || pass.length() >= LEN_PASSWORD) {
      return {false, RES_ERR_REQ_FMT, {}};
    }
    result_t matched = auth(user, pass);
    if (matched.succeeded){
      //data of user
      vector<uint8_t> content;
      auto temp = [&content](vector<uint8_t> val){ content = val; };
      if(kv_store->do_with_readonly(key, temp)){
        if (content.size() > 0){
          return {true, RES_OK, content};
        }
        else{
          return {false, RES_ERR_NO_DATA, {}};
        }
      }
      else{
        return {false, RES_ERR_KEY, {}};
      }
    }
    else{
        return matched;
    }
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
    //p3 
    result_t matched = auth(user, pass);
    if (!matched.succeeded) {
        return {false, matched.msg, {}};
    }

    lock_guard<mutex> lock(mtxlock);

    auto addLenAsBytes = [](vector<uint8_t> &targetVec, int len) {
        for (size_t i = 0; i < 4; i++) { // 4 cycke
            targetVec.push_back((len >> (8 * i)) & 0xff); // shift8 bits
        }
    };

    vector<uint8_t> temp;
    temp.insert(temp.end(), KVDELETE.begin(), KVDELETE.end());
    addLenAsBytes(temp, (int)key.size());
    temp.insert(temp.end(), key.begin(), key.end());

    while (temp.size() % 4 != 0) {
        temp.push_back('\0');
    }

    size_t totalbytesupdate = fwrite(temp.data(), sizeof(uint8_t), temp.size(), storage_file);
    if (totalbytesupdate != temp.size()) {
        cout << "fail to update kv delete\n";
    }

    fflush(storage_file);
    fsync(fileno(storage_file));

    if (kv_store->remove(key, [&]() {
    })) {
        return {true, RES_OK, {}};
    }
    return {false, RES_ERR_KEY, {}};
  };

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being upserted
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h.  Note that there are
  /// two
  ///         "OK" messages, depending on whether we get an insert or an update.
  virtual result_t kv_upsert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {
    //p3
    auto matched = auth(user, pass);
    if (!matched.succeeded)
      return {false, matched.msg, {}};
    //flag KVENTRY key and value data
    auto fwriteinfile = [&](const vector<uint8_t> &header) {
      lock_guard<mutex> lock(mtxlock);
      size_t inputbytes = 0;
      inputbytes += fwrite(header.data(), 1, 4, storage_file); 
      int keylength = static_cast<int>(key.size());
      inputbytes += fwrite(&keylength, 1, sizeof(int), storage_file); 
      inputbytes += fwrite(key.data(), 1, key.size(), storage_file);
      int valuelength = static_cast<int>(val.size());
      inputbytes += fwrite(&valuelength, 1, sizeof(int), storage_file); 
      inputbytes += fwrite(val.data(), 1, val.size(), storage_file);

      while (inputbytes % 4 != 0) {
        uint8_t zero = 0;
        inputbytes += fwrite(&zero, sizeof(char), 1, storage_file);
      }

      fflush(storage_file);
      fsync(fileno(storage_file));
    };

    if (kv_store->upsert(key, vector(val), [&]() { fwriteinfile(vector<uint8_t>(KVENTRY.begin(), KVENTRY.end())); }, [&]() { fwriteinfile(vector<uint8_t>(KVUPDATE.begin(), KVUPDATE.end())); }))
    {
      return {true, RES_OKINS, {}};
    }
      
    return {true, RES_OKUPD, {}};
  };

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {
    result_t matched = auth(user, pass);
    if (matched.succeeded){
      //get all keys in to 
      vector<uint8_t> content;
      auto temp = [&content](string keyy, vector<uint8_t> val){ 
        content.insert(content.end(), keyy.begin(), keyy.end());
        content.push_back('\n');
        //assert for compiler
        assert(val.size());
      };
      kv_store->do_all_readonly(temp, [](){});
      if (content.size() == 0){
        return {false, RES_ERR_NO_DATA, {}};
      }
      return {true, RES_OK, content};
    }
    else{
      return matched;
    }
    return {false, RES_ERR_SERVER, {}};
  };

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    fclose(storage_file);
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    //p3
    //p3
    string tempfilename = filename + ".tmp";
    FILE* fd = fopen(tempfilename.c_str(), "w");

    auto write_entry = [&fd](string key, const vector<uint8_t> &val, const vector<uint8_t> &header) {
      vector<uint8_t> temp;
      temp.insert(temp.end(), header.begin(), header.end());
      //reinterpret_cast change pointer
      long keylength = static_cast<long>(key.size());
      temp.insert(temp.end(), reinterpret_cast<const uint8_t*>(&keylength), reinterpret_cast<const uint8_t*>(&keylength) + sizeof(long));
      temp.insert(temp.end(), key.begin(), key.end());

      long valuelength = static_cast<long>(val.size());
      temp.insert(temp.end(), reinterpret_cast<const uint8_t*>(&valuelength), reinterpret_cast<const uint8_t*>(&valuelength) + sizeof(long));
      temp.insert(temp.end(), val.begin(), val.end());

      while (temp.size() % 4 != 0) {
        temp.push_back('\0');
      }

      size_t totalbytesupdate = fwrite(temp.data(), sizeof(uint8_t), temp.size(), fd);
      if (totalbytesupdate != temp.size()) {
        cout << "failed update entry to file\n";
      }
    };

    auth_table->do_all_readonly([&](const string &key, const AuthTableEntry &val) {
      write_entry(key, val.pass_hash, vector<uint8_t>(AUTHENTRY.begin(), AUTHENTRY.end()));
    }, [](){});

    kv_store->do_all_readonly([&](const string &key, const vector<uint8_t> &val) {
      write_entry(key, val, vector<uint8_t>(KVENTRY.begin(), KVENTRY.end()));
    }, [](){});

    rename(tempfilename.c_str(), filename.c_str());
    fclose(fd);
    return {true, RES_OK, {}};
  }

  //helper function
  void lengthtovector(vector<uint8_t>::const_iterator &iter, vector<uint8_t> &targetVec, int maxAllowedLength){
    vector<uint8_t> lenBytes(4);
    for (int i = 0; i < 4; ++i) {
        lenBytes[i] = *iter;
        ++iter;
    }
    int dataSize = 0;
    for (size_t i = 0; i < sizeof(int); ++i) {
        dataSize |= ((int)lenBytes[i] << (8 * i));
    }

    if (dataSize > 0 && dataSize <= maxAllowedLength) {
        targetVec.reserve(dataSize);
        for (int i = 0; i < dataSize; ++i) {
            targetVec.push_back(*iter);
            ++iter;
        }
    }
    else {
        if (maxAllowedLength == LEN_PROFILE_FILE && dataSize == 0) {
            return;
        }
        cout << "lengthtovector failed\n";
    }
  }


  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  ///         non-existent file is not an error.
  virtual result_t load_file() {
    struct stat buffer;
    if (stat(filename.c_str(), &buffer) != 0){
      storage_file = fopen(filename.c_str(), "a+");
      return {true, "File not found: " + filename, {}};
    }
    storage_file = fopen(filename.c_str(), "a+");
    if (!storage_file){
      return {true, "File not found: " + filename, {}};
    }

    vector<uint8_t> file_contents(buffer.st_size);

    if (fread(file_contents.data(), sizeof(char), buffer.st_size + 1, storage_file) != file_contents.size() || !feof(storage_file))
      return {true, "number of bytes is wrong in " + filename, {}};

    //AUTHENTRY、KVENTRY、AUTHDIFF、KVUPDATE KVDELETE
    vector<uint8_t>::const_iterator iter = file_contents.begin();
    while(iter <= file_contents.end()){

      string currflag = string(iter, iter + 4);
      iter += 4;
      if (currflag == AUTHENTRY){
        AuthTableEntry entry;
        vector<uint8_t> uname;
        lengthtovector(iter, uname, LEN_UNAME);
        entry.username = string(uname.begin(), uname.end());
        lengthtovector(iter, entry.salt, LEN_SALT);
        lengthtovector(iter, entry.pass_hash, LEN_PASSHASH);
        lengthtovector(iter, entry.content, LEN_PROFILE_FILE);
        while (*iter != 'A' && *iter != 'K'){
          iter++;
        }
        if(!auth_table->insert(string(uname.begin(), uname.end()), entry, [](){})){
          return {false, RES_ERR_USER_EXISTS, {}};
        }
      }

      else if (currflag == KVENTRY){
        string key;
        vector<uint8_t> val;
        vector<uint8_t> key_vec;

        lengthtovector(iter, key_vec, LEN_KEY);
        key = string(key_vec.begin(), key_vec.end());
        lengthtovector(iter, val, LEN_VAL);

        while (*iter != 'A' && *iter != 'K'){
          iter++;
        }

        if(!kv_store->insert(key, val, [](){})){
          return {false, RES_ERR_USER_EXISTS, {}};
        }
      }
      else if (currflag == AUTHDIFF){
        vector<uint8_t> uname;
        vector<uint8_t> profile_file;

        lengthtovector(iter, uname, LEN_UNAME);

        lengthtovector(iter, profile_file, LEN_PROFILE_FILE);
        while (*iter != 'A' && *iter != 'K'){
          iter++;
        }
        auto set_content = [&](AuthTableEntry &a){ 
          a.content = profile_file;
        };
        if(!auth_table->do_with(string(uname.begin(), uname.end()), set_content)){
          return {false, RES_ERR_SERVER, {}};
        }
      }
      else if (currflag == KVUPDATE){
        string key;
        vector<uint8_t> val;
        vector<uint8_t> key_vec;

        lengthtovector(iter, key_vec, LEN_KEY);
        key = string(key_vec.begin(), key_vec.end());

        lengthtovector(iter, val, LEN_VAL);
        while (*iter != 'A' && *iter != 'K'){
          iter++;
        }

        if(kv_store->upsert(key, val, [](){}, [](){})){
          return {false, RES_ERR_NO_DATA, {}};
        }
      }
      else if (currflag == KVDELETE){
        string key;
        vector<uint8_t> key_vec;

        lengthtovector(iter, key_vec, LEN_KEY);
        key = string(key_vec.begin(), key_vec.end());

        while (*iter != 'A' && *iter != 'K'){
          iter++;
        }

        if(!kv_store->remove(key, [](){})){
          return {false, RES_ERR_NO_DATA, {}};
        }
      }
      else{
        return{false, RES_ERR_SERVER, {}};
      }

    }

    return {true, "Loaded: " + filename, {}};
  }
};

/// Create an empty Storage object and specify the file from which it should be
/// loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname   The name of the file to use for persistence
/// @param buckets The number of buckets in the hash table
Storage *storage_factory(const std::string &fname, size_t buckets) {
  return new MyStorage(fname, buckets);
}
