#include <cassert>
#include <cstring>
#include <functional>
#include <iostream>
#include <openssl/rand.h>
#include <string>
#include <vector>

#include "../common/constants.h"
#include "../common/contextmanager.h"
#include "../common/err.h"

#include "authtableentry.h"
#include "map.h"
#include "map_factories.h"
#include "storage.h"
//

#include "../common/file.h"
using namespace std;
//
/// MyStorage is the student implementation of the Storage class
class MyStorage : public Storage {
  /// The map of authentication information, indexed by username
  Map<string, AuthTableEntry> *auth_table;



  /// The name of the file from which the Storage object was loaded, and to
  /// which we persist the Storage object every time it changes
  const string filename;

public:
  /// Construct an empty object and specify the file from which it should be
  /// loaded.  To avoid exceptions and errors in the constructor, the act of
  /// loading data is separate from construction.
  ///
  /// @param fname   The name of the file to use for persistence
  /// @param buckets The number of buckets in the hash table
  MyStorage(const std::string &fname, size_t buckets)
      : auth_table(authtable_factory(buckets)), filename(fname){}

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

    //salt to the password
    vector<uint8_t> passslat;
    passslat.insert(passslat.end(), pass.begin(), pass.end());
    passslat.insert(passslat.end(), salt.begin(), salt.end());

    //hash password
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
    EVP_MD_CTX_free(mdctxval);

    // struct of entry
    AuthTableEntry entry {user, salt, hash, {}};
    //save entry

    return auth_table->insert(user, entry) ? 
        result_t{true, RES_OK, std::vector<uint8_t>{}} : 
        result_t{false, RES_ERR_USER_EXISTS, std::vector<uint8_t>{}};
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
    //check if match
    result_t matched = auth(user, pass);

    if (!matched.succeeded) {
      return matched;
    }

    auto tempdata = [&content](AuthTableEntry &a) { a.content = content; };
    if (auth_table->do_with(user, tempdata)) {
        return {true, RES_OK, std::vector<uint8_t>{}};
    } else {
        return {false, RES_ERR_LOGIN, std::vector<uint8_t>{}};
    }
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
      auth_table->do_all_readonly(temp); 
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

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    //temporary file
    string createfile = this->filename + ".temp";
    FILE *fd = fopen(createfile.c_str(), "w+");

    // User, salt, hashed password, and data profile
    auth_table->do_all_readonly([&](const string &str, const AuthTableEntry &entryy) {
        size_t writebytes = 0;
        writebytes += fwrite(AUTHENTRY.c_str(), 1, 4, fd); 
        size_t usernlen = entryy.username.length();
        writebytes += fwrite(&usernlen, 1, 4, fd); 
        size_t saltnlen = entryy.salt.size();
        writebytes += fwrite(&saltnlen, 1, 4, fd); 
        size_t passnlen = entryy.pass_hash.size();
        writebytes += fwrite(&passnlen, 1, 4, fd); 
        size_t datanlen = entryy.content.size();
        writebytes += fwrite(&datanlen, 1, 4, fd); 
        writebytes += fwrite(str.c_str(), 1, usernlen, fd);
        writebytes += fwrite(entryy.salt.data(), 1, saltnlen, fd);
        writebytes += fwrite(entryy.pass_hash.data(), 1, passnlen, fd);
        
        if (datanlen) { 
            writebytes += fwrite(entryy.content.data(), 1, datanlen, fd);
        }

        if (writebytes % 4 != 0) {
            size_t zero = 0;
            writebytes += fwrite(&zero, sizeof(char), 4 - (writebytes % 4), fd);
        }
    });

    // Rename and save to file
    if (rename(createfile.c_str(), "company.dir") != 0) {
      // Handle error, perhaps log it or return an error result
      perror("Error renaming file");
      fclose(fd);
      return {false, RES_ERR_SERVER, {}};
    }

    // Release resources
    fclose(fd);
    return {true, RES_OK, {}};
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  /// non-existent
  ///         file is not an error.
  virtual result_t load_file() {
    FILE *storage_file = fopen(filename.c_str(), "r");
    if (storage_file == nullptr) {
      return {true, "File not found: " + filename, {}};
    }

    // Hint: Don't change the previous 4 lines!
    
    // else if (storage_file == nullptr) {
    //   //return {true, "No such file " + filename, {}};
      
    //   return {true, "File not found: " + filename, {}};
    // }
    //buff to read line
    vector<uint8_t> buffer (5);
    //4 each time
    while (fread(buffer.data(), 1, 4, storage_file) == 4) {
      // check deal with authtable or kv
      string readbuff(buffer.begin(),buffer.end());
      // deal with authTable
      if (!readbuff.compare(AUTHENTRY)) {
        size_t read = 4;
        size_t usernlen, saltnlen, hashedpass, datanlen;
        //read from table
        read += fread(&usernlen,1,4,storage_file);
        read += fread(&saltnlen,1,4,storage_file);
        read += fread(&hashedpass,1,4,storage_file);
        read += fread(&datanlen,1,4,storage_file);
        string user (usernlen,'\0');
        vector<uint8_t> salt(saltnlen), hashed_pass(hashedpass), profile(datanlen);
        read += fread(&user[0],1,usernlen,storage_file);
        read += fread(salt.data(),1,saltnlen,storage_file);
        read += fread(hashed_pass.data(),1,hashedpass,storage_file);
        if (datanlen) {
          read += fread(profile.data(),1,datanlen,storage_file);
        }

        //pad to align 4 bytes margin
        if ((read % 4) != 0) {
          size_t dummpy_pad=0;
          read += fread(&dummpy_pad,sizeof(char),4 - (read % 4), storage_file);
        }
        AuthTableEntry entryy {user, salt, hashed_pass, profile};
        auth_table ->insert(user, entryy);
      }

    }
    //release resource
    fclose(storage_file);
    return {true, "Loaded: "+ filename, {}};
  };
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
