#include <cassert>
#include <iostream>
#include <string>

#include "../common/constants.h"
#include "../common/crypto.h"
#include "../common/net.h"

#include "responses.h"

using namespace std;






/// Respond to an ALL command by generating a list of all the usernames in the
/// Auth table and returning them, one per line.
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param u       The user name associated with the request
/// @param p       The password associated with the request
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_all(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const std::string &u, const std::string &p,
                const vector<uint8_t> &) {
  //cout << "responses.cc::handle_all() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  // assert(sd);
  // assert(storage);
  // assert(ctx);
  // assert(u.length() > 0);
  // assert(p.length() > 0);
  // return false;
  //check format
  if(u.length() > LEN_UNAME || p.length() > LEN_PASSWORD||u.empty() || p.empty())
  {
    bool sendbytes =send_reliably(sd, aes_crypt_msg(ctx,RES_ERR_LOGIN));
    if (!sendbytes){
      fprintf(stderr, "Error responses\n");
    }
  }
  else
  {
    // All user to storage
    Storage::result_t matched = storage->get_all_users(u, p);
    send_reliably(sd,aes_crypt_msg(ctx,matched.msg));
  }
  return false;
}

/// Respond to a SET command by putting the provided data into the Auth table
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param u       The user name associated with the request
/// @param p       The password associated with the request
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_set(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const std::string &u, const std::string &p,
                const vector<uint8_t> &req) {
  //cout << "responses.cc::handle_set() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  // assert(sd);
  // assert(storage);
  // assert(ctx);
  // assert(u.length() > 0);
  // assert(p.length() > 0);
  // assert(req.size() > 0);
  // return false;
  //check format
  if(u.length() > LEN_UNAME || p.length() > LEN_PASSWORD||u.empty() || p.empty())
  {
    send_reliably(sd, aes_crypt_msg(ctx,RES_ERR_LOGIN));
  }
  else
  {
    vector<uint8_t> contentget;
    //copydata
    //still incorrect format..
    contentget.insert(contentget.end(), req.begin() + 3*sizeof(int32_t) + u.size() + p.size(),req.end());
    // Set the user data
    Storage::result_t setres = storage->set_user_data(u, p, contentget);

    send_reliably(sd,aes_crypt_msg(ctx,setres.msg));
    
  }
  return false;
}

/// Respond to a GET command by getting the data for a user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param u       The user name associated with the request
/// @param p       The password associated with the request
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_get(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const std::string &u, const std::string &p,
                const vector<uint8_t> &req) {
  //cout << "responses.cc::handle_get() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  // assert(sd);
  // assert(storage);
  // assert(ctx);
  // assert(u.length() > 0);
  // assert(p.length() > 0);
  // assert(req.size() > 0);
  // return false;
  //check format
  if(u.length() > LEN_UNAME || p.length() > LEN_PASSWORD||u.empty() || p.empty())
  {
    send_reliably(sd, aes_crypt_msg(ctx,RES_ERR_LOGIN));
  }
  else
  {
  //name of the user whose data is requested
  //get length
  int32_t namelen;
  memcpy(&namelen, req.data() + sizeof(int32_t) * 3, sizeof(int32_t));

  //get user name
  std::string targetuser(req.begin() + sizeof(int32_t) * 4, req.begin() + sizeof(int32_t) * 4 + namelen);

  //get data
  Storage::result_t getdatares = storage->get_user_data(u, p, targetuser);

  if (getdatares.succeeded) {
    //respond the data
    vector<uint8_t> responsessss;
    responsessss.insert(responsessss.end(), getdatares.msg.begin(), getdatares.msg.end());

    int32_t profileSize = static_cast<int32_t>(getdatares.data.size());
    vector<uint8_t> databytes(sizeof(int32_t));
    memcpy(databytes.data(), &profileSize, sizeof(int32_t));

    //insert data getted
    responsessss.insert(responsessss.end(), databytes.begin(), databytes.end());
    responsessss.insert(responsessss.end(), getdatares.data.begin(), getdatares.data.end());
    send_reliably(sd, aes_crypt_msg(ctx, responsessss));
  } else {
    //if failed to get data get_user_data(u, p, targetuser)
    send_reliably(sd, aes_crypt_msg(ctx, getdatares.msg));
  }

  }
  

  return false;
}

/// Respond to a REG command by trying to add a new user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param u       The user name associated with the request
/// @param p       The password associated with the request
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_reg(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const std::string &u, const std::string &p,
                const vector<uint8_t> &) {
  //cout << "responses.cc::handle_reg() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  // assert(sd);
  // assert(storage);
  // assert(ctx);
  // assert(u.length() > 0);
  // assert(p.length() > 0);
  // return false;
  //check format
  if (u.length() > LEN_UNAME || p.length() > LEN_PASSWORD) {
    send_reliably(sd, aes_crypt_msg(ctx, RES_ERR_REQ_FMT));
  }
  else
  {
    //register new user
    Storage::result_t addres = storage->add_user(u, p);

    send_reliably(sd, aes_crypt_msg(ctx, addres.msg));
    
  }
  return false;
}

/// In response to a request for a key, do a reliable send of the contents of
/// the pubfile
///
/// @param sd The socket on which to write the pubfile
/// @param pubfile A vector consisting of pubfile contents
///
/// @return false, to indicate that the server shouldn't stop
bool handle_key(int sd, const vector<uint8_t> &pubfile) {
  //cout << "responses.cc::handle_key() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  // assert(sd);
  // assert(pubfile.size() > 0);
  // return false;
  send_reliably(sd, pubfile);
  // if(!sendbytes){
  //   cout << "ERROR key";
  //   return true;
  // }
  return false;
}

/// Respond to a BYE command by returning false, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param u       The user name associated with the request
/// @param p       The password associated with the request
/// @param req     The unencrypted contents of the request
///
/// @return true, to indicate that the server should stop, or false on an error
bool handle_bye(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const std::string &u, const std::string &p,
                const vector<uint8_t> &) {
  //cout << "responses.cc::handle_bye() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  // assert(sd);
  // assert(storage);
  // assert(ctx);
  // assert(u.length() > 0);
  // assert(p.length() > 0);
  // return false;
  //check format
  if (u.length() > LEN_UNAME || p.length() > LEN_PASSWORD||u.empty() || p.empty()) {
    send_reliably(sd, aes_crypt_msg(ctx, RES_ERR_REQ_FMT));
  }
  else
  {
    Storage::result_t matched = storage->auth(u, p);

    send_reliably(sd,aes_crypt_msg(ctx,matched.msg));
    //proceed to stop
    if(matched.succeeded)
    {
      return true;
    }
    
  }

  return false;
  
}

/// Respond to a SAV command by persisting the file, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param u       The user name associated with the request
/// @param p       The password associated with the request
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_sav(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const std::string &u, const std::string &p,
                const vector<uint8_t> &) {
  //cout << "responses.cc::handle_sav() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  // assert(sd);
  // assert(storage);
  // assert(ctx);
  // assert(u.length() > 0);
  // assert(p.length() > 0);
  // return false;
  if (u.length() > LEN_UNAME || p.length() > LEN_PASSWORD||u.empty() || p.empty()) {
    send_reliably(sd, aes_crypt_msg(ctx, RES_ERR_REQ_FMT));
  }
  else
  {
    Storage::result_t matched = storage->auth(u, p);

    if(matched.succeeded)
    {
      Storage::result_t res2 = storage->save_file();
      send_reliably(sd, aes_crypt_msg(ctx, res2.msg));
    }
    else
    {
      send_reliably(sd, aes_crypt_msg(ctx, matched.msg));
    }
  }
  
  
  return false;
}
