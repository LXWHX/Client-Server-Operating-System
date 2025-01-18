#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include <vector>
#include <fstream>

#include "../common/constants.h"
#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"

#include "requests.h"

using namespace std;

///still error when implementing the request.cc back to default.

//fixed

/// Send a message to the server, using the common format for secure messages,
/// then take the response from the server, decrypt it, and return it.
///
/// @param sd  An open socket
/// @param pubkey The server's public key, for encrypting the aes key
/// @param user     The username for the request
/// @param password The password for the request....
/// @param cmd The command that is being sent....
/// @param msg The contents of the @ablock
///
/// @returns a vector with the (decrypted) result, or an empty vector on error
vector<uint8_t> send_cmd(int sd, EVP_PKEY* pubkey, const string &cmd, const string &user, const string &password, const vector<uint8_t> &msg) {
  //response block, encrypted  auth block, aes jey
  vector<uint8_t> r_block, enauth_block, aes_key = create_aes_key();

  // Prepare enauth_block with user and password
  //add user len + pad
  uint32_t user_length = static_cast<uint32_t>(user.size());
  for(size_t i = 0; i < sizeof(uint32_t); i++){
      enauth_block.push_back((user_length >> (8 * i)) & 0xFF);
  }
  enauth_block.insert(enauth_block.end(), user.begin(), user.end());

  //add passwordlen
  long passLength = static_cast<long>(password.size());
  for(size_t i = 0; i < sizeof(long); i++){
      enauth_block.push_back((passLength >> (8 * i)) & 0xff);
  }
  enauth_block.insert(enauth_block.end(), password.begin(), password.end());

  //add msg content to enauth_block
  enauth_block.insert(enauth_block.end(), msg.begin(), msg.end());

  //enauth_block use aes key encrypt
  enauth_block = aes_crypt_msg(create_aes_context(aes_key, true), enauth_block);

  //add cmd and aes key to rblock
  r_block.insert(r_block.end(), cmd.begin(), cmd.end());
  r_block.insert(r_block.end(), aes_key.begin(), aes_key.end());
  //add enauth_block.size as byte
  for(size_t i = 0; i < sizeof(long); i++){
      r_block.push_back((enauth_block.size() >> (8 * i)) & 0xff);
  }
  // padd
  if (LEN_RBLOCK_CONTENT > r_block.size()) {
      vector<uint8_t> padding(LEN_RBLOCK_CONTENT - r_block.size());
      if (RAND_bytes(padding.data(), padding.size()) != 1) {
          cerr << "Error exit pad randbytes\n";
          return {};
      }
      r_block.insert(r_block.end(), padding.begin(), padding.end());
  }

  //r_block pubkey encrypt
  size_t out_len = 0;
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, nullptr);
  //initialize
  if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
      cerr << "Error encrypt r_block ini\n";
      if (ctx) EVP_PKEY_CTX_free(ctx);
      return {};
  }
  //encrypt len
  if (EVP_PKEY_encrypt(ctx, nullptr, &out_len, r_block.data(), r_block.size()) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      cerr << "Error in rblock len\n";
      return {};
  }
  //encrypt
  vector<uint8_t> enc_rblock(out_len);
  if (EVP_PKEY_encrypt(ctx, enc_rblock.data(), &out_len, r_block.data(), r_block.size()) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      cerr << "Error encrypt r_block\n";
      return {};
  }
  //EVP_PKEY_CTX_free is release resource
  EVP_PKEY_CTX_free(ctx); 

  //combine enc_rblock and enauth_block 
  vector<uint8_t> totalBlock(enc_rblock);
  totalBlock.insert(totalBlock.end(), enauth_block.begin(), enauth_block.end());
  // Send to server
  if (send_reliably(sd, totalBlock) <= 0) {
      cerr << "Error send data to server\n";
      return {};
  }
  // Receive response and decrypt
  vector<uint8_t> response = reliable_get_to_eof(sd);
  if (response.empty()) {
    cerr << "Error response from server\n";
      return {};
  }
  if (string(response.begin(), response.begin() + RES_ERR_CRYPTO.length()) == RES_ERR_CRYPTO) {
      cerr << "Error ERR_CRYPT from server\n";
      return {};
  }
  vector<uint8_t> decrypt_response = aes_crypt_msg(create_aes_context(aes_key, false), response);
  if (string(decrypt_response.begin(), decrypt_response.begin() + 3) == "ERR") {
      cerr << string(decrypt_response.begin(), decrypt_response.end()) << endl;
      return {};
  }

  
  return decrypt_response;
}


/// If a buffer consists of RES_OK.bbbb.d+, where `.` means concatenation, bbbb
/// is a 4-byte binary integer and d+ is a string of characters, write the bytes
/// (d+) to a file
///
/// @param buf      The buffer holding a response
/// @param filename The name of the file to write
void send_result_to_file(const std::vector<uint8_t> &buf, const string &filename){
  //buffer contain at least RES_OK, 4 byte int and 1 char
    if (buf.size() < RES_OK.size() + 5) {
        cerr << "ERROR: Buffer too small." << endl;
        return;
    }

    // check buff RES_OK
    if (string(buf.begin(), buf.begin() + RES_OK.size()) == RES_OK) {
        // get size to write
        int size = 0;
        memcpy(&size, &buf[RES_OK.size()], sizeof(int));
        //check buff size enough
        if (size > 0 && buf.size() >= RES_OK.size() + 4 + size) { 
            ofstream file(filename, ios::binary);
            if (!file) {
                cerr << "Error open file" << endl;
                return;
            }

            //write
            file.write(reinterpret_cast<const char*>(&buf[RES_OK.size() + 4]), size);
            if (!file) {
                cerr << "Error write.file" << endl;
                return;
            }
            cout << RES_OK << endl;
        } else {
            cerr << "Error buff size." << endl;
        }
    }
}



/// req_key() writes a request for the server's key on a socket descriptor.
/// When it gets a key back, it writes it to a file.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param keyfile The name of the file to which the key should be written
void req_key(int sd, const string &keyfile) {
  // "KEY_"
    vector<uint8_t> get_reqkey(REQ_KEY.begin(), REQ_KEY.end()); 

    //send request to server
    if (send_reliably(sd, get_reqkey) <= 0) {
        cerr << "Error send key request to server" << endl;
        exit(EXIT_FAILURE);
    }

    //receive pubkey from server
    vector<uint8_t> pubkey(LEN_RSA_PUBKEY);

    //receive the pubkey into the vector
    if (reliable_get_to_eof_or_n(sd, pubkey.begin(), LEN_RSA_PUBKEY) <= 0) {
        cerr << "Error receive public key from server" << endl;
        exit(EXIT_FAILURE);
    }

    //write pubkey to file
    ofstream keyOutFile(keyfile, ios::binary);
    if (!keyOutFile) {
        cerr << "Error open file" << endl;
        exit(EXIT_FAILURE);
    }
    keyOutFile.write(reinterpret_cast<const char*>(pubkey.data()), pubkey.size());
    if (!keyOutFile.good()) {
        cerr << "Error write public key to file" << endl;
        exit(EXIT_FAILURE);
    }
  
}

/// req_reg() sends the REG command to register a new user
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_reg(int sd, EVP_PKEY *pubkey, const string &user, const string &pass,
             const string &) {
  vector<uint8_t> decrypt_response = send_cmd(sd, pubkey, REQ_REG, user, pass, {});
  cout << string(decrypt_response.begin(), decrypt_response.end()) << endl;
}

/// req_bye() writes a request for the server to exit.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_bye(int sd, EVP_PKEY *pubkey, const string &user, const string &pass,
             const string &) {
  vector<uint8_t> decrypt_response = send_cmd(sd, pubkey, REQ_BYE, user, pass, {});
  cout << string(decrypt_response.begin(), decrypt_response.end()) << endl;
}

/// req_sav() writes a request for the server to save its contents
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_sav(int sd, EVP_PKEY *pubkey, const string &user, const string &pass,
             const string &) {
  vector<uint8_t> decrypt_response = send_cmd(sd, pubkey, REQ_SAV, user, pass, {});
  cout << string(decrypt_response.begin(), decrypt_response.end()) << endl;
}

/// req_set() sends the SET command to set the content for a user
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param setfile The file whose contents should be sent
void req_set(int sd, EVP_PKEY *pubkey, const string &user, const string &pass,
             const string &setfile) {
  vector<uint8_t> fileContent = load_entire_file(setfile);
  vector<uint8_t> decrypt_response = send_cmd(sd, pubkey, REQ_SET, user, pass, fileContent);
  cout << string(decrypt_response.begin(), decrypt_response.end()) << endl;
}

/// req_get() requests the content associated with a user, and saves it to a
/// file called <user>.file.dat.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param getname The name of the user whose content should be fetched
void req_get(int sd, EVP_PKEY *pubkey, const string &user, const string &pass,
             const string &getname) {
  vector<uint8_t> getnameContent(getname.begin(), getname.end());
  vector<uint8_t> decrypt_response = send_cmd(sd, pubkey, REQ_GET, user, pass, getnameContent);
  send_result_to_file(decrypt_response, user + ".file.dat");
}

/// req_all() sends the ALL command to get a listing of all users, formatted
/// as text with one entry per line.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param allfile The file where the result should go
void req_all(int sd, EVP_PKEY *pubkey, const string &user, const string &pass,
             const string &allfile) {
  vector<uint8_t> decrypt_response = send_cmd(sd, pubkey, REQ_ALL, user, pass, {});
  send_result_to_file(decrypt_response, allfile);
}
