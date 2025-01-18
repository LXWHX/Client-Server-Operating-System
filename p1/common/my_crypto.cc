#include <cassert>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <vector>

#include "err.h"

using namespace std;
////
/// Run the AES symmetric encryption/decryption algorithm on a buffer of bytes.
/// Note that this will do either encryption or decryption, depending on how the
/// provided CTX has been configured.  After calling, the CTX cannot be used
/// again until it is reset.
///
/// @param ctx The pre-configured AES context to use for this operation
/// @param msg A buffer of bytes to encrypt/decrypt
///
/// @return A vector with the encrypted or decrypted result, or an empty
///         vector if there was an error
vector<uint8_t> aes_crypt_msg(EVP_CIPHER_CTX *ctx, const unsigned char *start,
                              int count) {
  //ref: https://www.cse.lehigh.edu/~spear/tutorials/viewer.html#cse303_crypto/tut.md

  // AES works on chunks of up to some size, which we store in cipher_block_size. 
  int cipher_block_size = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ctx));

  // Set up a buffer where AES puts crypted bits.  Since the last block is
  // special, we need this outside the loop.
  vector<uint8_t> out_buf(count + cipher_block_size);
  int out_len;

  // crypt in_buf into out_buf
  if (!EVP_CipherUpdate(ctx, out_buf.data(), &out_len, start, count)) {
    cerr << "Error in EVP_CipherUpdate: " << ERR_error_string(ERR_get_error(), nullptr) << endl;
    return {};
  }

  //get output length
  int final_output_len;
  // The final block needs special attention!
  if (!EVP_CipherFinal_ex(ctx, out_buf.data() + out_len, &final_output_len)) {
    cerr << "Error in EVP_CipherFinal_ex: " << ERR_error_string(ERR_get_error(), nullptr) << endl;
    return {};
  }
  //adjust for the final block
  out_buf.resize(out_len + final_output_len);

  return out_buf;
}
