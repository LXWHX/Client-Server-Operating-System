/**
 * crypto_rsa.cc
 *
 * Crypto_rsa demonstrates how to use public/private key RSA
 * encryption/decryption on a small chunk of data.
 *
 * Note that RSA keys are usually long-lived, so be sure to keep your private
 * key private!  Also, remember that RSA is slow, and often just used to sign a
 * digest or secure the transmission of an AES key that then gets used for the
 * actual encryption/decryption.
 */

#include <cassert>
#include <cstring>
#include <openssl/pem.h>
#include <string>
#include <unistd.h>

/** size of RSA key */
const int RSA_KEY_SIZE = 2048;

/**
 * Display a help message to explain how the command-line parameters for this
 * program work
 *
 * @progname The name of the program
 */
void usage(char *progname) {
  printf("%s: Perform basic RSA encryption/decryption tasks.\n",
         basename(progname));
  printf("  -b [string] Name of the file holding the RSA public key\n");
  printf("  -v [string] Name of the file holding the RSA private key\n");
  printf("  -i [string] Name of the input file to encrypt/decrypt\n");
  printf("  -o [string] Name of the output file to produce\n");
  printf("  -d          Decrypt from input to output using key\n");
  printf("  -e          Encrypt from input to output using key\n");
  printf("  -g          Generate a key file\n");
  printf("  -h       Print help (this message)\n");
}

/** arg_t is used to store the command-line arguments of the program */
struct arg_t {
  /** The file holding the public RSA key */
  std::string pub_key_file;

  /** The file holding the private RSA key */
  std::string pri_key_file;

  /** The input file */
  std::string infile;

  /** The output file */
  std::string outfile;

  /** Should we decrypt? */
  bool decrypt = false;

  /** Should we encrypt? */
  bool encrypt = false;

  /** Should we generate a key? */
  bool generate = false;

  /** Display a usage message? */
  bool usage = false;
};

/**
 * Parse the command-line arguments, and use them to populate the provided args
 * object.
 *
 * @param argc The number of command-line arguments passed to the program
 * @param argv The list of command-line arguments
 * @param args The struct into which the parsed args should go
 */
void parse_args(int argc, char **argv, arg_t &args) {
  long opt;
  while ((opt = getopt(argc, argv, "b:v:i:o:degh")) != -1) {
    switch (opt) {
    case 'b':
      args.pub_key_file = std::string(optarg);
      break;
    case 'v':
      args.pri_key_file = std::string(optarg);
      break;
    case 'i':
      args.infile = std::string(optarg);
      break;
    case 'o':
      args.outfile = std::string(optarg);
      break;
    case 'd':
      args.decrypt = true;
      break;
    case 'e':
      args.encrypt = true;
      break;
    case 'g':
      args.generate = true;
      break;
    case 'h':
      args.usage = true;
      break;
    }
  }
}
/**
 * Print an error message and exit the program
 *
 * @param err The error code to return
 * @param msg The message to display
 */
void print_error_and_exit(int err, const char *msg) {
  fprintf(stderr, "%s\n", msg);
  exit(err);
}

/**
 * Produce an RSA key and save its public and private parts to files
 *
 * @param pub The name of the public key file to generate
 * @param pri The name of the private key file to generate
 */
void generate_rsa_key_files(std::string pub, std::string pri) {
  printf("Generating RSA keys as (%s, %s)\n", pub.c_str(), pri.c_str());

  // It's very easy to make RSA keys in OpenSSL 3.0 :)
  EVP_PKEY *rsa = EVP_RSA_gen(RSA_KEY_SIZE);
  if (rsa == nullptr) {
    print_error_and_exit(0, "Error in EVP_RSA_gen()");
  }

  // Create/truncate the files
  FILE *pub_file = fopen(pub.c_str(), "w");
  if (pub_file == nullptr) {
    EVP_PKEY_free(rsa);
    print_error_and_exit(0, "Error opening public key file for output");
  }
  FILE *pri_file = fopen(pri.c_str(), "w");
  if (pri_file == nullptr) {
    EVP_PKEY_free(rsa);
    fclose(pub_file);
    print_error_and_exit(0, "Error opening private key file for output");
  }

  // Perform the writes.  Defer cleanup on error, because the cleanup is the
  // same regardless of how many of these writes succeed.
  if (PEM_write_PUBKEY(pub_file, rsa) != 1) {
    fprintf(stderr, "Error writing public key\n");
  } else if (PEM_write_PrivateKey(pri_file, rsa, NULL, NULL, 0, NULL, NULL) !=
             1) {
    fprintf(stderr, "Error writing private key\n");
  } else {
    printf("Done\n");
  }

  // Cleanup regardless of whether the writes succeeded or failed
  EVP_PKEY_free(rsa);
  fclose(pub_file);
  fclose(pri_file);
}

/**
 * Load an RSA public key from the given filename
 *
 * @param filename The name of the file that has the public key in it
 */
EVP_PKEY *load_pub(const char *filename) {
  FILE *pub = fopen(filename, "r");
  if (pub == nullptr) {
    perror("Error opening public key file");
    exit(0);
  }
  EVP_PKEY *rsa = PEM_read_PUBKEY(pub, NULL, NULL, NULL);
  if (rsa == nullptr) {
    fclose(pub);
    print_error_and_exit(0, "Error reading public key file");
  }
  return rsa;
}

/**
 * Load an RSA private key from the given filename
 *
 * @param filename The name of the file that has the private key in it
 */
EVP_PKEY *load_pri(const char *filename) {
  FILE *pri = fopen(filename, "r");
  if (pri == nullptr) {
    perror("Error opening private key file");
    exit(0);
  }
  EVP_PKEY *rsa = PEM_read_PrivateKey(pri, NULL, NULL, NULL);
  if (rsa == nullptr) {
    fclose(pri);
    print_error_and_exit(0, "Error reading private key file");
  }
  return rsa;
}

/**
 * Encrypt a file's contents and write the result to another file
 *
 * @param pub The public key
 * @param in  The file to read
 * @param out The file to populate with the result of the encryption
 */
bool rsa_encrypt(EVP_PKEY *pub, FILE *in, FILE *out) {
  // We're going to assume that the file is small, and read it straight into
  // this buffer:
  unsigned char msg[RSA_KEY_SIZE / 8] = {0};
  int bytes = fread(msg, 1, sizeof(msg), in);
  if (ferror(in)) {
    perror("Error in fread()");
    return false;
  }

  // Create an encryption context
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub, NULL);
  if (ctx == nullptr) {
    print_error_and_exit(0, "Error calling EVP_PKEY_CTX_new()");
  }
  if (1 != EVP_PKEY_encrypt_init(ctx)) {
    EVP_PKEY_CTX_free(ctx);
    print_error_and_exit(0, "Error calling EVP_PKEY_encrypt_init()");
  }

  // Encrypt into `enc`, record the #bytes in enc_count.
  //
  // First we get the size of the buffer
  size_t enc_count = 0;
  if (1 != EVP_PKEY_encrypt(ctx, nullptr, &enc_count, msg, bytes)) {
    EVP_PKEY_CTX_free(ctx);
    print_error_and_exit(0, "Error computing encrypted buffer size");
  }
  // Now make a buffer, encrypt into it, and free the context
  unsigned char enc[enc_count] = {0};
  if (1 != EVP_PKEY_encrypt(ctx, enc, &enc_count, msg, bytes)) {
    EVP_PKEY_CTX_free(ctx);
    print_error_and_exit(0, "Error calling EVP_PKEY_encrypt()");
  }
  EVP_PKEY_CTX_free(ctx);

  // Write the result to the output file
  fwrite(enc, 1, enc_count, out);
  if (ferror(out)) {
    perror("Error in fwrite()");
    return false;
  }
  return true;
}

/**
 * Decrypt a file's contents and write the result to another file
 *
 * @param pri The private key
 * @param in  The file to read
 * @param out The file to populate with the result of the encryption
 */
bool rsa_decrypt(EVP_PKEY *pri, FILE *in, FILE *out) {
  // We're going to assume that the file is small, and read it straight into
  // this buffer:
  unsigned char msg[2 * RSA_KEY_SIZE / 8] = {0};
  int bytes = fread(msg, 1, sizeof(msg), in);
  if (ferror(in)) {
    perror("Error in fread()");
    return false;
  }

  // Create a decryption context
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pri, NULL);
  if (ctx == nullptr) {
    print_error_and_exit(0, "Error calling EVP_PKEY_CTX_new()");
  }
  if (1 != EVP_PKEY_decrypt_init(ctx)) {
    EVP_PKEY_CTX_free(ctx);
    print_error_and_exit(0, "Error calling EVP_PKEY_decrypt_init()");
  }

  // Decrypt into `dec`, record the #bytes in dec_count
  size_t dec_count;
  if (1 != EVP_PKEY_decrypt(ctx, nullptr, &dec_count, msg, bytes)) {
    EVP_PKEY_CTX_free(ctx);
    print_error_and_exit(0, "Error computing decrypted buffer size");
  }
  unsigned char dec[dec_count] = {0};
  if (1 != EVP_PKEY_decrypt(ctx, dec, &dec_count, msg, bytes)) {
    EVP_PKEY_CTX_free(ctx);
    print_error_and_exit(0, "Error calling EVP_PKEY_decrypt()");
  }
  EVP_PKEY_CTX_free(ctx);

  // Write the result to the output file
  fwrite(dec, 1, dec_count, out);
  if (ferror(out)) {
    perror("Error in fwrite()");
    return false;
  }
  return true;
}

int main(int argc, char *argv[]) {
  // Parse the command-line arguments
  arg_t args;
  parse_args(argc, argv, args);
  if (args.usage) {
    usage(argv[0]);
    return 0;
  }

  if (args.generate) {
    generate_rsa_key_files(args.pub_key_file, args.pri_key_file);
    return 0;
  }

  // Open the input and output files... Output file gets truncated
  FILE *infile = fopen(args.infile.c_str(), "rb");
  if (!infile) {
    perror("Error opening input file");
    exit(0);
  }
  FILE *outfile = fopen(args.outfile.c_str(), "wb");
  if (!outfile) {
    perror("Error opening output file");
    exit(0);
  }

  // Encrypt or decrypt, and clean up
  if (args.encrypt) {
    printf("Encrypting %s to %s\n", args.infile.c_str(), args.outfile.c_str());
    EVP_PKEY *pub = load_pub(args.pub_key_file.c_str());
    if (rsa_encrypt(pub, infile, outfile)) {
      printf("Success!\n");
    }
    EVP_PKEY_free(pub);
  } else if (args.decrypt) {
    printf("Decrypting %s to %s\n", args.infile.c_str(), args.outfile.c_str());
    EVP_PKEY *pri = load_pri(args.pri_key_file.c_str());
    if (rsa_decrypt(pri, infile, outfile)) {
      printf("Success!\n");
    }
    EVP_PKEY_free(pri);
  }
  fclose(infile);
  fclose(outfile);
}