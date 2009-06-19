
#ifndef _CONSTANTS_HEADER_FILE
#define _CONSTANTS_HEADER_FILE


// common constants

// GOST R 34.10-2001 key length 
// Private key hex representation length in chars
#define PRIVATEKEY_CHAR_LEN 64
// byte length
#define PRIVATEKEY_BYTE_LEN 32

// Public key hex representation length in chars
#define PUBLICKEY_CHAR_LEN 128
// byte length
#define PUBLICKEY_BYTE_LEN 64

// GOST R 34.11-94 hash Length
#define HASH_BYTE_LEN 32

// GOST 28147-89 encrypt/decrypt block length in bytes.
#define CRYPTBLOCK_BYTE_LEN 32


// length in bytes of GOST R 34.11-94 algorithm hash-function
const int GOSTR341194ByteLen = 32;

// length in bytes of signature produced by GOST R 34.10-2001 algorithm
const int GOSTR34102001SigLen = 64;

// кол-во цифр (32-битных слов) в большом числе (длина числа)
const int iBNSize = 8;

#endif //_CONSTANTS_HEADER_FILE