// MIT License
//
// Copyright (c) 2019 Enix Yu
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// port

#include <stdlib.h>

typedef uint8_t BLOWFISH_UINT8;
typedef uint16_t BLOWFISH_UINT16;
typedef uint32_t BLOWFISH_UINT32;
typedef unsigned char BLOWFISH_BYTE;
typedef unsigned long BLOWFISH_SIZE_T;

typedef BLOWFISH_UINT8 BLOWFISH_Buffer[8];

// A Cipher is an instance of Blowfish encryption using a particular key.
typedef struct
{
  BLOWFISH_UINT32 p[18];
  BLOWFISH_UINT32 s0[256];
  BLOWFISH_UINT32 s1[256];
  BLOWFISH_UINT32 s2[256];
  BLOWFISH_UINT32 s3[256];
} Blowfish_Cipher;

typedef enum
{
  // No error
  Blowfish_ErrorCodeOK = 0,
  // Invalid key len
  Blowfish_ErrorCodeInvalidKeyLen = 1,
} Blowfish_ErrorCode;

//
// Export Function prototype
//

// Blowfish_InitCipher init a Cipher.
// The key argument should be the Blowfish key, from 1 to 56 bytes.
Blowfish_ErrorCode Blowfish_InitCipher(Blowfish_Cipher *cipher, BLOWFISH_UINT8 *key, BLOWFISH_SIZE_T keyLen);

// Blowfish_InitSaltedCipher init a Cipher that folds a salt into its key
// schedule. For most purposes, NewCipher, instead of NewSaltedCipher, is
// sufficient and desirable. For bcrypt compatibility, the key can be over 56
// bytes.
Blowfish_ErrorCode Blowfish_InitSaltedCipher(Blowfish_Cipher *cipher, BLOWFISH_UINT8 *key, BLOWFISH_SIZE_T keyLen, BLOWFISH_UINT8 *salt, BLOWFISH_SIZE_T saltLen);

// Blowfish_Encrypt encrypts the 8-byte buffer src using the key k
// and stores the result in dst.
// Note that for amounts of data larger than a block,
// it is not safe to just call Encrypt on successive blocks;
// instead, use an encryption mode like CBC (see crypto/cipher/cbc.go).
void Blowfish_Encrypt(Blowfish_Cipher *c, BLOWFISH_UINT8 *dst, const BLOWFISH_UINT8 *src);

// Blowfish_Decrypt decrypts the 8-byte buffer src using the key k
// and stores the result in dst.
void Blowfish_Decrypt(Blowfish_Cipher *c, BLOWFISH_UINT8 *dst, const BLOWFISH_UINT8 *src);
