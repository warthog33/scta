/* --COPYRIGHT--,BSD
 * Copyright (c) 2012, Texas Instruments Incorporated
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * *  Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * *  Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * *  Neither the name of Texas Instruments Incorporated nor the names of
 *    its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * --/COPYRIGHT--*/
/*****************************************************************************
 * DES Helper file. DES encryption procedure is done by using the following functions:
 * des_key( *(Key Structure), *key, mode);  ----- Initialises key scheduler 
 * des_enc( *(Key Structure), *data, #blocks); --- Initiates DES Encryption
 * des_dec( *(Key Structure), *data, #blocks); -- Initiates Decryption
 * 
 * mode   === EN0 (Encrypt) or DE1 (Decrypt) or ENDE (Encrypt and Decrypt)
 * blocks === # of blocks to be enc/decrypted
 *
 *DES_Enc_CBC(*(Key Structure),&data[x], #blocks); --- Adds CBC chaining to multiple blocks.Encode
 *
 *  3DES is as follows:
 * TripleDES_ENC( des_ctx *(Key Structure),unsigned char *data, short blocks,unsigned char *key1, unsigned char *key2,unsigned char *key3)
 * TripleDES_DEC( des_ctx *(Key Structure),unsigned char *data, short blocks,unsigned char *key1, unsigned char *key2,unsigned char *key3)
 *
 * Modified by JH 4/27/12 --- inital release
 *                         -- Formatting Changes
 *                         -- 3DES Added
 * Modified 6/4/12 by JH  --- Adding CBC funcitonality
 */

/// Modes ///

#define EN0   0      /* MODE == encrypt */
#define DE1   1      /* MODE == decrypt */
#define ENDE  2     /* MODE == Encrypt and Decrypt */


/// Key Structure Definition  ///
typedef struct {
  unsigned long ek[32];
 unsigned long dk[32];
} des_ctx;

/// Function Declarations  ///

extern void DES_Enc_CBC (des_ctx *dc,unsigned char *pucData, short sBlocks, unsigned char *pucIV);
extern void DES_Dec_CBC (des_ctx *dc,unsigned char *pucData, short sBlocks, unsigned char *pucIV);

extern void TripleDES_ENC_CBC( des_ctx *dc,unsigned char *pucData, short sBlocks, unsigned char *pucIV, unsigned char *pucKey1,unsigned char *pucKey2,unsigned char *pucKey3);
extern void TripleDES_DEC_CBC( des_ctx *dc,unsigned char *pucData, short sBlocks, unsigned char *pucIV, unsigned char *pucKey1,unsigned char *pucKey2,unsigned char *pucKey3);


extern void Des_Key(des_ctx *dc, unsigned char *pucKey, short sMode);
/* 
 * Function that starts key schedule.
 */

extern void Des_Enc(des_ctx *dc, unsigned char *pucData, short sBlocks);
/*
 * Function that starts encoding
 */

extern void Des_Dec(des_ctx *dc, unsigned char *pucData, short sBlocks);
/*
 * Function that starts decoding
 */

extern void TripleDES_ENC( des_ctx *dc,unsigned char *pucData, short sBlocks, unsigned char *pucKey1, unsigned char *pucKey2, unsigned char *pucKey3);

extern void TripleDES_DEC( des_ctx *dc,unsigned char *pucData, short sBlocks, unsigned char *pucKey1, unsigned char *pucKey2, unsigned char *pucKey3);



 void deskey(unsigned char *, short);
/*                  hexkey[8]     MODE
 * Sets the internal key register according to the hexadecimal
 * key contained in the 8 bytes of hexkey, according to the DES,
 * for encryption or decryption according to MODE.
 */
 void usekey(unsigned long *);
/*                cookedkey[32]
 * Loads the internal key register with the data in cookedkey.
 */

 void cpkey(unsigned long *);
/*               cookedkey[32]
 * Copies the contents of the internal key register into the storage
 * located at &cookedkey[0].
 */

 void des(unsigned char *, unsigned char *);
/*                from[8]         to[8]
 * Encrypts/Decrypts (according to the key currently loaded in the
 * internal key register) one block of eight bytes at address 'from'
 * into the block at address 'to'.  They can be the same.
 */

static void scrunch(unsigned char *, unsigned long *);
static void unscrun(unsigned long *, unsigned char *);
static void desfunc(unsigned long *, unsigned long *);
static void cookey(unsigned long *);


/// Algorithm Arrays ///

static unsigned long KnL[32] = { 0L };
static unsigned long KnR[32] = { 0L };
static unsigned long Kn3[32] = { 0L };
static const unsigned char Df_Key[24] = {
       0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
       0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67 };

static const unsigned short bytebit[8]    = {
       0200, 0100, 040, 020, 010, 04, 02, 01 };

static const unsigned long bigbyte[24] = {
       0x800000L,    0x400000L,     0x200000L,    0x100000L,
       0x80000L,     0x40000L,      0x20000L,     0x10000L,
       0x8000L,      0x4000L,       0x2000L,      0x1000L,
       0x800L,              0x400L,               0x200L,              0x100L,
       0x80L,               0x40L,                0x20L,               0x10L,
       0x8L,         0x4L,          0x2L,         0x1L   };

/* Use the key schedule specified in the Standard (ANSI X3.92-1981). */

static const unsigned char pc1[56] = {
       56, 48, 40, 32, 24, 16,  8,   0, 57, 49, 41, 33, 25, 17,
        9,  1, 58, 50, 42, 34, 26,  18, 10,  2, 59, 51, 43, 35,
       62, 54, 46, 38, 30, 22, 14,   6, 61, 53, 45, 37, 29, 21,
       13,  5, 60, 52, 44, 36, 28,  20, 12,  4, 27, 19, 11,  3 };

static const unsigned char totrot[16] = {
       1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28 };

static const unsigned char pc2[48] = {
       13, 16, 10, 23,  0,  4,       2, 27, 14,  5, 20,  9,
       22, 18, 11,  3, 25,  7,      15,  6, 26, 19, 12,  1,
       40, 51, 30, 36, 46, 54,      29, 39, 50, 44, 32, 47,
       43, 48, 38, 55, 33, 52,      45, 41, 49, 35, 28, 31 };

	   
/// S-Boxes ///

static const unsigned long SP1[64] = {
  0x01010400L, 0x00000000L, 0x00010000L, 0x01010404L,
  0x01010004L, 0x00010404L, 0x00000004L, 0x00010000L,
  0x00000400L, 0x01010400L, 0x01010404L, 0x00000400L,
  0x01000404L, 0x01010004L, 0x01000000L, 0x00000004L,
  0x00000404L, 0x01000400L, 0x01000400L, 0x00010400L,
  0x00010400L, 0x01010000L, 0x01010000L, 0x01000404L,
  0x00010004L, 0x01000004L, 0x01000004L, 0x00010004L,
  0x00000000L, 0x00000404L, 0x00010404L, 0x01000000L,
  0x00010000L, 0x01010404L, 0x00000004L, 0x01010000L,
  0x01010400L, 0x01000000L, 0x01000000L, 0x00000400L,
  0x01010004L, 0x00010000L, 0x00010400L, 0x01000004L,
  0x00000400L, 0x00000004L, 0x01000404L, 0x00010404L,
  0x01010404L, 0x00010004L, 0x01010000L, 0x01000404L,
  0x01000004L, 0x00000404L, 0x00010404L, 0x01010400L,
  0x00000404L, 0x01000400L, 0x01000400L, 0x00000000L,
  0x00010004L, 0x00010400L, 0x00000000L, 0x01010004L };

static const unsigned long SP2[64] = {
  0x80108020L, 0x80008000L, 0x00008000L, 0x00108020L,
  0x00100000L, 0x00000020L, 0x80100020L, 0x80008020L,
  0x80000020L, 0x80108020L, 0x80108000L, 0x80000000L,
  0x80008000L, 0x00100000L, 0x00000020L, 0x80100020L,
  0x00108000L, 0x00100020L, 0x80008020L, 0x00000000L,
  0x80000000L, 0x00008000L, 0x00108020L, 0x80100000L,
  0x00100020L, 0x80000020L, 0x00000000L, 0x00108000L,
  0x00008020L, 0x80108000L, 0x80100000L, 0x00008020L,
  0x00000000L, 0x00108020L, 0x80100020L, 0x00100000L,
  0x80008020L, 0x80100000L, 0x80108000L, 0x00008000L,
  0x80100000L, 0x80008000L, 0x00000020L, 0x80108020L,
  0x00108020L, 0x00000020L, 0x00008000L, 0x80000000L,
  0x00008020L, 0x80108000L, 0x00100000L, 0x80000020L,
  0x00100020L, 0x80008020L, 0x80000020L, 0x00100020L,
  0x00108000L, 0x00000000L, 0x80008000L, 0x00008020L,
  0x80000000L, 0x80100020L, 0x80108020L, 0x00108000L };

static const unsigned long SP3[64] = {
  0x00000208L, 0x08020200L, 0x00000000L, 0x08020008L,
  0x08000200L, 0x00000000L, 0x00020208L, 0x08000200L,
  0x00020008L, 0x08000008L, 0x08000008L, 0x00020000L,
  0x08020208L, 0x00020008L, 0x08020000L, 0x00000208L,
  0x08000000L, 0x00000008L, 0x08020200L, 0x00000200L,
  0x00020200L, 0x08020000L, 0x08020008L, 0x00020208L,
  0x08000208L, 0x00020200L, 0x00020000L, 0x08000208L,
  0x00000008L, 0x08020208L, 0x00000200L, 0x08000000L,
  0x08020200L, 0x08000000L, 0x00020008L, 0x00000208L,
  0x00020000L, 0x08020200L, 0x08000200L, 0x00000000L,
  0x00000200L, 0x00020008L, 0x08020208L, 0x08000200L,
  0x08000008L, 0x00000200L, 0x00000000L, 0x08020008L,
  0x08000208L, 0x00020000L, 0x08000000L, 0x08020208L,
  0x00000008L, 0x00020208L, 0x00020200L, 0x08000008L,
  0x08020000L, 0x08000208L, 0x00000208L, 0x08020000L,
  0x00020208L, 0x00000008L, 0x08020008L, 0x00020200L };

static const unsigned long SP4[64] = {
  0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
  0x00802080L, 0x00800081L, 0x00800001L, 0x00002001L,
  0x00000000L, 0x00802000L, 0x00802000L, 0x00802081L,
  0x00000081L, 0x00000000L, 0x00800080L, 0x00800001L,
  0x00000001L, 0x00002000L, 0x00800000L, 0x00802001L,
  0x00000080L, 0x00800000L, 0x00002001L, 0x00002080L,
  0x00800081L, 0x00000001L, 0x00002080L, 0x00800080L,
  0x00002000L, 0x00802080L, 0x00802081L, 0x00000081L,
  0x00800080L, 0x00800001L, 0x00802000L, 0x00802081L,
  0x00000081L, 0x00000000L, 0x00000000L, 0x00802000L,
  0x00002080L, 0x00800080L, 0x00800081L, 0x00000001L,
  0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
  0x00802081L, 0x00000081L, 0x00000001L, 0x00002000L,
  0x00800001L, 0x00002001L, 0x00802080L, 0x00800081L,
  0x00002001L, 0x00002080L, 0x00800000L, 0x00802001L,
  0x00000080L, 0x00800000L, 0x00002000L, 0x00802080L };

static const unsigned long SP5[64] = {
  0x00000100L, 0x02080100L, 0x02080000L, 0x42000100L,
  0x00080000L, 0x00000100L, 0x40000000L, 0x02080000L,
  0x40080100L, 0x00080000L, 0x02000100L, 0x40080100L,
  0x42000100L, 0x42080000L, 0x00080100L, 0x40000000L,
  0x02000000L, 0x40080000L, 0x40080000L, 0x00000000L,
  0x40000100L, 0x42080100L, 0x42080100L, 0x02000100L,
  0x42080000L, 0x40000100L, 0x00000000L, 0x42000000L,
  0x02080100L, 0x02000000L, 0x42000000L, 0x00080100L,
  0x00080000L, 0x42000100L, 0x00000100L, 0x02000000L,
  0x40000000L, 0x02080000L, 0x42000100L, 0x40080100L,
  0x02000100L, 0x40000000L, 0x42080000L, 0x02080100L,
  0x40080100L, 0x00000100L, 0x02000000L, 0x42080000L,
  0x42080100L, 0x00080100L, 0x42000000L, 0x42080100L,
  0x02080000L, 0x00000000L, 0x40080000L, 0x42000000L,
  0x00080100L, 0x02000100L, 0x40000100L, 0x00080000L,
  0x00000000L, 0x40080000L, 0x02080100L, 0x40000100L };

static const unsigned long SP6[64] = {
  0x20000010L, 0x20400000L, 0x00004000L, 0x20404010L,
  0x20400000L, 0x00000010L, 0x20404010L, 0x00400000L,
  0x20004000L, 0x00404010L, 0x00400000L, 0x20000010L,
  0x00400010L, 0x20004000L, 0x20000000L, 0x00004010L,
  0x00000000L, 0x00400010L, 0x20004010L, 0x00004000L,
  0x00404000L, 0x20004010L, 0x00000010L, 0x20400010L,
  0x20400010L, 0x00000000L, 0x00404010L, 0x20404000L,
  0x00004010L, 0x00404000L, 0x20404000L, 0x20000000L,
  0x20004000L, 0x00000010L, 0x20400010L, 0x00404000L,
  0x20404010L, 0x00400000L, 0x00004010L, 0x20000010L,
  0x00400000L, 0x20004000L, 0x20000000L, 0x00004010L,
  0x20000010L, 0x20404010L, 0x00404000L, 0x20400000L,
  0x00404010L, 0x20404000L, 0x00000000L, 0x20400010L,
  0x00000010L, 0x00004000L, 0x20400000L, 0x00404010L,
  0x00004000L, 0x00400010L, 0x20004010L, 0x00000000L,
  0x20404000L, 0x20000000L, 0x00400010L, 0x20004010L };

static const unsigned long SP7[64] = {
  0x00200000L, 0x04200002L, 0x04000802L, 0x00000000L,
  0x00000800L, 0x04000802L, 0x00200802L, 0x04200800L,
  0x04200802L, 0x00200000L, 0x00000000L, 0x04000002L,
  0x00000002L, 0x04000000L, 0x04200002L, 0x00000802L,
  0x04000800L, 0x00200802L, 0x00200002L, 0x04000800L,
  0x04000002L, 0x04200000L, 0x04200800L, 0x00200002L,
  0x04200000L, 0x00000800L, 0x00000802L, 0x04200802L,
  0x00200800L, 0x00000002L, 0x04000000L, 0x00200800L,
  0x04000000L, 0x00200800L, 0x00200000L, 0x04000802L,
  0x04000802L, 0x04200002L, 0x04200002L, 0x00000002L,
  0x00200002L, 0x04000000L, 0x04000800L, 0x00200000L,
  0x04200800L, 0x00000802L, 0x00200802L, 0x04200800L,
  0x00000802L, 0x04000002L, 0x04200802L, 0x04200000L,
  0x00200800L, 0x00000000L, 0x00000002L, 0x04200802L,
  0x00000000L, 0x00200802L, 0x04200000L, 0x00000800L,
  0x04000002L, 0x04000800L, 0x00000800L, 0x00200002L };

static const unsigned long SP8[64] = {
  0x10001040L, 0x00001000L, 0x00040000L, 0x10041040L,
  0x10000000L, 0x10001040L, 0x00000040L, 0x10000000L,
  0x00040040L, 0x10040000L, 0x10041040L, 0x00041000L,
  0x10041000L, 0x00041040L, 0x00001000L, 0x00000040L,
  0x10040000L, 0x10000040L, 0x10001000L, 0x00001040L,
  0x00041000L, 0x00040040L, 0x10040040L, 0x10041000L,
  0x00001040L, 0x00000000L, 0x00000000L, 0x10040040L,
  0x10000040L, 0x10001000L, 0x00041040L, 0x00040000L,
  0x00041040L, 0x00040000L, 0x10041000L, 0x00001000L,
  0x00000040L, 0x10040040L, 0x00001000L, 0x00041040L,
  0x10001000L, 0x00000040L, 0x10000040L, 0x10040000L,
  0x10040040L, 0x10000000L, 0x00040000L, 0x10001040L,
  0x00000000L, 0x10041040L, 0x00040040L, 0x10000040L,
  0x10040000L, 0x10001000L, 0x10001040L, 0x00000000L,
  0x10041040L, 0x00041000L, 0x00041000L, 0x00001040L,
  0x00001040L, 0x00040040L, 0x10000000L, 0x10041000L };
