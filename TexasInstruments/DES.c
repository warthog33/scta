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
/*--------------------------------------------------------------------------------
DES.C: DES Algorithm Program from the Book Applied Cryptography, Bruce Schneier
--------------------------------------------------------------------------------*/
/*This file has been modified for formatting and functionality.
 * 3DES has been added.
 * Modified by JH 4/27/12 --- inital release
 *                         -- Formatting Changes
 *                         -- 3DES Added
 * Modified 6/4/12 by JH  --- Adding CBC funcitonality
 */

#include <stdio.h>
#include "DES.h"



void CBCfunc(unsigned char* pucData, unsigned char BlockNumber){
  int i;
  for (i=0; i<8; i++){
    pucData[(BlockNumber -1)*8 + i] = pucData[(BlockNumber -2)*8 +i] ^ pucData[(BlockNumber -1)*8 +i];
  }
}


void deskey(unsigned char *key, short edf)  {
  /* Thanks to James Gillogly & Phil Karn! */
  register int i, j, l, m, n;
  unsigned char pc1m[56], pcr[56];
  unsigned long kn[32];

  for ( j = 0; j < 56; j++ ) {
    l = pc1[j];
    m = l & 07;
    pc1m[j] = (key[l >> 3] & bytebit[m]) ? 1 : 0;
  }
  for( i = 0; i < 16; i++ ) {
    if( edf == DE1 ) m = (15 - i) << 1;
    else             m = i << 1;
    n = m + 1;
    kn[m] = kn[n] = 0L;
    for( j = 0; j < 28; j++ ) {
      l = j + totrot[i];
      if( l < 28 ) pcr[j] = pc1m[l];
      else pcr[j] = pc1m[l - 28];
    }
    for( j = 28; j < 56; j++ ) {
      l = j + totrot[i];
      if( l < 56 ) pcr[j] = pc1m[l];
      else         pcr[j] = pc1m[l - 28];
    }
    for( j = 0; j < 24; j++ ) {
      if( pcr[pc2[j]] )    kn[m] |= bigbyte[j];
      if( pcr[pc2[j+24]] ) kn[n] |= bigbyte[j];
    }
  }
  cookey(kn);
}

static void cookey(unsigned long *raw1)  {
  register unsigned long *cook, *raw0;
  unsigned long dough[32];
  register int i;

  cook = dough;
  for( i = 0; i < 16; i++, raw1++ ) {
    raw0 = raw1++;
    *cook   = (*raw0 & 0x00fc0000L) << 6;
    *cook  |= (*raw0 & 0x00000fc0L) << 10;
    *cook  |= (*raw1 & 0x00fc0000L) >> 10;
    *cook++|= (*raw1 & 0x00000fc0L) >> 6;
    *cook   = (*raw0 & 0x0003f000L) << 12;
    *cook  |= (*raw0 & 0x0000003fL) << 16;
    *cook  |= (*raw1 & 0x0003f000L) >> 4;
    *cook++       |= (*raw1 & 0x0000003fL);
  }
  usekey(dough);
}

void cpkey(unsigned long *into)  {
  register unsigned long *from, *endp;

  from = KnL, endp = &KnL[32];
  while( from < endp ) *into++ = *from++;
}

void usekey(unsigned long *from)  {
  register unsigned long *to, *endp;

  to = KnL, endp = &KnL[32];
  while( to < endp ) *to++ = *from++;
}
/*
#if 0
void des(unsigned char *inblock, unsigned char *outblock)  {
  unsigned long work[2];

  scrunch(inblock, work);
  desfunc(work, KnL);
  unscrun(work, outblock);
}
#endif
*/
static void scrunch(unsigned char *outof, unsigned long *into)  {
  *into   = (*outof++ & 0xffL) << 24;
  *into  |= (*outof++ & 0xffL) << 16;
  *into  |= (*outof++ & 0xffL) << 8;
  *into++ |= (*outof++ & 0xffL);
  *into   = (*outof++ & 0xffL) << 24;
  *into  |= (*outof++ & 0xffL) << 16;
  *into  |= (*outof++ & 0xffL) << 8;
  *into  |= (*outof   & 0xffL);
}

static void unscrun(unsigned long *outof, unsigned char *into)  {
  *into++ = (*outof >> 24) & 0xffL;
  *into++ = (*outof >> 16) & 0xffL;
  *into++ = (*outof >>  8) & 0xffL;
  *into++ =  *outof++      & 0xffL;
  *into++ = (*outof >> 24) & 0xffL;
  *into++ = (*outof >> 16) & 0xffL;
  *into++ = (*outof >>  8) & 0xffL;
  *into   =  *outof     & 0xffL;
}


static void desfunc(unsigned long *block, unsigned long *keys)  {
  register unsigned long fval, work, right, leftt;
  register int round;

  leftt = block[0];
  right = block[1];
  work = ((leftt >> 4) ^ right) & 0x0f0f0f0fL;
  right ^= work;
  leftt ^= (work << 4);
  work = ((leftt >> 16) ^ right) & 0x0000ffffL;
  right ^= work;
  leftt ^= (work << 16);
  work = ((right >> 2) ^ leftt) & 0x33333333L;
  leftt ^= work;
  right ^= (work << 2);
  work = ((right >> 8) ^ leftt) & 0x00ff00ffL;
  leftt ^= work;
  right ^= (work << 8);
  right = ((right << 1) | ((right >> 31) & 1L)) & 0xffffffffL;
  work = (leftt ^ right) & 0xaaaaaaaaL;
  leftt ^= work;
  right ^= work;
  leftt = ((leftt << 1) | ((leftt >> 31) & 1L)) & 0xffffffffL;

  for( round = 0; round < 8; round++ ) {
    work  = (right << 28) | (right >> 4);
    work ^= *keys++;
    fval  = SP7[ work             & 0x3fL];
    fval |= SP5[(work >>  8) & 0x3fL];
    fval |= SP3[(work >> 16) & 0x3fL];
    fval |= SP1[(work >> 24) & 0x3fL];
    work  = right ^ *keys++;
    fval |= SP8[ work             & 0x3fL];
    fval |= SP6[(work >>  8) & 0x3fL];
    fval |= SP4[(work >> 16) & 0x3fL];
    fval |= SP2[(work >> 24) & 0x3fL];
    leftt ^= fval;
    work  = (leftt << 28) | (leftt >> 4);
    work ^= *keys++;
    fval  = SP7[ work             & 0x3fL];
    fval |= SP5[(work >>  8) & 0x3fL];
    fval |= SP3[(work >> 16) & 0x3fL];
    fval |= SP1[(work >> 24) & 0x3fL];
    work  = leftt ^ *keys++;
    fval |= SP8[ work             & 0x3fL];
    fval |= SP6[(work >>  8) & 0x3fL];
    fval |= SP4[(work >> 16) & 0x3fL];
    fval |= SP2[(work >> 24) & 0x3fL];
    right ^= fval;
  }

  right = (right << 31) | (right >> 1);
  work = (leftt ^ right) & 0xaaaaaaaaL;
  leftt ^= work;
  right ^= work;
  leftt = (leftt << 31) | (leftt >> 1);
  work = ((leftt >> 8) ^ right) & 0x00ff00ffL;
  right ^= work;
  leftt ^= (work << 8);
  work = ((leftt >> 2) ^ right) & 0x33333333L;
  right ^= work;
  leftt ^= (work << 2);
  work = ((right >> 16) ^ leftt) & 0x0000ffffL;
  leftt ^= work;
  right ^= (work << 16);
  work = ((right >> 4) ^ leftt) & 0x0f0f0f0fL;
  leftt ^= work;
  right ^= (work << 4);
  *block++ = right;
  *block = leftt;
}

/* Validation sets:
 *
 * Single-length key, single-length plaintext -
 * Key    : 0123 4567 89ab cdef
 * Plain  : 0123 4567 89ab cde7
 * Cipher : c957 4425 6a5e d31d
 *
 **********************************************************************/

void Des_Key(des_ctx *dc, unsigned char *pucKey, short sMode){

  if (sMode == EN0){
  	deskey(pucKey,sMode);
  	cpkey(dc->ek);
  }
  else if(sMode == DE1) {     
  	deskey(pucKey, sMode);
  	cpkey(dc->dk);
	}
  else if(sMode == ENDE){
   	 deskey(pucKey,EN0);
  	cpkey(dc->ek);
	deskey(pucKey,DE1);
  	cpkey(dc->dk);
  }
}
/* Encrypt several blocks in ECB sMode.  Caller is responsible for
   short blocks. */
void Des_Enc(des_ctx *dc, unsigned char *pucData, short sBlocks){
  unsigned long work[2];
  int i;
  unsigned char *cp;

  cp = pucData;

  for(i=0;i<sBlocks;i++){
    scrunch(cp,work);
    desfunc(work,dc->ek);
    unscrun(work,cp);
    cp+=8;
  }
}

void Des_Dec(des_ctx *dc, unsigned char *pucData, short sBlocks){
  unsigned long work[2];
  int i;
  unsigned char *cp;

  cp = pucData;
  for(i=0;i<sBlocks;i++){
    scrunch(cp,work);
    desfunc(work,dc->dk);
    unscrun(work,cp);
    cp+=8;
  }
}

void TripleDES_ENC( des_ctx *dc,unsigned char *pucData, short sBlocks, unsigned char *pucKey1, unsigned char *pucKey2, unsigned char *pucKey3){

	Des_Key(dc,pucKey1, EN0);
	Des_Enc(dc,pucData,sBlocks);
	Des_Key(dc,pucKey2, DE1);
	Des_Dec(dc, pucData,  sBlocks);
	Des_Key(dc,pucKey3, EN0);
	Des_Enc(dc,pucData,sBlocks);
}

void TripleDES_DEC( des_ctx *dc,unsigned char *pucData, short sBlocks,unsigned char *pucKey1,unsigned char *pucKey2,unsigned char *pucKey3){
	Des_Key(dc,pucKey3, DE1);
	Des_Dec(dc, pucData,  sBlocks);
	Des_Key(dc,pucKey2, EN0);
	Des_Enc(dc,pucData,sBlocks);
	Des_Key(dc,pucKey1, DE1);
	Des_Dec(dc, pucData,  sBlocks);
}

void TripleDES_ENC_CBC( des_ctx *dc,unsigned char *pucData, short sBlocks,unsigned char *pucIV, unsigned char *pucKey1, unsigned char *pucKey2, unsigned char *pucKey3){
int i,f,x;
des_ctx dc1, dc2, dc3;

	Des_Key(&dc1,pucKey1, EN0);
	Des_Key(&dc2,pucKey2, DE1);
	Des_Key(&dc3,pucKey3, EN0);
	for (f=0;f<16;f++){
		pucData[f] ^= pucIV[f];
	}
	for(i=0; i< sBlocks; i++){
		x=i*16;
		Des_Enc(&dc1,&pucData[x],1);
		Des_Dec(&dc2,&pucData[x],1);
		Des_Enc(&dc3,&pucData[x],1);
		if( i < (sBlocks-1)){
			for(f=0;f<16;f++){
				pucIV[x+f] = pucData[x+f];
			}
		}
		else{
			for(f=0;f<16;f++){
				pucData[x+f+16] = pucData[x+f];
			}
		}
	
	}
}

void TripleDES_DEC_CBC( des_ctx *dc,unsigned char *pucData, short sBlocks, unsigned char *pucIV, unsigned char *pucKey1,unsigned char *pucKey2,unsigned char *pucKey3){
	int i,f,x;
	des_ctx dc1, dc2, dc3;
	unsigned char temp[8];
	
	if(sBlocks<=1){ //Sanity Check
		return;
	}
	else{
		Des_Key(&dc1,pucKey3, DE1); //Key Schedules
		Des_Key(&dc2,pucKey2, EN0);
		Des_Key(&dc3,pucKey1, DE1);	
		x=(sBlocks-1)*16;  // address of start of last block of data
		for(f=0;f<16;f++){
			temp[f] = pucData[x+f]; //Copy newIV to Temp
		}
		for(i=0;i<sBlocks;i++){
			Des_Dec(&dc1,&pucData[x],1);  //3DES algorithm
			Des_Enc(&dc2,&pucData[x],1);
			Des_Dec(&dc3,&pucData[x],1);
			x = x-16;
			if(x >= 0){
				for(f=0;f<16;f++){
					pucData[x+f+16] ^= pucData[x+f]; //XOR block with input of next block
				}
			}
			else{
				for(f=0;f<16;f++){
					pucData[f] ^= pucIV[f];  // XOR first block with IV
					pucIV[f] = temp[f]; 	//Update IV;
				}
			}
		}
	}
}

void DES_Enc_CBC (des_ctx *dc,unsigned char *pucData, short sBlocks, unsigned char *pucIV){
  int CurrentBlock = 1;
  //unsigned char bx[8];
  //unsigned char ax[8];
  unsigned char d =0;
  unsigned char *cp;
  int i;
  cp = pucData;
  if (sBlocks <= 1) return;
 
  else{
    for(i=0; i<8; i++){
      pucData[i] ^= pucIV[i];
    }
    
    while(CurrentBlock < sBlocks){
   Des_Enc(dc,cp,1);
   
 //  for(i=0;i<8;i++){
//    bx[i] = pucData[i+d]; 
//  }
   
     for (i=0; i <8; i++){
    pucData[i+8+d] ^= pucData[i+d];
  }
  
 // for(i=0;i<8;i++){
  //  ax[i+d] = pucData[i+d]; 
 //  }
  cp+=8;
  CurrentBlock++;
  d+=8;
    }
  
   Des_Enc(dc,cp,1);
   for(i=0; i<8; i++){
      pucIV[i] = cp[i];
    }
  //  for(i=0;i<8;i++){
 //   ax[i] = pucData[i+d]; 
  // }
   //d=ax[0];
  }
}

void DES_Dec_CBC (des_ctx *dc,unsigned char *pucData, short sBlocks, unsigned char *pucIV){
  int CurrentBlock;
  //unsigned char bx[8];
  //unsigned char ax[8];
  unsigned char d =0;
  unsigned char *cp;
  unsigned char temp[8];
  int i;
  cp = pucData + (sBlocks-1)*8; //Starting DEC backwards
  CurrentBlock = sBlocks;
  for (i=0; i <8; i++){
   temp[i] = cp[i];  //Copying new pucIV (updated version)
  }
  if (sBlocks <= 1) return;
 
  else{
    while(CurrentBlock != 1){
   Des_Dec(dc,cp,1);  //dec last block
   d= (CurrentBlock -1) *8;  //reset block count
 //  for(i=0;i<8;i++){
//    bx[i] = pucData[i+d]; 
//  }
   
     for (i=0; i <8; i++){
    pucData[i+d] ^= pucData[i+ d - 8];  //xor op
 	 }
  
 // for(i=0;i<8;i++){
  //  ax[i+d] = pucData[i+d]; 
 //  }
  cp-=8;
  CurrentBlock--;
  //d+=8;
    }
  
   Des_Dec(dc,cp,1);
   for (i=0; i <8; i++){
     pucData[i] ^= pucIV[i];
    pucIV[i] = temp[i];
  }
  //  for(i=0;i<8;i++){
 //   ax[i] = pucData[i+d]; 
  // }
  // d=ax[0];
  }
}



