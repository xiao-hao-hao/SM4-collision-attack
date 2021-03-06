#if 0
#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include "sm4.h"

int main()
{
	unsigned char key[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
	//unsigned char input[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 }; //f0 02 c3 9e
	//unsigned char input[16] = { 0x53,0xc2,0x87,0x51,0xc5,0x61,0x63,0x66,0xf1,0x23,0x31,0x47,0x68,0x54,0x33,0x20 }; //ad 37 e7 f8
	//unsigned char input[16] = { 0x21,0x53,0x54,0x28,0x77,0x36,0x11,0x16,0x50,0x4e,0x1a,0xa2,0x8b,0xc3,0x5f,0x3a }; //5d 9a d2 77
	//unsigned char input[16] = { 0x32,0xaf,0xf2,0x7a,0xa1,0x2c,0x4f,0x58,0x34,0x8a,0x9f,0x12,0x38,0x2a,0xff,0xfa }; //5c ad a9 49
	//unsigned char input[16] = { 0x55,0x68,0x71,0x83,0x73,0x52,0x32,0x13,0x23,0x41,0xf1,0x1a,0x2c,0x7f,0xff,0xf9 }; //8d 4d ba 09
	//unsigned char input[16] = { 0x55,0x32,0x90,0xad,0xca,0xa0,0x1a,0x2a,0xaa,0x80,0x91,0x11,0x56,0x75,0x77,0x33 }; //c7 74 7a f1
	//unsigned char input[16] = { 0x24,0x54,0x65,0x79,0x23,0x61,0x25,0x34,0x58,0x02,0x10,0x73,0xa4,0xca,0xc8,0xcc }; //2e 88 7b 72
	//unsigned char input[16] = { 0x36,0x33,0xf1,0xf7,0x25,0x50,0x55,0x66,0x71,0x73,0xbb,0xdd,0xdf,0xee,0x28,0x88 }; //7a ec 40 ca
	//unsigned char input[16] = { 0x31,0x22,0x66,0xaa,0xa5,0xec,0xe2,0xca,0x53,0x79,0x33,0x58,0x79,0x99,0x11,0x61 }; //7e 2d 46 0a
	//unsigned char input[16] = { 0x55,0x24,0x73,0xa2,0xaa,0x21,0xa1,0x51,0x65,0x24,0x98,0x92,0x71,0x53,0xe3,0xf2 }; //4f 77 5c c8
	unsigned char input[16] = { 1,35,69,103,137,171,205,239,254,220,186,152,118,84,50,16 };
	
	unsigned char output[16];
	sm4_context ctx;
	unsigned long i;

	//encrypt standard testing vector    
	sm4_setKey_encrypt(&ctx, key);//设置加密情景
	sm4_crypt(&ctx, 1, 16, input, output);//1代表加密，input为输入的明文，output用来存放密文
	for (i = 0; i<16; i++)
		printf("%02x ", output[i]);
	printf("\n");

	//decrypt testing    
	//sm4_setKey_decrypt(&ctx, key);
	//sm4_crypt(&ctx, 0, 16, output, output);
	//for (i = 0; i<16; i++)
	//	printf("%02x ", output[i]);
	//printf("\n");

	return 0;
}

#endif