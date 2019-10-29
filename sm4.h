#ifndef _SM4_H_
#define _SM4_H_
#define SM4_ENCRYPT 1
#define SM4_DECRYPT 0

typedef struct
{
	int mode;//标记加解密模式
	unsigned long rk[32];//存放轮密钥
} sm4_context;//sm4是什么情景

void sm4_setKey_encrypt(sm4_context *contex, unsigned char key[16]);//设置加密情景

void sm4_setKey_decrypt(sm4_context *contex, unsigned char key[16]);//设置解密情景

void sm4_crypt(sm4_context *contex,
				int mode,
				int length,
				unsigned char *input,
				unsigned char *output);//sm4加解密函数
#endif