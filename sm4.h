#ifndef _SM4_H_
#define _SM4_H_
#define SM4_ENCRYPT 1
#define SM4_DECRYPT 0

typedef struct
{
	int mode;//��Ǽӽ���ģʽ
	unsigned long rk[32];//�������Կ
} sm4_context;//sm4��ʲô�龰

void sm4_setKey_encrypt(sm4_context *contex, unsigned char key[16]);//���ü����龰

void sm4_setKey_decrypt(sm4_context *contex, unsigned char key[16]);//���ý����龰

void sm4_crypt(sm4_context *contex,
				int mode,
				int length,
				unsigned char *input,
				unsigned char *output);//sm4�ӽ��ܺ���
#endif