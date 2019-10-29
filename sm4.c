#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include "sm4.h"

#define ROTATE_LEFT(x,s,n) ((x)<<(n)|((x)>>((s)-(n)))) //ѭ����λ

#define ULONG2UCHAR(l,c)					\
{											\
	(c)[0] = (unsigned char) ( (l) >> 24 );	\
	(c)[1] = (unsigned char) ( (l) >> 16 );	\
	(c)[2] = (unsigned char) ( (l) >>  8 );	\
	(c)[3] = (unsigned char) ( (l)		 );	\
} //l = input��inputΪunsigned long����  l�����8λ����c[0]�����8λ����c[3]

#define UCHAR2ULONG(l,c)					\
{											\
	(l) = ((unsigned long) (c)[0] << 24 )	\
		| ((unsigned long) (c)[1] << 16 )	\
		| ((unsigned long) (c)[2] <<  8 )	\
		| ((unsigned long) (c)[3]		);	\
} //ע������ǿ������ת������λ  ����8���ֽڸ���l��[0]�������λ��[3]�������λ

static const unsigned char S_box_table[16][16] = 
{
	{ 0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05 },
	{ 0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99 },
	{ 0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62 },
	{ 0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6 },
	{ 0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8 },
	{ 0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35 },
	{ 0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87 },
	{ 0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e },
	{ 0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1 },
	{ 0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3 },
	{ 0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f },
	{ 0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51 },
	{ 0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8 },
	{ 0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0 },
	{ 0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84 },
	{ 0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48 }
};

static const unsigned long FK[4] = { 0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc };

static const unsigned long CK[32] =
{
	0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
	0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
	0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
	0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
	0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
	0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
	0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
	0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

//S�����滻����
unsigned char S_Box(unsigned char input)
{
	unsigned char output = S_box_table[input >> 4][input & 0xf];
	return output;
}

//T����
unsigned long sm4_T(unsigned long input)
{
	unsigned char a[4];
	unsigned char b[4];
	unsigned long output;
	int i = 0;

	//tao����
	ULONG2UCHAR(input, a);//a[0]��input�ĸ�8λ��a[3]��input�ĵ�8λ
	////////////////////////////////////////////////////
	//for(i = 0; i < 4; ++i)
	//{
	//	printf("%02x ", a[i]);
	//}
	//printf("\n");
	////////////////////////////////////////////////////
	b[0] = S_Box(a[0]);//����S�к���
	b[1] = S_Box(a[1]);
	b[2] = S_Box(a[2]);
	b[3] = S_Box(a[3]);
	UCHAR2ULONG(output, b)//��b��32bitֵ�ŵ�output��

	//L����
	output = output
		^ ROTATE_LEFT(output, 32, 2)//outputΪ32λ���������ѭ���ƶ�2λ
		^ ROTATE_LEFT(output, 32, 10)
		^ ROTATE_LEFT(output, 32, 18)
		^ ROTATE_LEFT(output, 32, 24);
	return output;
}

//�ֺ���F
unsigned long sm4_F(unsigned long x0, 
					unsigned long x1, 
					unsigned long x2, 
					unsigned long x3, 
					unsigned long rk)//��������
{
	return (x0^sm4_T(x1^x2^x3^rk));//����T����
}

//��Կ��չ�õ�T'����
unsigned long sm4_Trk(unsigned long input)
{
	unsigned char a[4];
	unsigned char b[4];
	unsigned long output;

	//tao����
	ULONG2UCHAR(input, a);
	b[0] = S_Box(a[0]);
	b[1] = S_Box(a[1]);
	b[2] = S_Box(a[2]);
	b[3] = S_Box(a[3]);
	UCHAR2ULONG(output, b);

	//L'����
	output = output
		^ ROTATE_LEFT(output, 32, 13)
		^ ROTATE_LEFT(output, 32, 23);
	return output;
}

//����32������Կrk
void sm4_setKey(unsigned long rk[32], unsigned char key[16])//������Կ
{
	unsigned long MK[4];
	unsigned long k[36];
	unsigned long i = 0;

	UCHAR2ULONG(MK[0], key);
	UCHAR2ULONG(MK[1], key + 4);
	UCHAR2ULONG(MK[2], key + 8);
	UCHAR2ULONG(MK[3], key + 12);
	k[0] = MK[0] ^ FK[0];
	k[1] = MK[1] ^ FK[1];
	k[2] = MK[2] ^ FK[2];
	k[3] = MK[3] ^ FK[3];
	for (; i < 32; i++)
	{
		k[i + 4] = k[i] ^ (sm4_Trk(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]));
		rk[i] = k[i + 4];
	}

}

//�ӽ��ܹ���
//void sm4_round(unsigned long rk[32], //��������Կ
//				unsigned char input[16], //������ܵ����Ļ��߽��ܵ�����
//				unsigned char output[32]) //�ż��ܵõ������Ļ���ܵõ�������
//{
//	unsigned long i = 0;
//	unsigned long buf[36];//������ÿһ�ֵ�������
//
//	UCHAR2ULONG(buf[0], input);//��input��ǰ4���ֽڷ���buf[0]
//	UCHAR2ULONG(buf[1], input + 4);
//	UCHAR2ULONG(buf[2], input + 8);
//	UCHAR2ULONG(buf[3], input + 12);
//	for (i = 0; i < 32; i++)//����32���ֺ���
//	{
//		buf[i + 4] = sm4_F(buf[i], buf[i + 1], buf[i + 2], buf[i + 3], rk[i]);
//	}
//	ULONG2UCHAR(buf[35], output);
//	ULONG2UCHAR(buf[34], output + 4);
//	ULONG2UCHAR(buf[33], output + 8);
//	ULONG2UCHAR(buf[32], output + 12);
//}

void sm4_setKey_encrypt(sm4_context *context, unsigned char key[16])//���ü�������
{
	context->mode = SM4_ENCRYPT;//����Ϊ1
	sm4_setKey(context->rk, key);//��32�ּ�����Կ
}

void sm4_setKey_decrypt(sm4_context *context, unsigned char key[16])//���ý�������
{
	int i = 0;
	unsigned long tmp;
	context->mode = SM4_DECRYPT;//����Ϊ0
	sm4_setKey(context->rk, key);
	for (; i < 16; i++)//��32�ֽ�����Կ
	{
		tmp = context->rk[i];
		context->rk[i] = context->rk[31 - i];
		context->rk[31 - i] = tmp;
	}
}

//void sm4_crypt(sm4_context *context,
//				int mode,
//				int length,//��������ĵ��ֽ���
//				unsigned char *input,
//				unsigned char *output)
//{
//	while (length > 0)//ÿ�μ���16���ֽ�
//	{
//		sm4_round(context->rk, input, output);//���ܹ���
//		input += 16;
//		output += 16;
//		length -= 16;
//	}
//}



///////////////////////////////////////////////////////////////////////////////////////////////


//�ӽ��ܹ���
void sm4_round(unsigned long rk[32], 
				unsigned char input[16], 
				unsigned char output[32])
{
	unsigned long i = 0;
	unsigned long buf[36];

	UCHAR2ULONG(buf[0], input);
	UCHAR2ULONG(buf[1], input + 4);
	UCHAR2ULONG(buf[2], input + 8);
	UCHAR2ULONG(buf[3], input + 12);
	for (i = 0; i < 1; i++)
	{
		buf[i + 4] = sm4_F(buf[i], buf[i + 1], buf[i + 2], buf[i + 3], rk[i]);
	}
	ULONG2UCHAR(buf[35], output);
	ULONG2UCHAR(buf[34], output + 4);
	ULONG2UCHAR(buf[33], output + 8);
	ULONG2UCHAR(buf[32], output + 12);
}


void sm4_crypt(sm4_context *context,
				int mode,
				int length,
				unsigned char *input,
				unsigned char *output)
{
		sm4_round(context->rk, input, output);
}