#if 1

#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
int TAG = 0;//用来判断打印第几轮的S盒输出
FILE *stream;
typedef struct
{
	int mode;//标记加解密模式
	unsigned long rk[32];//存放轮密钥
} sm4_context;//sm4是什么情景

#define ROTATE_LEFT(x,s,n) ((x)<<(n)|((x)>>((s)-(n)))) //循环移位

#define ULONG2UCHAR(l,c)					\
{											\
	(c)[0] = (unsigned char) ( (l) >> 24 );	\
	(c)[1] = (unsigned char) ( (l) >> 16 );	\
	(c)[2] = (unsigned char) ( (l) >>  8 );	\
	(c)[3] = (unsigned char) ( (l)		 );	\
} //l = input，input为unsigned long类型  l的最高8位给了c[0]，最低8位给了c[3]

#define UCHAR2ULONG(l,c)					\
{											\
	(l) = ((unsigned long) (c)[0] << 24 )	\
		| ((unsigned long) (c)[1] << 16 )	\
		| ((unsigned long) (c)[2] <<  8 )	\
		| ((unsigned long) (c)[3]		);	\
} //注意是先强制类型转换再移位  将这8个字节赋给l，[0]赋给最高位，[3]赋给最低位

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

//S盒替换函数
unsigned char S_Box(unsigned char input)
{
	unsigned char output = S_box_table[input >> 4][input & 0xf];
	return output;
}

///////////////////////////////////////////////////////////////////////////////////////
//密钥扩展用的T'函数
unsigned long sm4_Trk(unsigned long input)
{
	unsigned char a[4];
	unsigned char b[4];
	unsigned long output;

	//tao函数
	ULONG2UCHAR(input, a);
	b[0] = S_Box(a[0]);
	b[1] = S_Box(a[1]);
	b[2] = S_Box(a[2]);
	b[3] = S_Box(a[3]);
	UCHAR2ULONG(output, b);

	//L'函数
	output = output
		^ ROTATE_LEFT(output, 32, 13)
		^ ROTATE_LEFT(output, 32, 23);
	return output;
}

//设置32个轮密钥rk
void sm4_setKey(unsigned long rk[32], unsigned char key[16])//求轮密钥
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
/////////////////////////////////////////////////////////////////////////////////////////
//T函数
unsigned long sm4_T(unsigned long input)
{
	unsigned char a[4];
	unsigned char b[4];
	unsigned long output;
	int i = 0;

	//tao函数
	ULONG2UCHAR(input, a);//a[0]放input的高8位，a[3]放input的低8位
	b[0] = S_Box(a[0]);//调用S盒函数
	b[1] = S_Box(a[1]);
	b[2] = S_Box(a[2]);
	b[3] = S_Box(a[3]);

	///////////////////////////////////////////
	if(TAG == 0)
	{
		for(i = 0; i < 4; ++i)
		{
			fprintf(stream, "%02x ", a[i]);
		}
		fprintf(stream, "\n");
	}

	//////////////////////////////////////////
	UCHAR2ULONG(output, b)//将b的32bit值放到output中

	//L函数
	output = output
		^ ROTATE_LEFT(output, 32, 2)//output为32位输出，向左循环移动2位
		^ ROTATE_LEFT(output, 32, 10)
		^ ROTATE_LEFT(output, 32, 18)
		^ ROTATE_LEFT(output, 32, 24);
	return output;
}

//轮函数F
unsigned long sm4_F(unsigned long x0, 
					unsigned long x1, 
					unsigned long x2, 
					unsigned long x3, 
					unsigned long rk)//迭代函数
{
	return (x0^sm4_T(x1^x2^x3^rk));//调用T函数
}

//加解密过程
void sm4_round(unsigned long rk[32], //传入轮密钥
				unsigned char input[16], //传入加密的明文或者解密的密文
				unsigned char output[32]) //放加密得到的密文或解密得到的明文
{
	unsigned long i = 0;
	unsigned long buf[36];//用来存每一轮的输出结果

	UCHAR2ULONG(buf[0], input);//把input的前4个字节放入buf[0]
	UCHAR2ULONG(buf[1], input + 4);
	UCHAR2ULONG(buf[2], input + 8);
	UCHAR2ULONG(buf[3], input + 12);
	for (i = 0; i < 2; i++)//进入32轮轮函数
	{
		buf[i + 4] = sm4_F(buf[i], buf[i + 1], buf[i + 2], buf[i + 3], rk[i]);
		++TAG;
	}
	ULONG2UCHAR(buf[35], output);
	ULONG2UCHAR(buf[34], output + 4);
	ULONG2UCHAR(buf[33], output + 8);
	ULONG2UCHAR(buf[32], output + 12);
}


void sm4_crypt(sm4_context *context,
				unsigned char *input,
				unsigned char *output)
{
		sm4_round(context->rk, input, output);//加密过程
}


void sm4_setKey_encrypt(sm4_context *context, unsigned char key[16])//设置加密情形
{
	context->mode = 1;//加密为1
	sm4_setKey(context->rk, key);//求32轮加密密钥
}

int main()
{

	unsigned char key[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
	unsigned char input[50][16] = 
	{
		{91,110,61,207,101,50,14,185,132,122,255,238,102,1,245,161},
		{191,56,134,188,88,252,141,102,51,171,24,76,29,253,251,104},
		{218,78,88,86,205,190,67,95,122,232,44,245,100,225,239,34},
		{116,129,123,91,96,32,177,104,9,86,219,129,25,43,148,61},
		{67,179,71,24,226,19,11,124,179,125,22,187,11,122,19,239},
		{205,61,206,231,210,255,54,121,19,91,111,198,135,18,32,237},
		{254,118,11,14,209,255,107,105,231,186,38,254,243,150,171,106},
		{72,49,150,212,17,234,118,78,123,25,16,90,38,210,17,172},
		{222,152,161,41,89,8,224,54,110,23,201,24,118,185,131,142},
		{123,110,201,189,61,170,141,158,145,160,212,255,163,220,131,16},
		{198,131,237,98,127,226,153,62,40,70,42,131,2,25,137,120},
		{99,93,45,191,66,138,47,174,118,131,231,84,116,247,94,200},
		{54,170,176,200,149,186,144,207,61,179,234,140,110,219,79,68},
		{143,136,84,211,25,107,156,175,255,161,209,203,97,54,27,242},
		{6,117,127,120,241,73,83,210,56,24,174,173,100,236,79,65},
		{51,141,208,122,90,192,200,119,5,123,26,99,50,203,124,221},
		{37,81,111,183,250,30,5,207,105,50,72,144,199,173,161,109},
		{99,144,5,231,2,125,255,196,114,243,133,225,229,31,209,124},
		{220,120,27,241,125,214,77,161,38,170,28,43,12,91,170,33},
		{52,89,35,39,158,53,177,8,203,40,152,249,133,151,36,129},
		{243,238,57,12,77,242,96,152,194,148,217,127,143,230,161,66},
		{76,2,9,143,40,135,39,42,244,54,230,251,169,163,119,138},
		{202,196,118,148,247,152,134,24,226,81,206,86,107,176,118,16},
		{135,98,73,254,150,31,65,28,203,44,18,231,117,142,209,66},
		{0,18,94,188,250,161,201,167,201,95,142,175,144,159,42,160},
		{42,245,233,30,90,63,116,175,144,181,126,202,16,34,155,44},
		{7,73,83,69,125,138,81,220,75,165,85,37,28,237,33,245},
		{224,50,185,123,57,105,38,108,241,202,66,82,207,196,212,85},
		{130,96,202,198,152,245,2,237,40,117,37,130,163,71,161,125},
		{46,73,48,94,74,56,114,62,130,140,101,251,176,209,124,12},
		{253,223,254,7,29,137,56,111,177,55,58,234,168,61,218,80},
		{158,244,203,213,241,43,114,66,127,249,54,250,22,173,47,199},
		{27,97,2,155,8,53,246,184,216,82,116,254,174,153,187,146},
		{202,162,91,205,53,232,26,141,168,127,106,87,157,89,182,113},
		{129,211,227,93,214,2,106,241,176,198,85,180,66,170,15,29},
		{137,32,241,247,229,174,252,239,177,50,134,210,37,153,28,104},
		{79,149,21,183,149,162,78,213,18,97,33,58,195,225,210,234},
		{176,251,120,7,223,216,31,83,93,97,239,87,196,222,94,75},
		{18,148,182,127,25,71,120,108,25,42,62,236,57,240,199,170},
		{149,229,22,106,66,54,51,44,35,246,30,199,69,180,76,39},
		{44,128,78,140,161,161,146,57,75,86,92,47,45,240,154,24},
		{47,166,135,139,174,101,195,215,126,178,154,100,232,0,252,7},
		{126,170,83,179,153,79,170,143,71,108,56,221,241,29,168,77},
		{94,68,79,148,240,136,55,235,110,217,59,42,138,129,151,165},
		{188,88,15,89,192,253,52,145,128,250,120,235,166,251,38,16},
		{206,138,195,66,56,148,206,95,218,84,135,63,70,187,99,214},
		{252,203,137,95,87,121,105,6,137,238,210,143,196,17,254,170},
		{125,93,124,18,2,37,159,155,64,173,96,32,238,35,225,64},
		{4,47,238,207,161,245,152,63,158,63,56,226,242,20,223,14},
		{229,207,141,39,130,233,18,134,98,100,240,54,54,47,15,158}
	};

	unsigned char output[16];
	int i = 0;
	sm4_context ctx;
	stream = fopen("s_output.txt", "w");
	sm4_setKey_encrypt(&ctx, key);//设置加密情景
	printf("%02x", ctx.rk[0]);
	for(i = 0; i < 50; ++i)
	{
		TAG = 0;
		sm4_crypt(&ctx, input[i], output);//1代表加密，input为输入的明文，output用来存放密文
	}
	//for (i = 0; i<16; i++)
	//	printf("%x ", output[i]);
	//printf("\n");
	fclose(stream);
	return 0;
}

#endif