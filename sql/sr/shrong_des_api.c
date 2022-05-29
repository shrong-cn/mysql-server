/******************************************************************************
 *[改动记录] 
 * 2021.04.26 加解密时对于内部的密文缓存/明文缓存不再使用malloc分配，改为在栈中
 * 分配，最大分配4096个字节。
 *
 *
 * ****************************************************************************/


#include <openssl/des.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "shrong_des_api.h"
//#include "my_inner_function.h"

#ifndef __MY_DEBUG__
#define __MY_DEBUG__
#endif
#undef  __MY_DEBUG__

#define  MAX_BUFF_SIZE  		4096           //2021.04.26

#define  MAX_RAW_DATA_LENGTH  	(4096 - 16 )   //2021.04.26



//下面这组测试函数主要是为了掌握DES/3DES的加解密方法而开发的，不是向外部提供的API接口。
// int Test_3DES_ecb(void);
// int Test_DES_ecb_Encrypt();
// int Test_DES_ncbc_Encrypt(int argc, char** argv  );

int CheckInputDecryptParameters_3DES(unsigned char *ciphertext, int ncipherLen, unsigned char *userkey, unsigned int keyLen, int nKeyMode );
int CheckInputDecryptParameters(unsigned char *ciphertext, int ncipherLen, unsigned char *userkey, unsigned int keyLen );

int CheckInputEncryptParameters_3DES(unsigned char *rawdata, int ndataLength, unsigned char *userkey, unsigned int keyLen,int nKeyMode );
int CheckInputEncryptParameters(unsigned char *rawdata, int ndataLength, unsigned char *userkey, unsigned int keyLen );


//为支持3-DES-ecb加密所封装的API
//返回值：0---SUCCESS； -1---FAILED
int shrong_3des_ecb_encrypt(
		unsigned char *rawdata,      //输入的待加密的原始字节流
		int nDataLen,      			 //该原始字节流的长度
		unsigned char *userkey,	    //所使用的密钥，使用时密钥的长度需要与加解密算法的类型相适配。
		unsigned int keyLen,         //密钥字节的实际长度
		int nKeyMode,                //加密算法密钥模式
		unsigned char *pOutCipher,  //加密后所输出密文字节流
		int *nCipherLength          //该密文字节流的长度
		)
{

#ifdef __MY_DEBUG__
	printf("\n待加密的原始数据的内容：%s\n", rawdata);
#endif

	int nRet = 0;
	nRet = CheckInputEncryptParameters_3DES( rawdata, nDataLen, userkey, keyLen,nKeyMode );
	if( nRet < 0 )
		return -1;

	/* 为适应3DES算法，需要通过输入的密钥构造出解密时真正使用的扩展密钥 */
	const int MAX_EXT_LENGTH = 24+1;  //2021.03.19
	unsigned char extenedKey[MAX_EXT_LENGTH]; /* 补齐后的密钥 */

	unsigned char blockKey[9];
	memcpy(extenedKey, userkey, keyLen);
	memset(extenedKey + keyLen, 0x00, MAX_EXT_LENGTH - keyLen);


	/* 分析补齐明文所需空间及补齐填充数据 */
	int rawLength 		= strlen((char*)rawdata);
	int dataRest   	 	= rawLength % 8;
	int TotalLength 	= rawLength + (8 - dataRest); //包含了填充数据在内的明文数据长度。 如果是8的整数倍仍然要填充8个字节。
	unsigned char padValue = 8 - dataRest;       //填充字节的值

#if 0   //2021.04.26
	unsigned char *srcplain 	 = (unsigned char *)malloc(TotalLength); /* 补齐后的明文 */
	unsigned char *ciphertext = (unsigned char *)malloc(TotalLength); //加密后的密文

	memset( srcplain, 0, TotalLength );
	memset( ciphertext, 0, TotalLength );

	if (NULL == srcplain || NULL == ciphertext )
	{
		ReleaseMemory(srcplain);
		ReleaseMemory(ciphertext);

		return -1;
	}
#else
	unsigned char srcplain[MAX_BUFF_SIZE] 	=	{0}; /* 补齐后的明文 */
	unsigned char ciphertext[MAX_BUFF_SIZE] 	= 	{0}; //加密后的密文

#endif


	/* 构造补齐字节后的待加密内容,补齐字节的填充值就是要补的字节的数目。 */
	memset(srcplain, 0, TotalLength);
	memcpy(srcplain, rawdata, rawLength);
	memset( srcplain + rawLength, padValue, 8 - dataRest );

	/* 密钥置换 */
	DES_key_schedule ks;
	DES_key_schedule ks2;
	DES_key_schedule ks3;
	memset(blockKey, 0, sizeof(blockKey));
	memcpy(blockKey, extenedKey + 0, 8);
	DES_set_key_unchecked((const_DES_cblock*)blockKey, &ks);

	memcpy(blockKey, extenedKey + 8, 8);
	DES_set_key_unchecked((const_DES_cblock*)blockKey, &ks2);

	if( _3DES_3K_ECB == nKeyMode )
		memcpy(blockKey, extenedKey + 16, 8);
	else if( _3DES_2K_ECB == nKeyMode )
		memcpy(blockKey, extenedKey + 0, 8);
	DES_set_key_unchecked((const_DES_cblock*)blockKey, &ks3);

	//量为了方便测试
#ifdef	__MY_DEBUG__
	printf("\nbefore encrypt( 附加有padding后的字节):\n");
	DisplayHexOctects(srcplain, TotalLength  );
#endif


	/* 循环加密每8字节一次完成对整个明文的加密 */
	const int  BLKSIZE =  8;   //经测试发现DES3也只能是每次对8字节的数据块进行加解密
	unsigned char tmp[BLKSIZE];
	unsigned char in[BLKSIZE];
	int count = TotalLength / BLKSIZE;
	for (int i = 0; i < count; i++)
	{
		memset(tmp, 0, BLKSIZE);
		memset(in, 0, BLKSIZE);
		memcpy(tmp, srcplain + BLKSIZE * i, BLKSIZE);
		DES_ecb3_encrypt((const_DES_cblock*)tmp, (DES_cblock*)in, &ks, &ks2, &ks3, DES_ENCRYPT);
		memcpy(ciphertext + BLKSIZE * i, in, BLKSIZE);
	}


	*nCipherLength = TotalLength;
	memcpy( pOutCipher, ciphertext, TotalLength   );

#if 0    //2021.04.26
	//对于动态分配的明文缓存已经使用完毕及时释放内存
	ReleaseMemory(srcplain);
	ReleaseMemory(ciphertext);
#endif
	return 0;
}




//为支持3-DES-ecb解密所封装的API
//返回值：0---SUCCESS； -1---FAILED
int shrong_3des_ecb_decrypt(
		unsigned char *ciphertext,   //输入的待解密的密文字节流
		int ncipherLen,      			 //该密文字节流的长度
		unsigned char *userkey,	    //所使用的密钥，使用时密钥的长度需要与加解密算法的类型相适配。
		unsigned int keyLen,         //密钥字节的实际长度，不能超过24个字节
		int nKeyMode,                //加密算法密钥模式
		unsigned char *pOutPlain,    //解密后所输出明文字节流
		int *nPlainLen           	 //该明文字节流的长度( 去掉了padding字节后的实际长度 )
		)
{
	int nRet =0;
	nRet = CheckInputDecryptParameters_3DES( ciphertext, ncipherLen, userkey, keyLen, nKeyMode );
	if( nRet < 0 )
		return -1;


	/* 为适应3DES算法，需要通过输入的密钥构造出解密时真正使用的扩展密钥 */
	const int MAX_EXT_LENGTH = 24+1;  //2021.03.19

	unsigned char extenedKey[MAX_EXT_LENGTH];

	memcpy(extenedKey, userkey, keyLen);
	memset(extenedKey + keyLen, 0x00, MAX_EXT_LENGTH - keyLen);

	 //按照所输入的密文的长度分配解密后的明文长度,但真正返回明文实际的有效长度时必须要去掉填充字节。
	int TotalLength 	= ncipherLen;
#if 0  //2021.04.26
	unsigned char *dstplain 	 = (unsigned char *)malloc(TotalLength); /* 解密后的明文 */
	if ( NULL == dstplain )
	{
		printf( "\nerror: 为存储解密后的明文动态分配内存出错.\n" );
		return -1;
	}
	memset( dstplain, 0, TotalLength );
#else  //2021.04.26
	unsigned char dstplain[ MAX_BUFF_SIZE] 	 = { 0 };
#endif

	/* 密钥置换 */
	DES_key_schedule ks;
	DES_key_schedule ks2;
	DES_key_schedule ks3;
	unsigned char blockKey[9];
	memset(blockKey, 0, sizeof(blockKey));
	memcpy(blockKey, extenedKey + 0, 8);
	DES_set_key_unchecked((const_DES_cblock*)blockKey, &ks);

	memcpy(blockKey, extenedKey + 8, 8);
	DES_set_key_unchecked((const_DES_cblock*)blockKey, &ks2);

	if( _3DES_3K_ECB == nKeyMode )
		memcpy(blockKey, extenedKey + 16, 8);
	else if( _3DES_2K_ECB == nKeyMode )
		memcpy(blockKey, extenedKey + 0, 8);
	DES_set_key_unchecked((const_DES_cblock*)blockKey, &ks3);

	//循环操作实现对整个加密后的密文进行解密
	const int  BLKSIZE =  8;   //经测试发现DES3也只能是每次对8字节的数据块进行加解密
	unsigned char tmp[BLKSIZE];
	unsigned char out[BLKSIZE];
	int count = TotalLength / BLKSIZE;
	for (int i = 0; i < count; i++)
	{
		memset(tmp, 0, BLKSIZE);
		memset(out, 0, BLKSIZE);
		memcpy(tmp, ciphertext + BLKSIZE * i, BLKSIZE);
		DES_ecb3_encrypt((const_DES_cblock*)tmp, (DES_cblock*)out, &ks, &ks2, &ks3, DES_DECRYPT);
		/* 将解密的内容拷贝到明文缓冲区 */
		memcpy(dstplain + BLKSIZE * i, out, BLKSIZE);
	}


#ifdef	__MY_DEBUG__
	//保留仅仅为了方便异常时的调试
	printf("\nafter decrypt( 附加有padding后的字节) :\n");
	DisplayHexOctects(dstplain, TotalLength  );
#endif


	int nRestLength = dstplain[TotalLength-1]; //计算得到填充字节的数目
	dstplain[TotalLength - nRestLength] = '\0';//为了能有效过滤掉不可见的填充字符

	//将明文数据返回给调用者提供的缓存中。
	/***********************************/
	*nPlainLen = TotalLength  - nRestLength; //真正有效的明文长度。
	if( *nPlainLen < 0 )
	{
		printf("decrypted PlainLen is not right, maybe the input userkey is not mathed.\n ");
		return -1;
	}

	memcpy(pOutPlain, dstplain,  (TotalLength  - nRestLength));

#if 0  //2021.04.26
	ReleaseMemory(dstplain);
#endif
	return 0;
}





//为支持DES-ecb加密所封装的API
//返回值：0---SUCCESS； -1---FAILED
int shrong_des_ecb_encrypt(
		unsigned char *rawdata,      //输入的待加密的原始字节流
		int nDataLen,      			 //该原始字节流的长度
		unsigned char *userkey,	    //所使用的密钥，使用时密钥的长度需要与加解密算法的类型相适配。
		unsigned int keyLen,         //密钥字节的实际长度
		unsigned char *pOutCipher,   //加密后所输出密文字节流
		int *nCipherLength           //该密文字节流的长度
		)
{
#ifdef __MY_DEBUG__
	printf("\n待加密的原始数据的内容：%s\n", rawdata);
#endif

	int nRet = 0;
	nRet = CheckInputEncryptParameters( rawdata, nDataLen, userkey, keyLen );
	if( nRet < 0 )
		return -1;

	unsigned char blockKey[9];

	/* 分析补齐明文所需空间及补齐填充数据 */
	int rawLength 		= strlen((char*)rawdata);
	int dataRest   	 	= rawLength % 8;
	int TotalLength 	= rawLength + (8 - dataRest); //包含了填充数据在内的明文数据长度。 如果是8的整数倍仍然要填充8个字节。
	unsigned char padValue = 8 - dataRest;       //填充字节的值

#if 0  //2021.04.26
	unsigned char *srcplain 	 = (unsigned char *)malloc(TotalLength); /* 补齐后的明文 */
	unsigned char *ciphertext = (unsigned char *)malloc(TotalLength); //加密后的密文

	memset( srcplain, 0, TotalLength );
	memset( ciphertext, 0, TotalLength );

	if (NULL == srcplain || NULL == ciphertext )
	{
		ReleaseMemory(srcplain);
		ReleaseMemory(ciphertext);

		return -1;
	}
#else
	unsigned char srcplain[MAX_BUFF_SIZE] 	= {0}; //(unsigned char *)malloc(TotalLength); /* 补齐后的明文 */
	unsigned char ciphertext[MAX_BUFF_SIZE] = {0};//(unsigned char *)malloc(TotalLength); //加密后的密文
#endif


	/* 构造补齐字节后的待加密内容,补齐字节的填充值就是要补的字节的数目。 */
	memset(srcplain, 0, TotalLength);
	memcpy(srcplain, rawdata, rawLength);
	memset( srcplain + rawLength, padValue, 8 - dataRest );

	DES_key_schedule ks;
	memset(blockKey, 0, sizeof(blockKey));
	memcpy(blockKey, userkey, 8);

	//检查密钥的奇偶性和密钥的强度，使用该属性设置，经常会导致密钥无法通过检验，而无法成功设置。
	//同时为了能够实现强密钥，可以我们自己写一段代码对输入的密码进行强密钥检查。
	//DES_set_key_checked(&key, &schedule);    //强制密钥检查
	DES_set_key_unchecked((const_DES_cblock*)blockKey, &ks);

	//量为了方便测试
#ifdef	__MY_DEBUG__
	printf("\nbefore encrypt( 附加有padding后的字节):\n");
	DisplayHexOctects(srcplain, TotalLength  );
#endif


	/* 循环加密每8字节一次完成对整个明文的加密 */
	const int  BLKSIZE =  8;
	unsigned char tmp[BLKSIZE];
	unsigned char in[BLKSIZE];
	int count = TotalLength / BLKSIZE;
	for (int i = 0; i < count; i++)
	{
		memset(tmp, 0, BLKSIZE);
		memset(in, 0, BLKSIZE);
		memcpy(tmp, srcplain + BLKSIZE * i, BLKSIZE);
		DES_ecb_encrypt((const_DES_cblock*)tmp, (DES_cblock*)in, &ks, DES_ENCRYPT);

		memcpy(ciphertext + BLKSIZE * i, in, BLKSIZE);
	}

	*nCipherLength = TotalLength;
	memcpy( pOutCipher, ciphertext, TotalLength   );


#if 0   //2021.04.26
	//对于动态分配的明文缓存已经使用完毕及时释放内存
	ReleaseMemory(srcplain);
	ReleaseMemory(ciphertext);
#endif

	return 0;
}



//为支持DES-ecb解密所封装的API
//返回值：0---SUCCESS； -1---FAILED
int shrong_des_ecb_decrypt(
		unsigned char *cipherdata,   //输入的待解密的密文字节流
		int ncipherLen,      			 //该密文字节流的长度
		unsigned char *userkey,	    //所使用的密钥，使用时密钥的长度需要与加解密算法的类型相适配。
		unsigned int keyLen,         //密钥字节的实际长度
		unsigned char *pOutPlain,   //解密后所输出明文字节流
		int *nPlainLen           	 //该明文字节流的长度( 去掉了padding字节后的实际长度 )
		)
{
	int nRet =0;
	nRet = CheckInputDecryptParameters( cipherdata, ncipherLen, userkey, keyLen );
	if( nRet < 0 )
		return -1;

	 //按照所输入的密文的长度分配解密后的明文长度,但真正返回明文实际的有效长度时必须要去掉填充字节。
	int TotalLength 	= ncipherLen;
#if 0 //20121.04.26
	unsigned char *dstplain 	 = (unsigned char *)malloc(TotalLength); /* 解密后的明文 */
	if ( NULL == dstplain )
	{
		printf( "\nerror: 为存储解密后的明文动态分配内存出错.\n" );
		return -1;
	}
	memset( dstplain, 0, TotalLength );
#else
	unsigned char dstplain[MAX_BUFF_SIZE] 	 = {0};//(unsigned char *)malloc(TotalLength); /* 解密后的明文 */
#endif

	DES_key_schedule kschedule;
	unsigned char blockKey[9];
	memset(blockKey, 0, sizeof(blockKey));
	memcpy(blockKey, userkey, 8);

	DES_set_key_unchecked((const_DES_cblock*)blockKey, &kschedule);
	//循环操作实现对整个加密后的密文进行解密
	const int  BLKSIZE =  8;
	unsigned char tmp[BLKSIZE];
	unsigned char out[BLKSIZE];
	int count = TotalLength / BLKSIZE;
	for (int i = 0; i < count; i++)
	{
		memset(tmp, 0, BLKSIZE);
		memset(out, 0, BLKSIZE);
		memcpy(tmp, cipherdata + BLKSIZE * i, BLKSIZE);

		DES_ecb_encrypt((const_DES_cblock*)tmp, (DES_cblock*)out, &kschedule, DES_DECRYPT);

		/* 将解密的内容拷贝到明文缓冲区 */
		memcpy(dstplain + BLKSIZE * i, out, BLKSIZE);
	}

#ifdef	__MY_DEBUG__
	//保留仅仅为了方便异常时的调试
	printf("after decrypt( 附加有padding后的字节) :\n");
	DisplayHexOctects(dstplain, TotalLength  );
#endif


	int nRestLength = dstplain[TotalLength-1]; //计算得到填充字节的数目
	dstplain[TotalLength - nRestLength] = '\0';//为了能有效过滤掉不可见的填充字符

	//将明文数据返回给调用者提供的缓存中。
	*nPlainLen = TotalLength  - nRestLength; //真正有效的明文长度。

	if( *nPlainLen < 0 )
	{
		printf("decrypted PlainLen is not right, maybe the input userkey is not mathed.\n ");
		return -1;
	}
	memcpy(pOutPlain, dstplain,  (TotalLength  - nRestLength));

#if 0 //20121.04.26
	ReleaseMemory(dstplain);
#endif

	return 0;
}




int CheckInputEncryptParameters_3DES(unsigned char *rawdata, int nDataLen, unsigned char *userkey, unsigned int keyLen, int nKeyMode )
{
	if ( NULL == rawdata )
	{
		printf( "error: the ipnput rawdata to be encrypted is NULL.\n" );
		return -1;
	}
	if ( nDataLen <= 0  || nDataLen > MAX_RAW_DATA_LENGTH )
	{
		printf( "error: the ipnput rawdata's Length is not right.\n" );
		return -1;
	}
	if ( NULL == userkey  )
	{
		printf( "error: the ipnput userkey is NULL.\n" );
		return -1;
	}
	/***********************************************/
	//对传递的密钥长度的表示还需仔细考虑
	switch( nKeyMode )
	{
	case _3DES_2K_ECB:
		if ( keyLen != 16 )
		{
			printf( "error: keyLen 'value( %d ) is not right , it should be 16 octects in 3DES_2K_ECB mode.\n", keyLen );
			return -1;
		}
		break;
	case _3DES_3K_ECB:
		if ( keyLen != 24 )
		{
			printf( "error: keyLen 'value( %d ) is not right , it should be 24 octects in 3DES_3K_ECB mode.\n", keyLen );
			return -1;
		}
		break;
	default:
		printf( "error: input keyMode's value is not right. \n" );
		break;
	}
	/**********************************************/
	return 0;
}


int CheckInputDecryptParameters_3DES(unsigned char *ciphertext, int ncipherLen, unsigned char *userkey, unsigned int keyLen, int nKeyMode )
{
	if ( NULL == ciphertext )
	{
		printf( "error: the ipnput ciphertext to be decrypted is NULL.\n" );
		return -1;
	}
	if ( ncipherLen <= 0  || ncipherLen > MAX_BUFF_SIZE )
	{
		printf( "error: the ipnput ciphertext's Length is not right.\n" );
		return -1;
	}

	if ( NULL == userkey  )
	{
		printf( "error: the ipnput userkey is NULL.\n" );
		return -1;
	}

	/***********************************************/
	//对传递的密钥长度的表示还需仔细考虑
	switch( nKeyMode )
	{
	case _3DES_2K_ECB:
		if ( keyLen != 16 )
		{
			printf( "error: keyLen 'value( %d ) is not right , it should be 16 octects in 3DES_2K_ECB mode.\n", keyLen );
			return -1;
		}
		break;
	case _3DES_3K_ECB:
		if ( keyLen != 24 )
		{
			printf( "error: keyLen 'value( %d ) is not right , it should be 24 octects in 3DES_3K_ECB mode.\n", keyLen );
			return -1;
		}
		break;
	default:
		printf( "error: input KeyMode's value is not right. \n" );
		break;
	}
	/**********************************************/

	return 0;
}

int CheckInputEncryptParameters(unsigned char *rawdata, int nDataLen, unsigned char *userkey, unsigned int keyLen )
{
	if ( NULL == rawdata )
	{
		printf( "error: the ipnput rawdata to be encrypted is NULL.\n" );
		return -1;
	}
	if ( nDataLen <= 0  || nDataLen > MAX_RAW_DATA_LENGTH )
	{
		printf( "error: the ipnput rawdata's Length is not right.\n" );
		return -1;
	}
	if ( NULL == userkey  )
	{
		printf( "error: the ipnput userkey is NULL.\n" );
		return -1;
	}

	//对传递的密钥长度的表示还需仔细考虑
	if ( keyLen != 8 )
	{
		printf( "error: keyLen 'value( %d ) is not right , it should be 8 octects in DES algrithm.\n", keyLen );
		return -1;
	}
	return 0;
}


int CheckInputDecryptParameters(unsigned char *ciphertext, int ncipherLen, unsigned char *userkey, unsigned int keyLen )
{
	if ( NULL == ciphertext )
	{
		printf( "error: the ipnput ciphertext to be decrypted is NULL.\n" );
		return -1;
	}
	if ( ncipherLen <= 0  || ncipherLen > MAX_BUFF_SIZE )
	{
		printf( "error: the ipnput ciphertext's Length is not right.\n" );
		return -1;
	}

	if ( NULL == userkey  )
	{
		printf( "error: the ipnput userkey is NULL.\n" );
		return -1;
	}

	//对传递的密钥长度的表示还需仔细考虑
	if ( keyLen != 8 )
	{
		printf( "error: keyLen 'value( %d ) is not right , it should be 8 octects in DES algrithm.\n", keyLen );
		return -1;
	}
	return 0;
}
