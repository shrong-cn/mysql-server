
//shrong_des_api.h
#ifndef __SHRONG_DES_API_HH__
#define __SHRONG_DES_API_HH__

enum
{
	_3DES_2K_ECB   	=	1,     //3DES-2K模式（128位）
	_3DES_3K_ECB   	=	2,     //3DES-3K模式（192位）
};

#ifdef __cplusplus
extern "C" {
#endif


//为支持3-DES-ecb加密所封装的API
//返回值：0---SUCCESS； -1---FAILED
//解密后的明文缓存的内存由API的调用者负责分配和释放，API内部不再维护
int shrong_3des_ecb_encrypt(
		unsigned char *rawdata,      	//输入的待加密的原始字节流
		int nDataLen,      		//该原始字节流的长度
		unsigned char *userkey,	    	//所使用的密钥，使用时密钥的长度需要与加解密算法的类型相适配。
		unsigned int keyLen,         	//密钥字节的实际长度. 限定3DES_2K使用16个字节，3DES_3K使用24个字节
		int nKeyMode,                	//加解密算法密钥模式 1： _3DES_2K_ECB；  2： _3DES_3K_ECB
		unsigned char *pOutCipher,   	//加密后所输出密文字节流
		int *nCipherLength           	//该密文字节流的长度
		);

//为支持3-DES-ecb解密所封装的API
//返回值：0---SUCCESS； -1---FAILED
//解密后的明文缓存的内存由API的调用者负责分配和释放，API内部不再维护
int shrong_3des_ecb_decrypt(
		unsigned char *cipherdata,   	//输入的待解密的密文字节流
		int ncipherLen,      		//该密文字节流的长度
		unsigned char *userkey,	    	//所使用的密钥，使用时密钥的长度需要与加解密算法的类型相适配。
		unsigned int keyLen,         	//密钥字节的实际长度,限定3DES_2K使用16个字节，3DES_3K使用24个字节
		int nKeyMode,                	//加解密算法密钥模式 1： _3DES_2K_ECB；  2： _3DES_3K_ECB
		unsigned char *pOutPlain,   	//解密后所输出明文字节流
		int *nPlainLen           	//该明文字节流的有效长度
		);




//为支持DES-ecb加密所封装的API
//返回值：0---SUCCESS； -1---FAILED
int shrong_des_ecb_encrypt(
		unsigned char *rawdata,      	//输入的待加密的原始字节流
		int nDataLen,      		//该原始字节流的长度
		unsigned char *userkey,	    	//所使用的密钥，使用时密钥的长度需要与加解密算法的类型相适配。
		unsigned int keyLen,         	//密钥字节的实际长度,DES算法中密钥为8个字节
		unsigned char *pOutCipher,  	//加密后所输出密文字节流
		int *nCipherLength           	//该密文字节流的长度
		);

//为支持DES-ecb解密所封装的API
//返回值：0---SUCCESS； -1---FAILED
int shrong_des_ecb_decrypt(
		unsigned char *cipherdata,   	//输入的待解密的密文字节流
		int ncipherLen,      		//该密文字节流的长度
		unsigned char *userkey,	    	//所使用的密钥，使用时密钥的长度需要与加解密算法的类型相适配。
		unsigned int keyLen,         	//密钥字节的实际长度，DES算法中密钥默认为8个字节
		unsigned char *pOutPlain,    	//解密后所输出明文字节流
		int *nPlainLen           	//该明文字节流的长度
		);


#ifdef __cplusplus
}
#endif


#endif
