#ifndef __SR_SM4_API_HH__
#define __SR_SM4_API_HH__

#include <stdbool.h>
#include "shrong_sm4.h"

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif


//定义SM4加解密时的模式
enum
{
    ECB_MODE = 0,
    CBC_MODE = 1,
    CFB_MODE = 2,
    OFB_MODE = 3,
    CTR_MODE = 4,
};

/******************************************************************************
[功能描述] 世融能量内部SM4加密算法接口
[注意事项]
---目前本接口暂时只支持ECB模式，
---向量值不用时，填写为NULL，向量的长度填写为0；正常填写时，向量一般占用16个字节
---加密时，PADDING封装逻辑在API内部完成。调用者暂不用关心
[代码编写]  张群峰
*******************************************************************************/
int sr_sm4_encrypt(
    unsigned char *userKey,   // SM4密钥
    unsigned int nUserKeyLen, // SM4密钥字节长度
    unsigned char mode,       //算法模式
    unsigned char padding,    //是否填充对齐 0否 1-仿照pkcs 2-先填充0x80再填充0
    unsigned char *pIV,       //向量
    unsigned int nIVLen,      //向量字节长度
    unsigned char *rawData,   //待加密的原始数据
    unsigned int nRawDataLen, //待加密原始数据长度
    unsigned char *pCipher,   //加密后输出的密文
    unsigned int *nCipherLen  //加密后输出的密文长度
);

/******************************************************************************
[功能描述] 世融能量内部SM4解密算法接口
[注意事项]
---目前本接口暂时只支持ECB模式，
---向量值不用时，填写为NULL，向量的长度填写为0；正常填写时，向量一般占用16个字节
---解密后，API内部负责去掉PADDING
[代码编写]  张群峰
*******************************************************************************/
int sr_sm4_decrypt1(
    unsigned char *userKey,   // SM4密钥
    unsigned int nUserKeyLen, // SM4密钥字节长度
    unsigned char mode,       //算法模式
    unsigned char padding,    //是否填充对齐 0否 1-仿照pkcs 2-先填充0x80再填充0
    unsigned char *pIV,       //向量
    unsigned int nIVLen,      //向量字节长度
    unsigned char *pCipher,   //待解密的密文数据
    unsigned int nCipherLen,  //待解密密文数据长度
    unsigned char *pOutlain,  //解密后输出的明文
    unsigned int *nplainLen   //解密后输出的明文数据长度
);

// /******************************************************************************
// [功能描述] 调试函数，按照HEX打印输入的数据
// [代码编写]  张群峰
// *******************************************************************************/
// int PrintData(
//     char *itemName,            //由调试调用者填写的字符串
//     unsigned char *sourceData, //打印的数据字节流
//     unsigned int dataLength,   //字节流的长度
//     unsigned int rowCount      //每行打印多少个字节
// );

#ifdef __cplusplus
}
#endif


#endif //__SR_SM4_API_HH__
