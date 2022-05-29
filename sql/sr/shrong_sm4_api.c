#include "stdlib.h"
#include "stdio.h"
#include <string.h>
#include <stdbool.h>

#include "shrong_sm4_api.h"
//#include "sql/server_component/kms_imp.h"

#define INFO printf



static int PrintData(char *itemName, unsigned char *sourceData, unsigned int dataLength, unsigned int rowCount)
{
    int i, j;
    if ((sourceData == NULL) || (rowCount == 0) || (dataLength == 0))
        return -1;
    if (itemName != NULL)
        INFO("%s[%d]:\n", itemName, dataLength);
    for (i = 0; i < (int)(dataLength / rowCount); i++)
    {
        INFO("%08x  ", i * rowCount);
        for (j = 0; j < (int)rowCount; j++)
        {
            INFO("%02x ", *(sourceData + i * rowCount + j));
        }
        INFO("\n");
    }
    if (!(dataLength % rowCount))
        return 0;
    INFO("%08x  ", (dataLength / rowCount) * rowCount);
    for (j = 0; j < (int)(dataLength % rowCount); j++)
    {
        INFO("%02x ", *(sourceData + (dataLength / rowCount) * rowCount + j));
    }
    INFO("\n");
    return 0;
}


int sr_sm4_encrypt(
    unsigned char *userKey,
    unsigned int nUserKeyLen,
    unsigned char mode,
    unsigned char padding,
    unsigned char *pIV,
    unsigned int nIVLen,
    unsigned char *pRawData,
    unsigned int nRawDataLen,
    unsigned char *pOutCipher,
    unsigned int *nCipherLen)
{
    if (!pRawData)
        return -1;
    if (nRawDataLen==0) {
        INFO("warning: sr_sm4_encrypt input data length is 0\n");
    } else if (nRawDataLen>1024) {
        INFO("error: sr_sm4_encrypt input data length is %d\n", nRawDataLen);
        return -1;
    }

    SR_SM4_KEY sm4key;
    memset(&sm4key, 0, sizeof(SR_SM4_KEY));

    SR_SM4_set_key(userKey, &sm4key);

    unsigned char *pInputParam = NULL;
    //  int nBuffLen = nRawDataLen + SM4_BLOCK_SIZE ;
    int nBuffLen = nRawDataLen + SM4_BLOCK_SIZE * 2;
    pInputParam = malloc(nBuffLen);
    if (!pInputParam)
    {
        return -1;
    }
    memset(pInputParam, 0, nBuffLen);

    int nPadLen = 0;
    if (padding) {
        if (0 != nRawDataLen % SM4_BLOCK_SIZE)
            nPadLen = SM4_BLOCK_SIZE - nRawDataLen % SM4_BLOCK_SIZE;
            /**********************/
        else
            nPadLen = SM4_BLOCK_SIZE; // 2022.02.19 added
        /**********************/
    } else {
        nPadLen = 0;
    }

    int nInputLen = nRawDataLen + nPadLen;

    memcpy(pInputParam, pRawData, nRawDataLen);

    if (0 != nPadLen)
    {
	if (padding==2) {
	    pInputParam[nRawDataLen] = 0x80;
            for(int i=nPadLen;i>1;i--) {
	        pInputParam[nRawDataLen + i - 1] = 0;
	    }
	} else if (padding==1) {
            pInputParam[nRawDataLen + nPadLen - 1] = nPadLen;
	}
    }
    //  printf("\n");
    PrintData("sr_sm4_encrypt(inner)", pInputParam, nInputLen, 16  );

    int offset = 0;
    while (offset < nInputLen)
    {
        SR_SM4_encrypt(pInputParam + offset, pOutCipher + offset, &sm4key);
        offset += 16;
    }
    //  printf("\n");
    //  PrintData("sr_sm4_encrypt(inner)", pOutCipher, nInputLen, 16  );

    *nCipherLen = nInputLen;
    if (pInputParam)
    {
        free(pInputParam);
        pInputParam = NULL;
    }

    return 0;
}

int sr_sm4_decrypt1(
    unsigned char *userKey,
    unsigned int nUserKeyLen,
    unsigned char mode,
    unsigned char padding,
    unsigned char *pIV,
    unsigned int nIVLen,
    unsigned char *pCipher,
    unsigned int nCipherLen,
    unsigned char *pOutlain,
    unsigned int *nplainLen)
{
#ifdef PRINTF_EN
    INFO("sr_sm4_decrypt() input, nCipherLen = %ld\n", nCipherLen);
#endif
    if (!userKey)
        return -1;
//    if (SM4_KEY_SIZE != nUserKeyLen)
//        return -1;

    if (!pCipher)
        return -1;
    if (0 == nCipherLen)
        return -1;

    SR_SM4_KEY sm4key;
    memset(&sm4key, 0, sizeof(SR_SM4_KEY));

    SR_SM4_set_key(userKey, &sm4key);

    int offset = 0;
    while (offset < nCipherLen) //改为按照实际的原始数据长度进行循环加密
    {
        SR_SM4_decrypt(pCipher + offset, pOutlain + offset, &sm4key);
        offset += 16;
    }

    //如果增加了padding,还需要去除掉padding.
    unsigned char padValue = pOutlain[nCipherLen - 1];
    unsigned int nValidLength = 0;
    if(padding==1) {
        if (padValue >= 0x01 && padValue <= 0x10)
        {
            nValidLength = nCipherLen - padValue;
            pOutlain[nValidLength] = '\0';
        } else {
            INFO("error: cipher is corrupted\n");
            return -1;
        }
        *nplainLen = nValidLength;
    } else if (padding==2) {
	int i=nCipherLen-1;
        for(;i>0;i--) {
            nValidLength = nCipherLen - padValue;
	    if(pOutlain[i]==0) // 0x00
		    continue;
	    else if(pOutlain[i]==0x80) // 0x80
		    break;
	    else if(i<nCipherLen-16) //no 0x80 found
		    return -1;
	}
	*nplainLen = i;
    } else {
        *nplainLen = nCipherLen;
    }

#ifdef PRINTF_EN
    INFO("sr_sm4_decrypt() output, *nplainLen = %d\n", *nplainLen);
#endif
    return 0;
}
