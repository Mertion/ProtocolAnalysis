#include "stdafx.h"
#include "IFProtocolAnalysis.h"
#include "crc16.h"

//协议包格式数据长度，包括：包头(1)、包尾(1)、指令类型(1)、数据长度(4)、校验码(2)
const int CONST_PROTOCOLDADALEN = 9;

//int DectoHex(int dec, unsigned char *hex, int length)
//{
//	int i;
//	for (i = length - 1; i >= 0; i--)
//	{
//		hex[i] = (dec % 256) & 0xFF;
//		dec /= 256;
//	}
//	return 0;
//}


unsigned char *ConvertCRC(unsigned char *arr, long bytesSend)
{
	unsigned char *array = new unsigned char[bytesSend];
	int ChConvertHex = 0;
	for (int i = 0; i < bytesSend; i++)
	{
		ChConvertHex = int(arr[i]);
		array[i] = ChConvertHex;
		if (i == bytesSend)
			break;

	}
	return array;

}

unsigned short BuildCRC(IN const byte* p_byteSourceData, const int p_nDataLen)
{
	//生成CRC校验码
	unsigned short crc1;
	unsigned char *array_temp = new unsigned char[p_nDataLen];
	unsigned char *array = new unsigned char[p_nDataLen];
	memcpy(array, p_byteSourceData, p_nDataLen);
	array_temp = ConvertCRC(array, p_nDataLen);
	crc1 = crc16(0x0000, array_temp, p_nDataLen);

	delete[] array;
	delete[] array_temp;

	return crc1;
}
//************************************
// Method:    ProtocolPackage
// FullName:  ProtocolPackage
// Access:    public 
// Returns:   int
// Qualifier: 协议打包
// Parameter: IN const byte p_byteSourceData[] 输入数据
// Parameter: IN int p_nSourceDataLen 输入数据长度
// Parameter: OUT byte * p_bytearrCMD 生成指令
// Parameter: OUT int * p_pCMDLen 生成指令长度
//************************************
int __stdcall ProtocolPackage(IN const byte* p_byteSourceData, IN const int p_nSourceDataLen, OUT byte* p_bytearrCMD, OUT int* p_pCMDLen)
{
	//判断要打包的数据长度是否超过缓存大小。
	if (MAX_DATABUFFERSIZE < p_nSourceDataLen)
	{
		return ENUM_PROTOCOLPACkAGE_FAILED;
	}

	int t_nDataLen = p_nSourceDataLen + CONST_PROTOCOLDADALEN ;
	byte* t_byteTempData = new byte[t_nDataLen + 1];
	memset(t_byteTempData, 0, (t_nDataLen + 1));

	//设置包头
	t_byteTempData[0] = 0x02;
	//设置包格式：0-JSON,1-TLV
	t_byteTempData[1] = 0x00;
	//设置包长度
	memcpy(t_byteTempData + 2, &p_nSourceDataLen, 4);
	//设置包数据
	memcpy(t_byteTempData + 6, p_byteSourceData, p_nSourceDataLen);
	//生成校验码
	unsigned short crc1 = BuildCRC(p_byteSourceData, p_nSourceDataLen);
	//设置校验码
	memcpy(t_byteTempData + 6 + p_nSourceDataLen, &crc1, 2);
	//设置包尾
	t_byteTempData[(t_nDataLen - 1)] = 0x03;

	//输出数据包
	memset(p_bytearrCMD, 0, 1024);
	memcpy(p_bytearrCMD, t_byteTempData, t_nDataLen);
	*p_pCMDLen = t_nDataLen;

	delete [] t_byteTempData;
	return ENUM_PROTOCOLPACkAGE_SUCCESS;
}

//************************************
// Method:    ProtocolUnpacking
// FullName:  ProtocolUnpacking
// Access:    public 
// Returns:   int
// Qualifier: 协议解包
// Parameter: IN OUT byte* p_pbyteSourceData 输入数据及拆包后剩余数据
// Parameter: IN OUT int* p_pnSourceDataLen 输入数据长度及拆包后剩余数据长度
// Parameter: OUT byte * p_bytearrCMD 成功拆出的数据包
// Parameter: OUT int * p_pCMDLen 成功解包的数据包长度
//************************************
int __stdcall ProtocolUnpacking(IN OUT byte* p_pbyteSourceData, IN OUT int* p_pnSourceDataLen, OUT byte* p_bytearrCMD, OUT int* p_pCMDLen)
{
	int t_nDatalen = *p_pnSourceDataLen;
	//判断数据长度是否超过1包数据的基本长度
	if (t_nDatalen < 10)
	{
		return ENUM_PROTOCOLPACkAGE_NONE;
	} 
	else if (t_nDatalen >= MAX_DATABUFFERSIZE)
	{
		return ENUM_PROTOCOLPACkAGE_ERROR_DATALEN;
	}
	
	//复制数据副本
	byte* t_byteTempData = new byte[t_nDatalen];
	memset(t_byteTempData, 0, t_nDatalen);
	memcpy(t_byteTempData, p_pbyteSourceData, t_nDatalen);

	//校验包头
	if (0x02 != t_byteTempData[0])
	{
		memset(p_pbyteSourceData, 0, t_nDatalen);
		*p_pnSourceDataLen = 0;
		delete[] t_byteTempData;

		return ENUM_PROTOCOLPACkAGE_ERROR_HEAD;
	}

	//获取数据长度
	int t_nPackageCmdLen = 0;
	memcpy(&t_nPackageCmdLen, t_byteTempData + 2, 4);
	//数据包长度校验
	if ((t_nPackageCmdLen + CONST_PROTOCOLDADALEN) > t_nDatalen)
	{
		delete[] t_byteTempData;

		return ENUM_PROTOCOLPACkAGE_NONE;
	}
	
	//校验数据包尾
	if (0x03 != t_byteTempData[(t_nPackageCmdLen + CONST_PROTOCOLDADALEN - 1)])
	{
		memset(p_pbyteSourceData, 0, t_nDatalen);
		*p_pnSourceDataLen = 0;
		delete[] t_byteTempData;

		return ENUM_PROTOCOLPACkAGE_ERROR_END;
	}

	//校验CRC
	//生成校验码
	unsigned short crc1 = BuildCRC(t_byteTempData + 6, t_nPackageCmdLen);
	unsigned short crc2 = 0;
	memcpy(&crc2, t_byteTempData + t_nPackageCmdLen + 6, 2);
	if (crc1 != crc2)
	{
		return ENUM_PROTOCOLPACkAGE_ERROR_CRC;
	}

	//提取数据包
	int t_nPackeLen = t_nPackageCmdLen + CONST_PROTOCOLDADALEN;
	*p_pCMDLen = t_nPackageCmdLen;
	memset(p_bytearrCMD, 0, 8192);
	memcpy(p_bytearrCMD, t_byteTempData + 6, (t_nPackeLen - 9));

	//在原数据包中剔除已提取数据
	memset(p_pbyteSourceData, 0, t_nDatalen);
	memcpy(p_pbyteSourceData, t_byteTempData + t_nPackeLen, (t_nDatalen - t_nPackeLen));

	return ENUM_PROTOCOLPACkAGE_SUCCESS;
}
