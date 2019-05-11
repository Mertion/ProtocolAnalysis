#include "stdafx.h"

//数据缓存大小
#define MAX_DATABUFFERSIZE 8192

enum ENUM_PROTOCOLPACkAGE
{
	ENUM_PROTOCOLPACkAGE_SUCCESS = 0,		//成功解出数据包
	ENUM_PROTOCOLPACkAGE_FAILED,			//操作失败
	ENUM_PROTOCOLPACkAGE_NONE,				//没解出数据包
	ENUM_PROTOCOLPACkAGE_ERROR_HEAD,		//数据包头格式错误
	ENUM_PROTOCOLPACkAGE_ERROR_END,			//数据包尾格式错误
	ENUM_PROTOCOLPACkAGE_ERROR_DATALEN,		//数据包尾格式错误
	ENUM_PROTOCOLPACkAGE_ERROR_CRC,			//CRC校验错误
};

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
int __stdcall ProtocolPackage(IN const byte* p_byteSourceData, IN int p_nSourceDataLen, OUT byte* p_bytearrCMD, OUT int* p_pCMDLen);

//************************************
// Method:    ProtocolUnpacking
// FullName:  ProtocolUnpacking
// Access:    public 
// Returns:   int
// Qualifier: 协议解包
// Parameter: IN const byte p_byteSourceData[]
// Parameter: IN int p_nSourceDataLen
// Parameter: OUT byte * p_bytearrCMD
// Parameter: OUT int * p_pCMDLen
//************************************
int __stdcall ProtocolUnpacking(IN OUT byte* p_pbyteSourceData, IN OUT int* p_pnSourceDataLen, OUT byte* p_bytearrCMD, OUT int* p_pCMDLen);
