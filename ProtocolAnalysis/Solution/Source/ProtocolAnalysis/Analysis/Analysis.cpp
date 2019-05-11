#include "stdafx.h"
#include "IFProtocolAnalysis.h"
#include "crc16.h"

//Э�����ʽ���ݳ��ȣ���������ͷ(1)����β(1)��ָ������(1)�����ݳ���(4)��У����(2)
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
	//����CRCУ����
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
// Qualifier: Э����
// Parameter: IN const byte p_byteSourceData[] ��������
// Parameter: IN int p_nSourceDataLen �������ݳ���
// Parameter: OUT byte * p_bytearrCMD ����ָ��
// Parameter: OUT int * p_pCMDLen ����ָ���
//************************************
int __stdcall ProtocolPackage(IN const byte* p_byteSourceData, IN const int p_nSourceDataLen, OUT byte* p_bytearrCMD, OUT int* p_pCMDLen)
{
	//�ж�Ҫ��������ݳ����Ƿ񳬹������С��
	if (MAX_DATABUFFERSIZE < p_nSourceDataLen)
	{
		return ENUM_PROTOCOLPACkAGE_FAILED;
	}

	int t_nDataLen = p_nSourceDataLen + CONST_PROTOCOLDADALEN ;
	byte* t_byteTempData = new byte[t_nDataLen + 1];
	memset(t_byteTempData, 0, (t_nDataLen + 1));

	//���ð�ͷ
	t_byteTempData[0] = 0x02;
	//���ð���ʽ��0-JSON,1-TLV
	t_byteTempData[1] = 0x00;
	//���ð�����
	memcpy(t_byteTempData + 2, &p_nSourceDataLen, 4);
	//���ð�����
	memcpy(t_byteTempData + 6, p_byteSourceData, p_nSourceDataLen);
	//����У����
	unsigned short crc1 = BuildCRC(p_byteSourceData, p_nSourceDataLen);
	//����У����
	memcpy(t_byteTempData + 6 + p_nSourceDataLen, &crc1, 2);
	//���ð�β
	t_byteTempData[(t_nDataLen - 1)] = 0x03;

	//������ݰ�
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
// Qualifier: Э����
// Parameter: IN OUT byte* p_pbyteSourceData �������ݼ������ʣ������
// Parameter: IN OUT int* p_pnSourceDataLen �������ݳ��ȼ������ʣ�����ݳ���
// Parameter: OUT byte * p_bytearrCMD �ɹ���������ݰ�
// Parameter: OUT int * p_pCMDLen �ɹ���������ݰ�����
//************************************
int __stdcall ProtocolUnpacking(IN OUT byte* p_pbyteSourceData, IN OUT int* p_pnSourceDataLen, OUT byte* p_bytearrCMD, OUT int* p_pCMDLen)
{
	int t_nDatalen = *p_pnSourceDataLen;
	//�ж����ݳ����Ƿ񳬹�1�����ݵĻ�������
	if (t_nDatalen < 10)
	{
		return ENUM_PROTOCOLPACkAGE_NONE;
	} 
	else if (t_nDatalen >= MAX_DATABUFFERSIZE)
	{
		return ENUM_PROTOCOLPACkAGE_ERROR_DATALEN;
	}
	
	//�������ݸ���
	byte* t_byteTempData = new byte[t_nDatalen];
	memset(t_byteTempData, 0, t_nDatalen);
	memcpy(t_byteTempData, p_pbyteSourceData, t_nDatalen);

	//У���ͷ
	if (0x02 != t_byteTempData[0])
	{
		memset(p_pbyteSourceData, 0, t_nDatalen);
		*p_pnSourceDataLen = 0;
		delete[] t_byteTempData;

		return ENUM_PROTOCOLPACkAGE_ERROR_HEAD;
	}

	//��ȡ���ݳ���
	int t_nPackageCmdLen = 0;
	memcpy(&t_nPackageCmdLen, t_byteTempData + 2, 4);
	//���ݰ�����У��
	if ((t_nPackageCmdLen + CONST_PROTOCOLDADALEN) > t_nDatalen)
	{
		delete[] t_byteTempData;

		return ENUM_PROTOCOLPACkAGE_NONE;
	}
	
	//У�����ݰ�β
	if (0x03 != t_byteTempData[(t_nPackageCmdLen + CONST_PROTOCOLDADALEN - 1)])
	{
		memset(p_pbyteSourceData, 0, t_nDatalen);
		*p_pnSourceDataLen = 0;
		delete[] t_byteTempData;

		return ENUM_PROTOCOLPACkAGE_ERROR_END;
	}

	//У��CRC
	//����У����
	unsigned short crc1 = BuildCRC(t_byteTempData + 6, t_nPackageCmdLen);
	unsigned short crc2 = 0;
	memcpy(&crc2, t_byteTempData + t_nPackageCmdLen + 6, 2);
	if (crc1 != crc2)
	{
		return ENUM_PROTOCOLPACkAGE_ERROR_CRC;
	}

	//��ȡ���ݰ�
	int t_nPackeLen = t_nPackageCmdLen + CONST_PROTOCOLDADALEN;
	*p_pCMDLen = t_nPackageCmdLen;
	memset(p_bytearrCMD, 0, 8192);
	memcpy(p_bytearrCMD, t_byteTempData + 6, (t_nPackeLen - 9));

	//��ԭ���ݰ����޳�����ȡ����
	memset(p_pbyteSourceData, 0, t_nDatalen);
	memcpy(p_pbyteSourceData, t_byteTempData + t_nPackeLen, (t_nDatalen - t_nPackeLen));

	return ENUM_PROTOCOLPACkAGE_SUCCESS;
}
