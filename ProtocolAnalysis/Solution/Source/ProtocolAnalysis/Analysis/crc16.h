#ifndef _CRC16_H
#define _CRC16_H
/*
参数说明
crc: 设置crc类型,通常都使用0;
buf: 原始数据.
len: 数据长度.
返回值: 返回根据输入数据计算出的CRC码,两个字节

*/
unsigned short crc16(unsigned short crc, unsigned char *buf, unsigned int len);
#endif				/* crc16.h */
