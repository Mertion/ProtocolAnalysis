// ProtocolAnalysis.h : ProtocolAnalysis DLL ����ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CProtocolAnalysisApp
// �йش���ʵ�ֵ���Ϣ������� ProtocolAnalysis.cpp
//

class CProtocolAnalysisApp : public CWinApp
{
public:
	CProtocolAnalysisApp();

// ��д
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
};
