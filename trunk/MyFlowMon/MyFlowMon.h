
// MyFlowMon.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CMyFlowMonApp:
// �йش����ʵ�֣������ MyFlowMon.cpp
//

class CMyFlowMonApp : public CWinApp
{
public:
	CMyFlowMonApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CMyFlowMonApp theApp;