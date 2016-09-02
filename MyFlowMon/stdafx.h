
// stdafx.h : ��׼ϵͳ�����ļ��İ����ļ���
// ���Ǿ���ʹ�õ��������ĵ�
// �ض�����Ŀ�İ����ļ�

#pragma once

#ifndef _SECURE_ATL
#define _SECURE_ATL 1
#endif

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN            // �� Windows ͷ���ų�����ʹ�õ�����
#endif

#include "targetver.h"

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS      // ĳЩ CString ���캯��������ʽ��

// �ر� MFC ��ĳЩ�����������ɷ��ĺ��Եľ�����Ϣ������
#define _AFX_ALL_WARNINGS

#include <afxwin.h>         // MFC ��������ͱ�׼���
#include <afxext.h>         // MFC ��չ


#include <afxdisp.h>        // MFC �Զ�����



#ifndef _AFX_NO_OLE_SUPPORT
#include <afxdtctl.h>           // MFC �� Internet Explorer 4 �����ؼ���֧��
#endif
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>             // MFC �� Windows �����ؼ���֧��
#endif // _AFX_NO_AFXCMN_SUPPORT

#include <afxcontrolbars.h>     // �������Ϳؼ����� MFC ֧��



#include <string>

using namespace std;

#include "..\\LoadDrive\\LoadDrive.h"
#pragma comment(lib,"..\\bin\\LoadDrive.lib")

#define LOADDEVICE 1           //��ʶ�Ƿ�����豸���Ʋ��ִ���
#define RENAMESYS  0

#define FwSysFileDirectory32 "\\i386\\"       //tdi�����ļ���32λϵͳ
#define FwSysFileDirectory64 "\\amd64\\"       //�����ļ���64λϵͳ
#define FwSysFile "inspect.sys"       //�����ļ���32λϵͳ
#define FwSysFile32 "inspectX86.sys"       //�����ļ���32λϵͳ
#define FwSysFile64 "inspectX64.sys"       //�����ļ���64λϵͳ
#define FwSvcName "FlowMonInspect"         //��ʾ������������
#define FwLnkName "\\\\.\\FlowMonInspect"  //����ͨѶʱ��������
#define FwLnkNameT _T("\\\\.\\FlowMonInspect")

#define FwRegePath _T("Software\\LBZ\\FwDriverLife") //����ǽ����·��







#ifdef _UNICODE
#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
#endif


