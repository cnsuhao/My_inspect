
// MyFlowMonDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "MyFlowMon.h"
#include "MyFlowMonDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

bool CMyFlowMonDlg::m_bUnload = false;

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMyFlowMonDlg 对话框




CMyFlowMonDlg::CMyFlowMonDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CMyFlowMonDlg::IDD, pParent)
{
	//m_bUnload = false;
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMyFlowMonDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CMyFlowMonDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_Btn_LoadSys, &CMyFlowMonDlg::OnBnClickedBtnLoadsys)
	ON_BN_CLICKED(IDC_Btn_UnLoadSys, &CMyFlowMonDlg::OnBnClickedBtnUnloadsys)
	ON_BN_CLICKED(IDC_Btn_LimitUp, &CMyFlowMonDlg::OnBnClickedBtnLimitup)
	ON_BN_CLICKED(IDC_Btn_LimitDown, &CMyFlowMonDlg::OnBnClickedBtnLimitdown)
END_MESSAGE_MAP()


// CMyFlowMonDlg 消息处理程序

BOOL CMyFlowMonDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMyFlowMonDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMyFlowMonDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMyFlowMonDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

typedef void (WINAPI *LPFN_PGNSI)(LPSYSTEM_INFO);

BOOL Is64Bit_OS()  
{  
	BOOL bRetVal = FALSE;  
	SYSTEM_INFO si = { 0 };  
	LPFN_PGNSI pGNSI = (LPFN_PGNSI) GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "GetNativeSystemInfo");  
	if (pGNSI == NULL)  
	{  
		return FALSE;  
	}  
	pGNSI(&si);  
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||   
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 )  
	{  
		bRetVal = TRUE;  
	}  
	else  
	{  
		//32 位操作系统  
		_tprintf(_T("is 32 bit OS\r\n"));  
	}  
	return bRetVal;  
}


//从文件路径获取文件目录
BOOL GetFileDirectoryA(CHAR *RealExistFilePath,int len,CHAR *FilePath)
{
	int i=0;
	CHAR lpPath[260];
	BOOL bRetOK = FALSE;

	//wcslen(L"x:\\")*2
	//效验合法的长度，不然产生溢出漏洞，要蓝屏哦
	if (len < 6 || len > 260)
		return bRetOK;

	memset(lpPath,0,sizeof(lpPath));
	memset(FilePath,0,sizeof(FilePath));

	memcpy(lpPath,RealExistFilePath,len);
	for(i=0;i<len;i++)
	{
		if (strstr(lpPath,"\\") == 0)
		{
			bRetOK = TRUE;
			memcpy(FilePath,RealExistFilePath,strlen(RealExistFilePath) - strlen(lpPath));
			break;
		}
		memset(lpPath,0,sizeof(lpPath));
		memcpy(lpPath,RealExistFilePath+i,strlen(RealExistFilePath+i));
	}
	return bRetOK;
}

DWORD WINAPI R0ThreadProc(LPVOID lpParameter)
{
	CMyFlowMonDlg* pMainDlg = (CMyFlowMonDlg*)lpParameter;
	//CLoadDrive mLoadDrive;
	FlowInfo FwMess = {0};
	TCHAR tcsErr[1024] = {};
	//char szMessage[512] = {0};
	DWORD dwRet = 0;
	float fDownSpeed = 0;
	float fUpSpeed = 0;
	//循环等待驱动消息
	while(TRUE)
	{
		if(NULL == pMainDlg->m_hMainDevice || !DeviceIoControl(pMainDlg->m_hMainDevice, MonitorFlowData, &FwMess, sizeof(FlowInfo), NULL, 0, &dwRet, NULL))
			break;
		fDownSpeed = (float)FwMess.dwDownTpye/1024;
		fUpSpeed = (float)FwMess.dwUpTpye/1024;
		_stprintf_s(tcsErr, _T("总上传速度:%0.2fKb/s,总下载速度:%0.2fKb/s"), fUpSpeed, fDownSpeed);
		SetDlgItemText(pMainDlg->m_hWnd, IDC_STATIC3, tcsErr);
		fDownSpeed = (float)FwMess.dwDownTpyeLAN/1024;
		fUpSpeed = (float)FwMess.dwUpTpyeLAN/1024;
		_stprintf_s(tcsErr, _T("局域网上传速度:%0.2fKb/s,局域网下载速度:%0.2fKb/s"), fUpSpeed, fDownSpeed);
		SetDlgItemText(pMainDlg->m_hWnd, IDC_STATIC2, tcsErr);

		fDownSpeed = (float)FwMess.dwDownTpyeWAN/1024;
		fUpSpeed = (float)FwMess.dwUpTpyeWAN/1024;
		_stprintf_s(tcsErr, _T("外网上传速度:%0.2fKb/s,外网下载速度:%0.2fKb/s"), fUpSpeed, fDownSpeed);
		SetDlgItemText(pMainDlg->m_hWnd, IDC_STATIC1, tcsErr);

		//memset(&FwMess, 0, sizeof(FlowInfo));
		FwMess.dwDownTpye = 0;
		FwMess.dwUpTpye = 0;

		if (CMyFlowMonDlg::m_bUnload)
		{
			break;
		}

		Sleep(1000);

	}

	::MessageBoxA(0, "监控线程退出", "提示", MB_OK);
	return 0;
}

void CMyFlowMonDlg::OnBnClickedBtnLoadsys()
{
	// TODO: 在此添加控件通知处理程序代码
	BOOL bIs64 = Is64Bit_OS();

	//通讯前先加载驱动
	char lpPath[260] = {0};
	char lpModule[260] = {0};
	//获取当前路径
	GetModuleFileNameA(NULL,lpModule,sizeof(lpModule));
	GetFileDirectoryA(lpModule,strlen(lpModule),lpPath);

	if (bIs64)
	{
#if RENAMESYS
		strcat(lpPath, "\\");
		strcat_s(lpPath, FwSysFile64);
#else
		strcat(lpPath, FwSysFileDirectory64);
		strcat_s(lpPath, FwSysFile);
#endif


	}
	else
	{
#if RENAMESYS
		strcat(lpPath, "\\");
		strcat_s(lpPath, FwSysFile32);
#else
		strcat(lpPath, FwSysFileDirectory32);
		strcat_s(lpPath, FwSysFile);
#endif

	}

	CLoadDrive mLoadDrive;
	TCHAR tcsErr[1024] = {0};

	//if (mLoadDrive.LoadFwDriver(lpPath))
	if (mLoadDrive.LoadNTDriver(FwSvcName, lpPath, tcsErr))
	{
		::MessageBox(this->m_hWnd, _T("驱动加载成功..."), _T("提示:"), MB_OK);
		//打开防火墙设备,(注意这个设备需要在UI线程中打开,所以不能封装在dll中维护)
		m_hMainDevice = CreateFile(FwLnkNameT/*_T("\\\\.\\Wall_Device")*/,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
		if(m_hMainDevice == INVALID_HANDLE_VALUE)
		{
			AfxMessageBox(_T("打开设备失败，程序即将退出！"),MB_OK | MB_ICONSTOP );
			exit(0);
		}
		HANDLE hThread = NULL;
		hThread = CreateThread(0, 0, R0ThreadProc, this, 0, 0);
		if(NULL != hThread)
			CloseHandle(hThread);

	}
	else
		::MessageBox(this->m_hWnd, _T("驱动加载失败..."), _T("错误:"), MB_OK);

}


void CMyFlowMonDlg::OnBnClickedBtnUnloadsys()
{
	// TODO: 在此添加控件通知处理程序代码
	CMyFlowMonDlg::m_bUnload = true;

	CLoadDrive mLoadDrive;

	if (NULL != this->m_hMainDevice)
	{
		CloseHandle( this->m_hMainDevice );
		this->m_hMainDevice = NULL;
	}

	//if (mLoadDrive.UnLoadFwDriver(&(this->m_hMainDevice)))
	if (mLoadDrive.UnLoadNTDriver(FwSvcName))
		::MessageBox(this->m_hWnd, _T("驱动卸载成功..."), _T("提示:"), MB_OK);
	else
		::MessageBox(this->m_hWnd, _T("驱动卸载失败..."), _T("错误:"), MB_OK);
}


void CMyFlowMonDlg::OnBnClickedBtnLimitup()
{
	// TODO: 在此添加控件通知处理程序代码
	TCHAR tcsUp[260] = {};
	DWORD dwUp = 0;
	GetDlgItemText(IDC_EDIT1, tcsUp, sizeof(tcsUp));

	LARGE_INTEGER li = {0};
	_stscanf(tcsUp,_T("%u"), &dwUp);

	CLoadDrive mLoadDrive;

	if(mLoadDrive.FwAddLimitUpSpeed(this->m_hMainDevice, dwUp))
		::MessageBox(this->m_hWnd, _T("成功..."), _T("提示:"), MB_OK);
	else
		::MessageBox(this->m_hWnd, _T("失败..."), _T("提示:"), MB_OK);
}


void CMyFlowMonDlg::OnBnClickedBtnLimitdown()
{
	// TODO: 在此添加控件通知处理程序代码
	TCHAR tcsDown[260] = {};
	DWORD dwDown = 0;
	GetDlgItemText(IDC_EDIT2, tcsDown, sizeof(tcsDown));

	LARGE_INTEGER li = {0};
	_stscanf(tcsDown,_T("%u"), &dwDown);

	CLoadDrive mLoadDrive;

	if(mLoadDrive.FwAddLimitDownSpeed(this->m_hMainDevice, dwDown))
		::MessageBox(this->m_hWnd, _T("成功..."), _T("提示:"), MB_OK);
	else
		::MessageBox(this->m_hWnd, _T("失败..."), _T("提示:"), MB_OK);

}
