
// MyFlowMonDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "MyFlowMon.h"
#include "MyFlowMonDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

bool CMyFlowMonDlg::m_bUnload = false;

// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// CMyFlowMonDlg �Ի���




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


// CMyFlowMonDlg ��Ϣ�������

BOOL CMyFlowMonDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CMyFlowMonDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
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
		//32 λ����ϵͳ  
		_tprintf(_T("is 32 bit OS\r\n"));  
	}  
	return bRetVal;  
}


//���ļ�·����ȡ�ļ�Ŀ¼
BOOL GetFileDirectoryA(CHAR *RealExistFilePath,int len,CHAR *FilePath)
{
	int i=0;
	CHAR lpPath[260];
	BOOL bRetOK = FALSE;

	//wcslen(L"x:\\")*2
	//Ч��Ϸ��ĳ��ȣ���Ȼ�������©����Ҫ����Ŷ
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
	//ѭ���ȴ�������Ϣ
	while(TRUE)
	{
		if(NULL == pMainDlg->m_hMainDevice || !DeviceIoControl(pMainDlg->m_hMainDevice, MonitorFlowData, &FwMess, sizeof(FlowInfo), NULL, 0, &dwRet, NULL))
			break;
		fDownSpeed = (float)FwMess.dwDownTpye/1024;
		fUpSpeed = (float)FwMess.dwUpTpye/1024;
		_stprintf_s(tcsErr, _T("���ϴ��ٶ�:%0.2fKb/s,�������ٶ�:%0.2fKb/s"), fUpSpeed, fDownSpeed);
		SetDlgItemText(pMainDlg->m_hWnd, IDC_STATIC3, tcsErr);
		fDownSpeed = (float)FwMess.dwDownTpyeLAN/1024;
		fUpSpeed = (float)FwMess.dwUpTpyeLAN/1024;
		_stprintf_s(tcsErr, _T("�������ϴ��ٶ�:%0.2fKb/s,�����������ٶ�:%0.2fKb/s"), fUpSpeed, fDownSpeed);
		SetDlgItemText(pMainDlg->m_hWnd, IDC_STATIC2, tcsErr);

		fDownSpeed = (float)FwMess.dwDownTpyeWAN/1024;
		fUpSpeed = (float)FwMess.dwUpTpyeWAN/1024;
		_stprintf_s(tcsErr, _T("�����ϴ��ٶ�:%0.2fKb/s,���������ٶ�:%0.2fKb/s"), fUpSpeed, fDownSpeed);
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

	::MessageBoxA(0, "����߳��˳�", "��ʾ", MB_OK);
	return 0;
}

void CMyFlowMonDlg::OnBnClickedBtnLoadsys()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	BOOL bIs64 = Is64Bit_OS();

	//ͨѶǰ�ȼ�������
	char lpPath[260] = {0};
	char lpModule[260] = {0};
	//��ȡ��ǰ·��
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
		::MessageBox(this->m_hWnd, _T("�������سɹ�..."), _T("��ʾ:"), MB_OK);
		//�򿪷���ǽ�豸,(ע������豸��Ҫ��UI�߳��д�,���Բ��ܷ�װ��dll��ά��)
		m_hMainDevice = CreateFile(FwLnkNameT/*_T("\\\\.\\Wall_Device")*/,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
		if(m_hMainDevice == INVALID_HANDLE_VALUE)
		{
			AfxMessageBox(_T("���豸ʧ�ܣ����򼴽��˳���"),MB_OK | MB_ICONSTOP );
			exit(0);
		}
		HANDLE hThread = NULL;
		hThread = CreateThread(0, 0, R0ThreadProc, this, 0, 0);
		if(NULL != hThread)
			CloseHandle(hThread);

	}
	else
		::MessageBox(this->m_hWnd, _T("��������ʧ��..."), _T("����:"), MB_OK);

}


void CMyFlowMonDlg::OnBnClickedBtnUnloadsys()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CMyFlowMonDlg::m_bUnload = true;

	CLoadDrive mLoadDrive;

	if (NULL != this->m_hMainDevice)
	{
		CloseHandle( this->m_hMainDevice );
		this->m_hMainDevice = NULL;
	}

	//if (mLoadDrive.UnLoadFwDriver(&(this->m_hMainDevice)))
	if (mLoadDrive.UnLoadNTDriver(FwSvcName))
		::MessageBox(this->m_hWnd, _T("����ж�سɹ�..."), _T("��ʾ:"), MB_OK);
	else
		::MessageBox(this->m_hWnd, _T("����ж��ʧ��..."), _T("����:"), MB_OK);
}


void CMyFlowMonDlg::OnBnClickedBtnLimitup()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	TCHAR tcsUp[260] = {};
	DWORD dwUp = 0;
	GetDlgItemText(IDC_EDIT1, tcsUp, sizeof(tcsUp));

	LARGE_INTEGER li = {0};
	_stscanf(tcsUp,_T("%u"), &dwUp);

	CLoadDrive mLoadDrive;

	if(mLoadDrive.FwAddLimitUpSpeed(this->m_hMainDevice, dwUp))
		::MessageBox(this->m_hWnd, _T("�ɹ�..."), _T("��ʾ:"), MB_OK);
	else
		::MessageBox(this->m_hWnd, _T("ʧ��..."), _T("��ʾ:"), MB_OK);
}


void CMyFlowMonDlg::OnBnClickedBtnLimitdown()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	TCHAR tcsDown[260] = {};
	DWORD dwDown = 0;
	GetDlgItemText(IDC_EDIT2, tcsDown, sizeof(tcsDown));

	LARGE_INTEGER li = {0};
	_stscanf(tcsDown,_T("%u"), &dwDown);

	CLoadDrive mLoadDrive;

	if(mLoadDrive.FwAddLimitDownSpeed(this->m_hMainDevice, dwDown))
		::MessageBox(this->m_hWnd, _T("�ɹ�..."), _T("��ʾ:"), MB_OK);
	else
		::MessageBox(this->m_hWnd, _T("ʧ��..."), _T("��ʾ:"), MB_OK);

}
