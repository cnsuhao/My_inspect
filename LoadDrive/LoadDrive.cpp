// LoadDrive.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include "LoadDrive.h"


// ���ǵ���������һ��ʾ��
// LOADDRIVE_API int nLoadDrive=0;
// 
// ���ǵ���������һ��ʾ����
// LOADDRIVE_API int fnLoadDrive(void)
// {
// 	return 42;
// }

// �����ѵ�����Ĺ��캯����
// �й��ඨ�����Ϣ������� LoadDrive.h
CLoadDrive::CLoadDrive()
{
	//m_hDevice = NULL;
	crc32_init();

	return;
}

CLoadDrive::~CLoadDrive()
{
// 	if (NULL != m_hDevice)
// 	{
// 		CloseHandle( m_hDevice );
// 		m_hDevice = NULL;
// 	}
	return;
}

BOOL CLoadDrive::Is64Bit_OS()
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
	return bRetVal;
}

BOOL CLoadDrive::LoadNTDriver(char* lpszDriverName,char* lpszDriverPath, TCHAR* tcsErr)
{
	char szDriverImagePath[256];
	//_asm int 3;
	//�õ�����������·��
	GetFullPathNameA(lpszDriverPath, 256, szDriverImagePath, NULL);
	//printf("���ص�����·��:%s\r\n", szDriverImagePath);
	BOOL bRet = FALSE;

	SC_HANDLE hServiceMgr=NULL;//SCM�������ľ��
	SC_HANDLE hServiceDDK=NULL;//NT��������ķ�����

	//�򿪷�����ƹ�����
	hServiceMgr = OpenSCManagerA( NULL, NULL, SC_MANAGER_ALL_ACCESS );

	if( hServiceMgr == NULL )  
	{
		//OpenSCManagerʧ��
		wsprintf(tcsErr, _T("OpenSCManager() Faild %d ! \n"), GetLastError());
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		////OpenSCManager�ɹ�
		wsprintf(tcsErr, _T("OpenSCManager() ok ! \n"));
	}

	//������������Ӧ�ķ���
	hServiceDDK = CreateServiceA( hServiceMgr,
		lpszDriverName, //�����������ע����е�����  
		lpszDriverName, // ע������������ DisplayName ֵ  
		SERVICE_ALL_ACCESS, // ������������ķ���Ȩ��  
		SERVICE_KERNEL_DRIVER,// ��ʾ���صķ�������������  
		SERVICE_DEMAND_START, // ע������������ Start ֵ  
		SERVICE_ERROR_IGNORE, // ע������������ ErrorControl ֵ  
		szDriverImagePath, // ע������������ ImagePath ֵ  
		NULL,  
		NULL,  
		NULL,  
		NULL,  
		NULL);  

	DWORD dwRtn;
	//�жϷ����Ƿ�ʧ��
	if( hServiceDDK == NULL )  
	{  
		dwRtn = GetLastError();
		if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS )  
		{  
			//��������ԭ�򴴽�����ʧ��
			wsprintf(tcsErr, _T("CrateService() ʧ�� %d ! \n"), dwRtn);
			bRet = FALSE;
			goto BeforeLeave;
		}  
		else  
		{
			//���񴴽�ʧ�ܣ������ڷ����Ѿ�������
			printf( "CrateService() ���񴴽�ʧ�ܣ������ڷ����Ѿ������� ERROR is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n" );  
		}

		// ���������Ѿ����أ�ֻ��Ҫ��  
		hServiceDDK = OpenServiceA( hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS );  
		if( hServiceDDK == NULL )  
		{
			//����򿪷���Ҳʧ�ܣ�����ζ����
			dwRtn = GetLastError();
			wsprintf(tcsErr, _T("OpenService() Faild %d ! \n"), dwRtn);
			bRet = FALSE;
			goto BeforeLeave;
		}  
		else
			wsprintf(tcsErr, _T("OpenService() ok ! \n"));
	}  
	else
		wsprintf(tcsErr, _T("CrateService() ok ! \n"));

	//�����������
	bRet= StartServiceA( hServiceDDK, NULL, NULL );  
	if( !bRet )  
	{  
		DWORD dwRtn = GetLastError();  
		if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING )  
		{
			wsprintf(tcsErr, _T("StartService() Faild %d ! \n"), dwRtn);
			bRet = FALSE;
			goto BeforeLeave;
		}  
		else  
		{  
			if( dwRtn == ERROR_IO_PENDING )  
			{  
				//�豸����ס
				wsprintf(tcsErr, _T("StartService() Faild ERROR_IO_PENDING ! \n"));
				bRet = FALSE;
				goto BeforeLeave;
			}  
			else  
			{  
				//�����Ѿ�����
				wsprintf(tcsErr, _T("StartService() Faild ERROR_SERVICE_ALREADY_RUNNING ! \n"));
				bRet = TRUE;
				goto BeforeLeave;
			}  
		}  
	}
	bRet = TRUE;
	//�뿪ǰ�رվ��
BeforeLeave:
	if(hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if(hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;
}

BOOL CLoadDrive::SendKernelData(char* LinkName, PVOID pInBuffer,int sizeIn, int inMSGCode, LPVOID lpOut, DWORD dwOutSize, TCHAR* tcsErr)
{
	HANDLE service = 0;
	HANDLE device = 0;
	//char ret[1024];
	//WCHAR ToSend[512];
	DWORD bytes;
	BOOLEAN bool_ret = FALSE;
	//device = CreateFile(_T("\\\\.\\wfp_sample_device"),GENERIC_ALL,0,NULL,OPEN_EXISTING,0,NULL);
	device = CreateFileA(LinkName, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if( !device || device == INVALID_HANDLE_VALUE ) {
		//printf("������ʧ�ܣ��������ز��ɹ�. %d\r\n",GetLastError());
		wsprintf(tcsErr, _T("������ʧ�ܣ��������ز��ɹ�. %d\r\n"), GetLastError());
		return bool_ret; 
	}
	//----"\\\\.\\My_DriverLinkName", //\\??\My_DriverLinkName
	bool_ret = DeviceIoControl(device,
		CODEMSG(inMSGCode),
		pInBuffer, 
		sizeIn, 
		lpOut, 
		dwOutSize,
		&bytes,
		NULL);
	if(bool_ret)
		wsprintf(tcsErr, _T("����ͨ����ɹ�\r\n"));
	CloseHandle(device);
	return bool_ret;
}

BOOL CLoadDrive::UnLoadNTDriver(char * szSvrName)
{
	//һ�������õ��ı���
	BOOL bRet = FALSE;
	SC_HANDLE hSCM=NULL;//SCM�������ľ��,�������OpenSCManager�ķ���ֵ
	SC_HANDLE hService=NULL;//NT��������ķ��������������OpenService�ķ���ֵ
	SERVICE_STATUS SvrSta;
	//����SCM������
	hSCM = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );  
	if( hSCM == NULL )  
	{
		//����SCM������ʧ��
		printf( "OpenSCManager() Faild %d ! \n", GetLastError() );  
		bRet = FALSE;
		goto BeforeLeave;
	}  
	else  
	{
		//��SCM�������ɹ�
		printf( "OpenSCManager() ok ! \n" );  
	}
	//������������Ӧ�ķ���
	hService = OpenServiceA( hSCM, szSvrName, SERVICE_ALL_ACCESS );  

	if( hService == NULL )  
	{
		//����������Ӧ�ķ���ʧ�� �˳�
		printf( "OpenService() Faild %d ! \n", GetLastError() );  
		bRet = FALSE;
		goto BeforeLeave;
	}  
	else  
	{  
		printf( "OpenService() ok ! \n" );  //����������Ӧ�ķ��� �ɹ�
	}  
	//��ֹͣ�����������ֹͣʧ�ܣ�ֻ�������������ܣ��ٶ�̬���ء�  
	if( !ControlService( hService, SERVICE_CONTROL_STOP , &SvrSta ) )  
	{  
		printf( "��ControlService() ֹͣ��������ʧ�� �����:%d !\n", GetLastError() );  
	}  
	else  
	{
		//ֹͣ��������ɹ�
		printf( "��ControlService() ֹͣ��������ɹ� !\n" );  
	}  
	//�嶯̬ж����������  
	if( !DeleteService( hService ) )  //TRUE//FALSE
	{
		//ж��ʧ��
		printf( "ж��ʧ��:DeleteSrevice()�����:%d !\n", GetLastError() );  
	}  
	else  
	{  
		//ж�سɹ�
		printf ( "ж�سɹ� !\n" );  

	}  
	bRet = TRUE;
	//�� �뿪ǰ�رմ򿪵ľ��
BeforeLeave:
	if(hService>0)
	{
		CloseServiceHandle(hService);
	}
	if(hSCM>0)
	{
		CloseServiceHandle(hSCM);
	}
	return bRet;
}

BOOL CLoadDrive::SendFwData(char* LinkName, PVOID pInBuffer,int sizeIn, int inMSGCode, LPVOID lpOut, DWORD dwOutSize, TCHAR* tcsErr)
{
	HANDLE service = 0;
	HANDLE device = 0;
	//char ret[1024];
	//WCHAR ToSend[512];
	DWORD bytes;
	BOOLEAN bool_ret = FALSE;

	//device = CreateFileA(LinkName, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	device = CreateFileA( LinkName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if( !device || device == INVALID_HANDLE_VALUE ) {
		//printf("������ʧ�ܣ��������ز��ɹ�. %d\r\n",GetLastError());
		wsprintf(tcsErr, _T("������ʧ�ܣ��������ز��ɹ�. %d\r\n"), GetLastError());
		return bool_ret; 
	}
	//----"\\\\.\\My_DriverLinkName", //\\??\My_DriverLinkName
	bool_ret = DeviceIoControl(device,
		CODEMSG_NET(inMSGCode),
		pInBuffer, 
		sizeIn, 
		lpOut, 
		dwOutSize,
		&bytes,
		NULL);
	if(bool_ret)
		wsprintf(tcsErr, _T("����ͨ����ɹ�\r\n"));
	CloseHandle(device);
	return bool_ret;
}

BOOL CLoadDrive::AddProtectPid(ULONG ulPid)
{
	typedef struct _ComRing0DatePid
	{
		int inSize;
		ULONG dwArry_Pid[254];
	}ComRing0DatePid, *pComRing0DatePid;

	ComRing0DatePid mComRing0Date = {0};
	mComRing0Date.inSize = 1;
	mComRing0Date.dwArry_Pid[0] = ulPid;
	int nOut = -1;
	TCHAR tcsErr[260] = {};
	TCHAR tcsMessage[1024] = {0};
	BOOL bFunc = SendKernelData("\\\\.\\MyRing0", &mComRing0Date, sizeof(mComRing0Date), 0x800, &nOut, sizeof(int), tcsErr);

	return bFunc;
}

BOOL CLoadDrive::RemoveProtectPid(ULONG ulPid)
{
	typedef struct _ComRing0DatePid
	{
		int inSize;
		ULONG dwArry_Pid[254];
	}ComRing0DatePid, *pComRing0DatePid;

	ComRing0DatePid mComRing0Date = {0};
	mComRing0Date.inSize = 1;
	mComRing0Date.dwArry_Pid[0] = ulPid;
	int nOut = -1;
	TCHAR tcsErr[260] = {};
	TCHAR tcsMessage[1024] = {0};
	BOOL bFunc = SendKernelData("\\\\.\\MyRing0", &mComRing0Date, sizeof(mComRing0Date), 0x802, &nOut, sizeof(int), tcsErr);

	return bFunc;
}

BOOL CLoadDrive::AddStopProc(UINT32 uinCrc32)
{
	int nOut = -1;
	TCHAR tcsErr[260] = {};
	TCHAR tcsMessage[1024] = {0};
	BOOL bFunc = SendKernelData("\\\\.\\MyRing0", &uinCrc32, sizeof(UINT32), 0x801, &nOut, sizeof(int), tcsErr);

	return bFunc;
}

//  BOOL CLoadDrive::AddStopProc(TCHAR* tcsProcessName)
//  {
//  	USES_CONVERSION; 
//  	UINT32 uinCrc32 = 0;
//  	WCHAR* wcsProcessName = NULL;
//  
//  #ifndef UNICODE
//  	wcsProcessName = A2W(tcsProcessName);
//  #else
//  	wcsProcessName = tcsProcessName;
//  #endif
// 
// 	size_t Crc32 = wcslen(wcsProcessName)*sizeof(WCHAR);
//  
//  	uinCrc32 = (UINT32)crc32_encode((char*)wcsProcessName, wcslen(wcsProcessName)*sizeof(WCHAR));
//  
//  	int nOut = -1;
//  	TCHAR tcsErr[260] = {};
//  	TCHAR tcsMessage[1024] = {0};
//  	BOOL bFunc = SendKernelData("\\\\.\\MyRing0", &uinCrc32, sizeof(UINT32), 0x801, &nOut, sizeof(int), tcsErr);
//  
//  	return bFunc;
//  }

  BOOL CLoadDrive::AddStopProc(char* szProcessName)
  {
  
  	USES_CONVERSION; 
  	UINT32 uinCrc32 = 0;
  	WCHAR* wcsProcessName = NULL;
  
  
  	wcsProcessName = A2W(szProcessName);
  
  
  	uinCrc32 = (UINT32)crc32_encode((char*)wcsProcessName, wcslen(wcsProcessName)*sizeof(WCHAR));
  
  	int nOut = -1;
  	TCHAR tcsErr[260] = {};
  	TCHAR tcsMessage[1024] = {0};
  	BOOL bFunc = SendKernelData("\\\\.\\MyRing0", &uinCrc32, sizeof(UINT32), 0x801, &nOut, sizeof(int), tcsErr);
  
  	return bFunc;
  }

BOOL CLoadDrive::RemoveStopProc(UINT32 uinCrc32)
{
	int nOut = -1;
	TCHAR tcsErr[260] = {};
	TCHAR tcsMessage[1024] = {0};
	BOOL bFunc = SendKernelData("\\\\.\\MyRing0", &uinCrc32, sizeof(UINT32), 0x803, &nOut, sizeof(int), tcsErr);

	return bFunc;
}

BOOL CLoadDrive::RemoveStopProc(TCHAR* tcsProcessName)
{
	USES_CONVERSION; 
	UINT32 uinCrc32 = 0;
	WCHAR* wcsProcessName = NULL;

#ifndef UNICODE
	wcsProcessName = A2W(tcsProcessName);
#else
	wcsProcessName = tcsProcessName;
#endif

	uinCrc32 = (UINT32)crc32_encode((char*)wcsProcessName, wcslen(wcsProcessName)*sizeof(WCHAR));

	int nOut = -1;
	TCHAR tcsErr[260] = {};
	TCHAR tcsMessage[1024] = {0};
	BOOL bFunc = SendKernelData("\\\\.\\MyRing0", &uinCrc32, sizeof(UINT32), 0x803, &nOut, sizeof(int), tcsErr);

	return bFunc;
}

BOOL CLoadDrive::LoadProctectDriver(char* lpszDriverPath)
{
	TCHAR tcsError[1024] = {0};
	BOOL bFunc = LoadNTDriver("MyRing0", lpszDriverPath, tcsError);

	return bFunc;
}

BOOL CLoadDrive::UnLoadProtectDriver()
{
	BOOL bFunc = UnLoadNTDriver("MyRing0");

	return bFunc;
}

LSTATUS InitRege(
	__in HKEY hKey,
	__in_opt LPCTSTR lpSubKey
	)
{
	LSTATUS status;
	DWORD cbSize = sizeof(DWORD);
	DWORD value = 1;
	HKEY hKeyGlobalrules = NULL, hKeyDnsrules = NULL, hKeyIprules = NULL, hKeyProcessrules = NULL, hkResult = NULL;


	status = RegCreateKey(hKey, lpSubKey, &hkResult);//HKEY_LOCAL_MACHINE  HKEY_CURRENT_USER
	if( status != ERROR_SUCCESS)
	{
		return status;
	}

	status = RegCreateKey(hkResult, _T("globalrules"), &hKeyGlobalrules);//HKEY_LOCAL_MACHINE  HKEY_CURRENT_USER
	if( status != ERROR_SUCCESS)
	{
		return status;
	}
	status = RegCreateKey(hkResult, _T("dnsrules"), &hKeyDnsrules);//HKEY_LOCAL_MACHINE  HKEY_CURRENT_USER
	if( status != ERROR_SUCCESS)
	{
		return status;
	}
	status = RegCreateKey(hkResult, _T("iprules"), &hKeyIprules);//HKEY_LOCAL_MACHINE  HKEY_CURRENT_USER
	if( status != ERROR_SUCCESS)
	{
		return status;
	}

	status = RegCreateKey(hkResult, _T("processrules"), &hKeyProcessrules);//HKEY_LOCAL_MACHINE  HKEY_CURRENT_USER
	if( status != ERROR_SUCCESS)
	{
		return status;
	}

	status = ::RegSetValueEx(hKeyGlobalrules, TEXT("MonitorEnable"), 0, REG_DWORD, (PBYTE)&value, cbSize);
	if( status != ERROR_SUCCESS )
	{
		return status;
	}
	status = ::RegSetValueEx(hKeyGlobalrules, TEXT("ProcessMonitorEnable"), 0, REG_DWORD, (PBYTE)&value, cbSize);
	if( status != ERROR_SUCCESS )
	{
		return status;
	}
	status = ::RegSetValueEx(hKeyGlobalrules, TEXT("IpMonitorEnable"), 0, REG_DWORD, (PBYTE)&value, cbSize);
	if( status != ERROR_SUCCESS )
	{
		return status;
	}
	status = ::RegSetValueEx(hKeyGlobalrules, TEXT("DnsMonitorEnable"), 0, REG_DWORD, (PBYTE)&value, cbSize);
	if( status != ERROR_SUCCESS )
	{
		return status;
	}

	value = 1;
	status = ::RegSetValueEx(hKeyDnsrules, TEXT("other_access"), 0, REG_DWORD, (PBYTE)&value, cbSize);
	if( status != ERROR_SUCCESS )
	{
		return status;
	}
	status = ::RegSetValueEx(hKeyIprules, TEXT("other_access"), 0, REG_DWORD, (PBYTE)&value, cbSize);
	if( status != ERROR_SUCCESS )
	{
		return status;
	}
	status = ::RegSetValueEx(hKeyProcessrules, TEXT("other_access"), 0, REG_DWORD, (PBYTE)&value, cbSize);
	if( status != ERROR_SUCCESS )
	{
		return status;
	}
	if (NULL != hKeyProcessrules)
		RegCloseKey(hKeyProcessrules);
	if (NULL != hKeyIprules)
		RegCloseKey(hKeyIprules);
	if (NULL != hKeyDnsrules)
		RegCloseKey(hKeyDnsrules);

	if (NULL != hKeyGlobalrules)
		RegCloseKey(hKeyGlobalrules);

	if (NULL != hkResult)
		RegCloseKey(hkResult);

	return status;
}

BOOL CLoadDrive::LoadFwDriver(char* lpszDriverPath/*, PHANDLE pHdevier*/)
{
	LSTATUS status = ERROR_SUCCESS;

	status = InitRege(HKEY_CURRENT_USER, FwRegePath);
	if( status != ERROR_SUCCESS)
	{
		::MessageBox(NULL, _T("����ǽ������ʼ��ʧ��~!"), _T("����:"), MB_OK);
		return FALSE;
	}
	TCHAR tcsError[1024] = {0};
	BOOL bFunc = LoadNTDriver("Wall_Device", lpszDriverPath, tcsError);

// 	if (bFunc)
// 	{
// 		m_hDevice = CreateFile( _T("\\\\.\\Wall_Device"),
// 			GENERIC_READ | GENERIC_WRITE,
// 			FILE_SHARE_READ | FILE_SHARE_WRITE,
// 			NULL,
// 			OPEN_EXISTING,
// 			FILE_ATTRIBUTE_NORMAL,
// 			NULL);
// 		if( m_hDevice == INVALID_HANDLE_VALUE)
// 		{
// 			if(UnLoadFwDriver())
// 			{
// 				bFunc = FALSE;
// 			}
// 
// 			
// 		}else{
// 			//д��ע���ȫ�ֿ���
// 			HKEY m_hKey;
// 			LSTATUS status = InitRege(HKEY_CURRENT_USER, _T("Software\\LBZ\\FwDriverLife"), &m_hKey);
// 			if( status != ERROR_SUCCESS)
// 			{
// 				if(UnLoadFwDriver())
// 				{
// 					bFunc = FALSE;
// 				}
// 				*pHdevier = m_hDevice;
// 			}
// 		}
// 
// 
// 	}


	return bFunc;
}

BOOL CLoadDrive::UnLoadFwDriver(PHANDLE phDevice)
{

	if (NULL != *phDevice)
	{
		CloseHandle( *phDevice );
		*phDevice = NULL;
	}

	BOOL bFunc = UnLoadNTDriver("Wall_Device");

	return bFunc;
}



BOOL IsProcessRuleExist(HKEY hKey, TCHAR* pcProcessName)
{
#define MAX_KEY_LENGTH 255

	BOOL bRet = FALSE;

	LSTATUS status = ERROR_SUCCESS;

	if (NULL == hKey)
		return FALSE;

	HKEY /*hKey = NULL, */hKey1 = NULL;

	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name    
	DWORD    cbName;                   // size of name string     
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name     
	DWORD    cchClassName = MAX_PATH;  // size of class string     
	DWORD    cSubKeys = 0;               // number of subkeys     
	DWORD    cbMaxSubKey;              // longest subkey size     
	DWORD    cchMaxClass;              // longest class string     
	DWORD    cValues;              // number of values for key     
	DWORD    cchMaxValue;          // longest value name     
	DWORD    cbMaxValueData;       // longest value data     
	DWORD    cbSecurityDescriptor; // size of security descriptor     
	FILETIME ftLastWriteTime;      // last write time     

	DWORD i, retCode; 

// 	status = RegCreateKey(HKEY_CURRENT_USER, _T("Software\\LBZ\\FwDriverLife\\processrules"), &hKey);
// 
// 	if( status != ERROR_SUCCESS)
// 	{
// 		return bRet;
// 	}
	retCode = RegQueryInfoKey(  
		hKey,                    // key handle     
		achClass,                // buffer for class name     
		&cchClassName,           // size of class string     
		NULL,                    // reserved     
		&cSubKeys,               // number of subkeys     
		&cbMaxSubKey,            // longest subkey size     
		&cchMaxClass,            // longest class string     
		&cValues,                // number of values for this key     
		&cchMaxValue,            // longest value name     
		&cbMaxValueData,         // longest value data     
		&cbSecurityDescriptor,   // security descriptor     
		&ftLastWriteTime);       // last write time    

	for (i = 0; i<cSubKeys; i++)  
	{  
		cbName = MAX_KEY_LENGTH;  
		retCode = RegEnumKeyEx(hKey, i,  
			achKey,  
			&cbName,  
			NULL,  
			NULL,  
			NULL,  
			&ftLastWriteTime);  
		if (retCode == ERROR_SUCCESS && NULL != cbName)  
		{  
			status = RegCreateKey(hKey, achKey, &hKey1);

			if(status == ERROR_SUCCESS)
			{
				TCHAR szBuffer[1024] = { 0 };  
				DWORD dwNameLen = 1024;
				TCHAR* tcsValue = _T("name");
				DWORD dwType = REG_SZ;
				if (ERROR_SUCCESS == RegQueryValueEx(hKey1, tcsValue, 0, &dwType, (LPBYTE)szBuffer, &dwNameLen))
				{
					if (_tcsicmp(pcProcessName, szBuffer) == 0)
						bRet = TRUE;
				}

				RegCloseKey(hKey1); 
			}

		}  
	}

	//RegCloseKey(hKey);

	return bRet;
}

BOOL CLoadDrive::FwAddProcessRule(HANDLE  hDevice,TCHAR* pcProcessName)
{

	USES_CONVERSION;
// 	if (NULL == m_hDevice)
// 		return FALSE;

	BOOL bFunc = FALSE;
	LSTATUS status = ERROR_SUCCESS;
	HKEY hKey = NULL;
	WCHAR* buffer = NULL;
	TCHAR tcsKeyName[128] = {0};
	DWORD crcProcessPath = 0;

	status = RegCreateKey(HKEY_CURRENT_USER, _T("Software\\LBZ\\FwDriverLife\\processrules"), &hKey);

	if( status != ERROR_SUCCESS)
	{
		return FALSE;
	}

	if (IsProcessRuleExist(hKey, pcProcessName))
	{
		//�����˾Ͳ����κ���,�����������
		bFunc = TRUE;
	}else
	{
		//�����ڵĻ�,��Ҫ������ͼ�ֵ

		//��ȡcrc32ֵ������
		size_t len = _tcslen( pcProcessName );
		if (NULL >= len)
			return FALSE;

#ifdef UNICODE
		buffer = pcProcessName;
		len = len * sizeof( WCHAR );
#else
		buffer = A2W(pcProcessName);
		len = len * sizeof( WCHAR );
#endif

		//ת��ΪСд
		for(int i = 0; i < len / sizeof( WCHAR ); i++)
		{
			if( buffer[i] >= L'A' && buffer[i] <= L'Z' )
				buffer[i] = buffer[i] - L'A' + L'a';
		}
		crcProcessPath = crc32_encode((char*)buffer,len);
		_stprintf_s(tcsKeyName, 128, _T("%x"), crcProcessPath );


		HKEY hKey1 = NULL;
		if (ERROR_SUCCESS == RegCreateKey(hKey, tcsKeyName, &hKey1))
		{
			if(ERROR_SUCCESS == ::RegSetValueEx(hKey1, TEXT("name"), 0, REG_SZ, (PBYTE)pcProcessName, _tcslen(pcProcessName)* sizeof(TCHAR)))
				bFunc = TRUE;
			else
				bFunc = FALSE;
			DWORD dwVule = 0;
			if(ERROR_SUCCESS == ::RegSetValueEx(hKey1, TEXT("rule"), 0, REG_DWORD, (PBYTE)&dwVule, sizeof(DWORD)))
				bFunc = TRUE;
			else
				bFunc = FALSE;

			RegCloseKey(hKey1);
		}

	}

	RegCloseKey(hKey);


	DWORD retLength = 0;
	BOOL bOk = DeviceIoControl(hDevice/*m_hDevice*/, AddOneProcessRule, (LPVOID)&crcProcessPath, sizeof(DWORD), NULL, 0, &retLength, NULL);


	return (bOk && bFunc);
}

BOOL CLoadDrive::FwRemoveProcessRule(HANDLE hDevice, TCHAR* pcProcessName)
{
	USES_CONVERSION;
// 	if (NULL == m_hDevice)
// 		return FALSE;

	BOOL bFunc = FALSE;
	LSTATUS status = ERROR_SUCCESS;
	HKEY hKey = NULL;
	WCHAR* buffer = NULL;
	TCHAR tcsKeyName[128] = {0};
	DWORD crcProcessPath = 0;

	status = RegCreateKey(HKEY_CURRENT_USER, _T("Software\\LBZ\\FwDriverLife\\processrules"), &hKey);

	if( status != ERROR_SUCCESS)
	{
		return FALSE;
	}

	size_t len = _tcslen( pcProcessName );
	if (NULL >= len)
		return FALSE;

#ifdef UNICODE
	buffer = pcProcessName;
	len = len * sizeof( WCHAR );
#else
	buffer = A2W(pcProcessName);
	len = len * sizeof( WCHAR );
#endif

	//ת��ΪСд
	for(int i = 0; i < len / sizeof( WCHAR ); i++)
	{
		if( buffer[i] >= L'A' && buffer[i] <= L'Z' )
			buffer[i] = buffer[i] - L'A' + L'a';
	}
	crcProcessPath = crc32_encode((char*)buffer,len);
	_stprintf_s(tcsKeyName, 128, _T("%x"), crcProcessPath );

	status = RegDeleteKey(hKey, tcsKeyName);
	if( status == ERROR_SUCCESS )
		bFunc = TRUE;

	RegCloseKey(hKey);
	

	DWORD retLength = 0;
	BOOL bOk = DeviceIoControl(hDevice, RemoveProcessRule, (LPVOID)&crcProcessPath, sizeof(DWORD), NULL, 0, &retLength, NULL);


	return (bOk && bFunc);
}

BOOL IsDnsRuleExist(HKEY hKey, TCHAR* pcProcessName)
{
#define MAX_KEY_LENGTH 255

	BOOL bRet = FALSE;

	LSTATUS status = ERROR_SUCCESS;

	if (NULL == hKey)
		return FALSE;

	HKEY /*hKey = NULL, */hKey1 = NULL;

	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name    
	DWORD    cbName;                   // size of name string     
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name     
	DWORD    cchClassName = MAX_PATH;  // size of class string     
	DWORD    cSubKeys = 0;               // number of subkeys     
	DWORD    cbMaxSubKey;              // longest subkey size     
	DWORD    cchMaxClass;              // longest class string     
	DWORD    cValues;              // number of values for key     
	DWORD    cchMaxValue;          // longest value name     
	DWORD    cbMaxValueData;       // longest value data     
	DWORD    cbSecurityDescriptor; // size of security descriptor     
	FILETIME ftLastWriteTime;      // last write time     

	DWORD i, retCode; 

	// 	status = RegCreateKey(HKEY_CURRENT_USER, _T("Software\\LBZ\\FwDriverLife\\processrules"), &hKey);
	// 
	// 	if( status != ERROR_SUCCESS)
	// 	{
	// 		return bRet;
	// 	}
	retCode = RegQueryInfoKey(  
		hKey,                    // key handle     
		achClass,                // buffer for class name     
		&cchClassName,           // size of class string     
		NULL,                    // reserved     
		&cSubKeys,               // number of subkeys     
		&cbMaxSubKey,            // longest subkey size     
		&cchMaxClass,            // longest class string     
		&cValues,                // number of values for this key     
		&cchMaxValue,            // longest value name     
		&cbMaxValueData,         // longest value data     
		&cbSecurityDescriptor,   // security descriptor     
		&ftLastWriteTime);       // last write time    

	for (i = 0; i<cSubKeys; i++)  
	{  
		cbName = MAX_KEY_LENGTH;  
		retCode = RegEnumKeyEx(hKey, i,  
			achKey,  
			&cbName,  
			NULL,  
			NULL,  
			NULL,  
			&ftLastWriteTime);  
		if (retCode == ERROR_SUCCESS && NULL != cbName)  
		{  
			status = RegCreateKey(hKey, achKey, &hKey1);

			if(status == ERROR_SUCCESS)
			{
				TCHAR szBuffer[1024] = { 0 };  
				DWORD dwNameLen = 1024;
				TCHAR* tcsValue = _T("name");
				DWORD dwType = REG_SZ;
				if (ERROR_SUCCESS == RegQueryValueEx(hKey1, tcsValue, 0, &dwType, (LPBYTE)szBuffer, &dwNameLen))
				{
					if (_tcsicmp(pcProcessName, szBuffer) == 0)
						bRet = TRUE;
				}

				RegCloseKey(hKey1); 
			}

		}  
	}

	//RegCloseKey(hKey);

	return bRet;
}

BOOL CLoadDrive::FwAddDnsRule(HANDLE hDevice, TCHAR* pthDnsName)
{
	USES_CONVERSION;
	if (NULL == hDevice)
		return FALSE;

	BOOL bFunc = FALSE;
	LSTATUS status = ERROR_SUCCESS;
	HKEY hKey = NULL;
	WCHAR* buffer = NULL;
	TCHAR tcsKeyName[128] = {0};

	status = RegCreateKey(HKEY_CURRENT_USER, _T("Software\\LBZ\\FwDriverLife\\dnsrules"), &hKey);

	if( status != ERROR_SUCCESS)
	{
		return FALSE;
	}

	if (IsDnsRuleExist(hKey, pthDnsName))
	{
		//�����˾Ͳ����κ���,�����������
		bFunc = TRUE;
	}else
	{
		//�����ڵĻ�,��Ҫ������ͼ�ֵ

		//��ȡcrc32ֵ������
		size_t len = _tcslen( pthDnsName );

		if (NULL >= len)
			return FALSE;

#ifdef UNICODE
		buffer = pthDnsName;
		len = len * sizeof( WCHAR );
#else
		buffer = A2W(pthDnsName);
		len = len * sizeof( WCHAR );
#endif

// 		//ת��ΪСд
// 		for(int i = 0; i < len / sizeof( WCHAR ); i++)
// 		{
// 			if( buffer[i] >= L'A' && buffer[i] <= L'Z' )
// 				buffer[i] = buffer[i] - L'A' + L'a';
// 		}
		DWORD crcProcessPath = crc32_encode((char*)buffer,len);
		_stprintf_s(tcsKeyName, 128, _T("%x"), crcProcessPath );


		HKEY hKey1 = NULL;
		if (ERROR_SUCCESS == RegCreateKey(hKey, tcsKeyName, &hKey1))
		{
			if(ERROR_SUCCESS == ::RegSetValueEx(hKey1, TEXT("name"), 0, REG_SZ, (PBYTE)pthDnsName, _tcslen(pthDnsName)* sizeof(TCHAR)))
				bFunc = TRUE;
			else
				bFunc = FALSE;
			DWORD dwVule = 0;
			if(ERROR_SUCCESS == ::RegSetValueEx(hKey1, TEXT("rule"), 0, REG_DWORD, (PBYTE)&dwVule, sizeof(DWORD)))
				bFunc = TRUE;
			else
				bFunc = FALSE;

			RegCloseKey(hKey1);
		}

	}

	RegCloseKey(hKey);


	DWORD retLength = 0;
	BOOL bOk = DeviceIoControl(hDevice,UpdateDnsRuleCfg,NULL,0,NULL,0,&retLength,NULL);


	return (bOk && bFunc);
}

BOOL CLoadDrive::FwRemoveDnsRule(HANDLE hDevice, TCHAR* pthDnsName)
{
	USES_CONVERSION;
	if (NULL == hDevice)
		return FALSE;

	BOOL bFunc = FALSE;
	LSTATUS status = ERROR_SUCCESS;
	HKEY hKey = NULL;
	WCHAR* buffer = NULL;
	TCHAR tcsKeyName[128] = {0};

	status = RegCreateKey(HKEY_CURRENT_USER, _T("Software\\LBZ\\FwDriverLife\\dnsrules"), &hKey);

	if( status != ERROR_SUCCESS)
	{
		return FALSE;
	}

	size_t len = _tcslen( pthDnsName );

	if (NULL >= len)
		return FALSE;

#ifdef UNICODE
	buffer = pthDnsName;
	len = len * sizeof( WCHAR );
#else
	buffer = A2W(pthDnsName);
	len = len * sizeof( WCHAR );
#endif

// 	//ת��ΪСд
// 	for(int i = 0; i < len / sizeof( WCHAR ); i++)
// 	{
// 		if( buffer[i] >= L'A' && buffer[i] <= L'Z' )
// 			buffer[i] = buffer[i] - L'A' + L'a';
// 	}
	DWORD crcProcessPath = crc32_encode((char*)buffer,len);
	_stprintf_s(tcsKeyName, 128, _T("%x"), crcProcessPath );

	status = RegDeleteKey(hKey, tcsKeyName);
	if( status == ERROR_SUCCESS )
		bFunc = TRUE;

	RegCloseKey(hKey);


	DWORD retLength = 0;
	BOOL bOk = DeviceIoControl(hDevice, UpdateDnsRuleCfg, NULL, 0, NULL, 0, &retLength, NULL);


	return (bOk && bFunc);
}

BOOL CLoadDrive::FwAddRedirectRule(HANDLE hDevice, TCHAR* pthHost, TCHAR* pthLink)
{
	USES_CONVERSION;
	if (NULL == hDevice)
		return FALSE;

	DWORD      value = 0,retLength = 0;
	string strSenduf("Host: ");
	char str_[1024] = {0};

#ifdef _UNICODE
	strSenduf += W2A(pthHost);
	strSenduf += "@xxoo@http://";
	strSenduf += W2A(pthLink);
#else
	strSenduf += pthHost;
	strSenduf += "@xxoo@http://";
	strSenduf += pthLink;
#endif

	memset(str_, 0, 1024);
	strncpy_s(str_, strSenduf.c_str(), 1024-1);

	return DeviceIoControl(hDevice, RemoveRedirection, str_, sizeof(str_), NULL, 0, &retLength, NULL);

}

BOOL CLoadDrive::FwRemoveRedirectRule(HANDLE  hDevice, TCHAR* pthHost)
{
	USES_CONVERSION;
	TCHAR tcsErr[1024] = {0};

// 	if (NULL == m_hDevice)
// 		return FALSE;

	DWORD      value = 0,retLength = 0;
	string strSenduf("Host: ");
	char str_[1024] = {0};
	TCHAR pthLink[] = _T("www.baidu.com");

#ifdef _UNICODE
	strSenduf += W2A(pthHost);
	strSenduf += "@xxoo@http://";
	strSenduf += W2A(pthLink);
#else
	strSenduf += pthHost;
	strSenduf += "@xxoo@http://";
	strSenduf += pthLink;
#endif

	memset(str_,'\0', 1024);
	strncpy_s(str_, strSenduf.c_str(), 1024-1);

	BOOL bFunc = DeviceIoControl(/*m_hDevice*/hDevice, RemoveRedirection, str_, sizeof(str_), NULL, 0, &retLength, NULL);
	if (!bFunc)
	{
		wsprintf(tcsErr, _T("������:0x%08x\r\n"), GetLastError());

		//::MessageBox(NULL, tcsErr, _T("����"), MB_OK);
	}

	return bFunc;
}

void SeparatorStr(tstring tstrPara, vector<ULONG>* pveOut, tstring tstrSeparat)
{
	tstring strRight = tstrPara, strTmp;
	int pos = -1;
	ULONG ulPidTmp = 0;

	while (!strRight.empty())
	{
		if (strRight.find(tstrSeparat, 0) != strRight.npos)
		{
			pos = strRight.find(tstrSeparat, 0);
			strTmp = strRight.substr(0, pos);
			_stscanf(strTmp.c_str(), _T("%u"), &ulPidTmp);
			pveOut->push_back(ulPidTmp);
			strRight = strRight.substr(pos + 1, strRight.size());
		} 
		else
		{
			_stscanf(strRight.c_str(), _T("%u"), &ulPidTmp);
			pveOut->push_back(ulPidTmp);
			strRight.clear();
		}

	}
}

void SeparatorStr(tstring tstrPara, vector<tstring>* pveOut, tstring tstrSeparat)
{
	tstring strRight = tstrPara, strTmp;
	int pos = -1;
	ULONG ulPidTmp = 0;

	while (!strRight.empty())
	{
		if (strRight.find(tstrSeparat, 0) != strRight.npos)
		{
			pos = strRight.find(tstrSeparat, 0);
			strTmp = strRight.substr(0, pos);
			//_stscanf(strTmp.c_str(), _T("%u"), &ulPidTmp);

			pveOut->push_back(strTmp);
			strRight = strRight.substr(pos + 1, strRight.size());
		} 
		else
		{
			//_stscanf(strRight.c_str(), _T("%u"), &ulPidTmp);
			pveOut->push_back(strRight);
			strRight.clear();
		}

	}
}

BOOL CLoadDrive::FwAddPointIpRule(HANDLE hDevice, TCHAR* tcsIp)
{
 	//USES_CONVERSION;
 	if (NULL == hDevice)
 		return FALSE;

	vector<ULONG> vIpTmp;

	SeparatorStr(tcsIp, &vIpTmp, _T("."));

	if (vIpTmp.size() != 4)
		return FALSE;

	ULONG ulIp = (vIpTmp[3] << 24) | (vIpTmp[2] << 16) | (vIpTmp[1] << 8) | ( vIpTmp[0]);

// 	unsigned char uc1 = (unsigned char)(ulIp>>24)&0xFF;
// 	unsigned char uc2 = (unsigned char)(ulIp>>16)&0xFF;
// 	unsigned char uc3 = (unsigned char)(ulIp>>8)&0xFF;
// 	unsigned char uc4 = (unsigned char)(ulIp)&0xFF;

	ULONG ulTest = (((ulIp)&0xFF)<<24) | (((ulIp>>8)&0xFF)<<16) | (((ulIp>>16)&0xFF)<<8) | (((ulIp>>24)&0xFF));

	DWORD dwRet = 0;

	LARGE_INTEGER liIp = {0};

	liIp.LowPart = ulTest/*ulIp*/;

	liIp.HighPart = ulTest/*ulIp*/;

	return DeviceIoControl(hDevice, AddPointIpRule, &liIp, sizeof(LARGE_INTEGER), NULL, 0, &dwRet, NULL);
}

BOOL CLoadDrive::FwRemovePointIpRule(HANDLE hDevice, TCHAR* tcsIp)
{
	USES_CONVERSION;
	if (NULL == hDevice)
		return FALSE;

	vector<ULONG> vIpTmp;

	SeparatorStr(tcsIp, &vIpTmp, _T("."));

	//ת��asiic
	char szIp[32] = {0};
#ifdef _UNICODE
	//szIp=W2A(tcsIp);
	strcpy_s(szIp, sizeof(szIp), W2A(tcsIp));
#else
	strcpy_s(szIp, sizeof(szIp), tcsIp);
#endif
	if (vIpTmp.size() != 4)
		return FALSE;

	ULONG ulIp = (vIpTmp[3] << 24) | (vIpTmp[2] << 16) | (vIpTmp[1] << 8) | ( vIpTmp[0]);

	ULONG ulTest = (((ulIp)&0xFF)<<24) | (((ulIp>>8)&0xFF)<<16) | (((ulIp>>16)&0xFF)<<8) | (((ulIp>>24)&0xFF));

	DWORD dwRet = 0;

	LARGE_INTEGER liIp = {0};

	liIp.LowPart = ulTest;

	liIp.HighPart = ulTest;

	return DeviceIoControl(hDevice, RemovePointIpRule, &liIp, sizeof(LARGE_INTEGER), NULL, 0, &dwRet, NULL);
}

BOOL CLoadDrive::FwAddRangeIpRule(HANDLE hDevice, LARGE_INTEGER liIp)
{
	if (NULL == hDevice)
		return FALSE;
	DWORD dwRet = 0;
	return DeviceIoControl(hDevice, AddPointIpRule, &liIp, sizeof(LARGE_INTEGER), NULL, 0, &dwRet, NULL);
}

BOOL CLoadDrive::FwAddRangeIpRule(HANDLE hDevice, TCHAR* tcsRangeIp)
{
 	if (NULL == hDevice)
 		return FALSE;

	vector<tstring> veOut;
	SeparatorStr(tcsRangeIp, &veOut, _T("~"));

	if (veOut.size() != 2)
		return FALSE;

	vector<ULONG> vIpTmp;
	SeparatorStr(veOut[0], &vIpTmp, _T("."));
	if (vIpTmp.size() != 4)
		return FALSE;
	ULONG ulIp0 = (vIpTmp[3] << 24) | (vIpTmp[2] << 16) | (vIpTmp[1] << 8) | ( vIpTmp[0]);
	ULONG ulTest0 = (((ulIp0)&0xFF)<<24) | (((ulIp0>>8)&0xFF)<<16) | (((ulIp0>>16)&0xFF)<<8) | (((ulIp0>>24)&0xFF));


	vector<ULONG> vIpTmp1;
	SeparatorStr(veOut[1], &vIpTmp1, _T("."));
	if (vIpTmp1.size() != 4)
		return FALSE;
	ULONG ulIp1 = (vIpTmp1[3] << 24) | (vIpTmp1[2] << 16) | (vIpTmp1[1] << 8) | ( vIpTmp1[0]);
	ULONG ulTest1 = (((ulIp1)&0xFF)<<24) | (((ulIp1>>8)&0xFF)<<16) | (((ulIp1>>16)&0xFF)<<8) | (((ulIp1>>24)&0xFF));

	LARGE_INTEGER liIp = {0};
	DWORD dwRet = 0;
	liIp.LowPart = ulTest0;
	liIp.HighPart = ulTest1;

	return DeviceIoControl(hDevice, AddPointIpRule, &liIp, sizeof(LARGE_INTEGER), NULL, 0, &dwRet, NULL);
}

BOOL CLoadDrive::FwRemoveRangeIpRule(HANDLE hDevice, LARGE_INTEGER liIp)
{
	if (NULL == hDevice)
		return FALSE;
	DWORD dwRet = 0;
	return DeviceIoControl(hDevice, RemovePointIpRule, &liIp, sizeof(LARGE_INTEGER), NULL, 0, &dwRet, NULL);
}

BOOL CLoadDrive::FwRemoveRangeIpRule(HANDLE hDevice, TCHAR* tcsRangeIp)
{
	if (NULL == hDevice)
		return FALSE;

	vector<tstring> veOut;
	SeparatorStr(tcsRangeIp, &veOut, _T("~"));

	if (veOut.size() != 2)
		return FALSE;

	vector<ULONG> vIpTmp;
	SeparatorStr(veOut[0], &vIpTmp, _T("."));
	if (vIpTmp.size() != 4)
		return FALSE;
	ULONG ulIp0 = (vIpTmp[3] << 24) | (vIpTmp[2] << 16) | (vIpTmp[1] << 8) | ( vIpTmp[0]);
	ULONG ulTest0 = (((ulIp0)&0xFF)<<24) | (((ulIp0>>8)&0xFF)<<16) | (((ulIp0>>16)&0xFF)<<8) | (((ulIp0>>24)&0xFF));

	vector<ULONG> vIpTmp1;
	SeparatorStr(veOut[1], &vIpTmp1, _T("."));
	if (vIpTmp1.size() != 4)
		return FALSE;
	ULONG ulIp1 = (vIpTmp1[3] << 24) | (vIpTmp1[2] << 16) | (vIpTmp1[1] << 8) | ( vIpTmp1[0]);
	ULONG ulTest1 = (((ulIp1)&0xFF)<<24) | (((ulIp1>>8)&0xFF)<<16) | (((ulIp1>>16)&0xFF)<<8) | (((ulIp1>>24)&0xFF));

	LARGE_INTEGER liIp = {0};
	DWORD dwRet = 0;
	liIp.LowPart = ulTest0;
	liIp.HighPart = ulTest1;

	return DeviceIoControl(hDevice, RemovePointIpRule, &liIp, sizeof(LARGE_INTEGER), NULL, 0, &dwRet, NULL);
}

BOOL CLoadDrive::FwAddLimitUpSpeed(HANDLE hDevice, DWORD Speed)
{
	if (NULL == hDevice)
		return FALSE;
	DWORD dwRet = 0;
	return DeviceIoControl(hDevice, LimitUpSpeed, &Speed, sizeof(DWORD), NULL, 0, &dwRet, NULL);
}

BOOL CLoadDrive::FwAddLimitDownSpeed(HANDLE hDevice, DWORD Speed)
{
	if (NULL == hDevice)
		return FALSE;
	DWORD dwRet = 0;
	return DeviceIoControl(hDevice, LimitDownSpeed, &Speed, sizeof(DWORD), NULL, 0, &dwRet, NULL);
}



