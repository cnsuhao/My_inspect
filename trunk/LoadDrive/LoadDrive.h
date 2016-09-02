// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� LOADDRIVE_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// LOADDRIVE_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
#ifdef LOADDRIVE_EXPORTS
#define LOADDRIVE_API __declspec(dllexport)
#else
#define LOADDRIVE_API __declspec(dllimport)
#endif


#include <tchar.h>
#include <stdio.h>
#include <winioctl.h>
#include <atlconv.h>
#include "crc32.h"

#include <string>
#include <vector>

using namespace std;

#ifdef UNICODE
#define tstring wstring
#define tifstream wifstream
#else
#define tstring string
#define tifstream ifstream
#endif


typedef struct _FlowInfo{
	DWORD dwUpTpye;      //���ϴ�����
	DWORD dwDownTpye;    //����������
	DWORD dwLimitUp;     //�����ϴ�����(��������Ч)
	DWORD dwLimitDown;   //������������(��������Ч)
	DWORD dwUpTpyeLAN;   //�������ϴ�����
	DWORD dwDownTpyeLAN; //��������������
	DWORD dwUpTpyeWAN;   //�����ϴ�����
	DWORD dwDownTpyeWAN; //������������
}FlowInfo, *PFlowInfo;

#define FwRegePath _T("Software\\LBZ\\FwDriverLife") //����ǽ����·��

//#define FlowDriver "FlowDriver"

typedef void (WINAPI *LPFN_PGNSI)(LPSYSTEM_INFO);

#define CODEMSG(_number) CTL_CODE(FILE_DEVICE_UNKNOWN,_number , METHOD_BUFFERED,\
	FILE_READ_DATA | FILE_WRITE_DATA)       

#define CODEMSG_NET(_number) CTL_CODE(FILE_DEVICE_NETWORK,_number , METHOD_NEITHER,\
	FILE_READ_DATA | FILE_WRITE_DATA)


#define INIT_NTOS_FUNCTION 0x800

#define  IOCTL_LOAD_PROCESS_CONFIG CTL_CODE( FILE_DEVICE_NETWORK,0x801,METHOD_NEITHER,FILE_ANY_ACCESS )

#define  IOCTL_MONITOR_ON CTL_CODE( FILE_DEVICE_NETWORK,0x802,METHOD_NEITHER,FILE_ANY_ACCESS )

#define  IOCTL_MONITOR_OFF CTL_CODE( FILE_DEVICE_NETWORK,0x803,METHOD_NEITHER,FILE_ANY_ACCESS )

#define  IOCTL_BLOCK_ALL CTL_CODE( FILE_DEVICE_NETWORK,0x804,METHOD_NEITHER,FILE_ANY_ACCESS )

#define  IOCTL_LOAD_IP_CONFIG CTL_CODE( FILE_DEVICE_NETWORK,0x805,METHOD_NEITHER,FILE_ANY_ACCESS )

#define  IOCTL_UNLOAD_PROCESS_CONFIG CTL_CODE( FILE_DEVICE_NETWORK,0x806,METHOD_NEITHER,FILE_ANY_ACCESS )

#define  IOCTL_UNLOAD_IP_CONFIG CTL_CODE( FILE_DEVICE_NETWORK,0x807,METHOD_NEITHER,FILE_ANY_ACCESS )

#define IOCTL_LOAD_DNS_CONFIG CTL_CODE( FILE_DEVICE_NETWORK,0x808,METHOD_NEITHER,FILE_ANY_ACCESS )

#define IOCTL_UNLOAD_DNS_CONFIG CTL_CODE( FILE_DEVICE_NETWORK,0x809,METHOD_NEITHER,FILE_ANY_ACCESS )

#define AddRedirection CTL_CODE( FILE_DEVICE_NETWORK,0x80a,METHOD_NEITHER,FILE_ANY_ACCESS )

#define RemoveRedirection CTL_CODE( FILE_DEVICE_NETWORK,0x80b,METHOD_NEITHER,FILE_ANY_ACCESS )

#define AddPointIpRule CTL_CODE( FILE_DEVICE_NETWORK,0x80c,METHOD_NEITHER,FILE_ANY_ACCESS )

#define RemovePointIpRule CTL_CODE( FILE_DEVICE_NETWORK,0x80d,METHOD_NEITHER,FILE_ANY_ACCESS )

#define AddOneProcessRule CTL_CODE( FILE_DEVICE_NETWORK,0x80e,METHOD_NEITHER,FILE_ANY_ACCESS )

#define RemoveProcessRule CTL_CODE( FILE_DEVICE_NETWORK,0x80f,METHOD_NEITHER,FILE_ANY_ACCESS )

#define UpdateDnsRuleCfg CTL_CODE( FILE_DEVICE_NETWORK,0x810,METHOD_NEITHER,FILE_ANY_ACCESS )

#define LimitUpSpeed CTL_CODE( FILE_DEVICE_NETWORK,0x811,METHOD_NEITHER,FILE_ANY_ACCESS )
	
#define LimitDownSpeed CTL_CODE( FILE_DEVICE_NETWORK,0x812,METHOD_NEITHER,FILE_ANY_ACCESS )	

#define MonitorFlowData CTL_CODE( FILE_DEVICE_NETWORK,0x813,METHOD_NEITHER,FILE_ANY_ACCESS )

// �����Ǵ� LoadDrive.dll ������
class LOADDRIVE_API CLoadDrive {
public:
	CLoadDrive(void);
	~CLoadDrive();
	// TODO: �ڴ�������ķ�����
	BOOL Is64Bit_OS();
	/*********************************************************************************************/
	/*
	��������: ���ز�������������
	��������: [lpszDriverPath]:in	�����ļ�·��

	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע: 
	*/
	/*********************************************************************************************/
	BOOL LoadProctectDriver(char* lpszDriverPath);
	/*********************************************************************************************/
	/*
	��������: ж�ر�������
	��������: ��

	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע: 
	*/
	/*********************************************************************************************/
	BOOL UnLoadProtectDriver();

	/*********************************************************************************************/
	/*
	��������:���ز���������
	��������: [lpszDriverName]:in	����������
			  [lpszDriverPath]:in	�����ļ�·��
			  [tcsErr]:out ������Ϣ,�������ʱ��ѯ

	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע: 
	*/
	/*********************************************************************************************/
	BOOL LoadNTDriver(char* lpszDriverName,char* lpszDriverPath, TCHAR* tcsErr);

	BOOL SendKernelData(char* LinkName, PVOID pInBuffer,int sizeIn, int inMSGCode, LPVOID lpOut, DWORD dwOutSize, TCHAR* tcsErr);
	/*********************************************************************************************/
	/*
	��������: ���Ӷ�ָ����Pid���̽��б���,��ֹ����������ر�
	��������: [ulPid]:in	Ҫ�����Ľ���pid

	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע: 
	*/
	/*********************************************************************************************/
	BOOL AddProtectPid(ULONG ulPid);
	/*********************************************************************************************/
	/*
	��������: �Ƴ���ָ����Pid���̽��б���
	��������: [ulPid]:in	Ҫ�Ƴ������Ľ���pid

	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע: 
	*/
	/*********************************************************************************************/
	BOOL RemoveProtectPid(ULONG ulPid);
	/*********************************************************************************************/
	/*
	��������: ���ӶԽ�����CRC32ֵ�Ľ��̽�ֹ������
	��������: [uinCrc32]:in	Ҫ��ֹ�����Ľ�����CRC32ֵ

	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע:     Ҫcrc32�Ľ���������ȫ·��,�����ļ���,��:QQ.exe(���ִ�Сд),WiseUC.exe��
	*/
	/*********************************************************************************************/
	BOOL AddStopProc(UINT32 uinCrc32);

	//BOOL AddStopProc(TCHAR* tcsProcessName);

	BOOL AddStopProc(char* szProcessName);
	/*********************************************************************************************/
	/*
	��������: �Ƴ��Ѿ���ֹ�������Ľ�����crc32��־�Ľ���
	��������: [uinCrc32]:in	������CRC32ֵ

	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע:     Ҫcrc32�Ľ���������ȫ·��,�����ļ���,��:QQ.exe(���ִ�Сд),WiseUC.exe��
	*/
	/*********************************************************************************************/
	BOOL RemoveStopProc(UINT32 uinCrc32);

	BOOL RemoveStopProc(TCHAR* tcsProcessName);

	BOOL SendFwData(char* LinkName, PVOID pInBuffer,int sizeIn, int inMSGCode, LPVOID lpOut, DWORD dwOutSize, TCHAR* tcsErr);

	/*********************************************************************************************/
	/*
	��������: ���ݷ�����ж��������
	��������: [szSvrName]:in	Ҫж�ص�����������

	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע:     Ҫcrc32�Ľ���������ȫ·��,�����ļ���,��:QQ.exe(���ִ�Сд),WiseUC.exe��
	*/
	/*********************************************************************************************/
	BOOL UnLoadNTDriver(char * szSvrName);

	/*-------------------------------------------------------------------------------------------*/
	/*********************************************************************************************/
	/**********                                                                      *************/
	/**********                          ����ǽ�������                              *************/
	/**********                                                                      *************/
	/*********************************************************************************************/
	/*-------------------------------------------------------------------------------------------*/
	/*
	��������: ���ز�����ǽ����
	��������: [lpszDriverPath]:in	����ǽ�����ļ�·��

	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע: 
	*/
	/*********************************************************************************************/
	BOOL LoadFwDriver(char* lpszDriverPath);
	/*********************************************************************************************/
	/*
	��������: ж�ط���ǽ����
	��������: phDevice: Ҫ��ж�صķ���ǽ�豸���

	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע: 
	*/
	/*********************************************************************************************/
	BOOL UnLoadFwDriver(PHANDLE phDevice);
	/*********************************************************************************************/
	/*
	��������: ����һ�����ǽ���̹���
	��������: hDevice:����ǽ�豸���
			  pcProcessName:Ҫ����ֹ�����Ľ�����(����ȫ·��),����:QQ.exe
	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע: 
	*/
	/*********************************************************************************************/
	BOOL FwAddProcessRule(HANDLE hDevice, TCHAR* pcProcessName);
	/*********************************************************************************************/
	/*
	��������: �Ƴ�һ�����ǽ���̹���
	��������: hDevice:����ǽ�豸���
			  pcProcessName:Ҫ���Ƴ���ֹ�����Ľ���������(����ȫ·��),����:QQ.exe
	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע: 
	*/
	/*********************************************************************************************/
	BOOL FwRemoveProcessRule(HANDLE hDevice, TCHAR* pcProcessName);
	/*********************************************************************************************/
	/*
	��������: ����һ�����ǽIP����
	��������: hDevice:����ǽ�豸���
			  tcsIp:Ҫ����ֹ������IP,����:"192.168.100.206"
	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע: 
	*/
	/*********************************************************************************************/
	BOOL FwAddPointIpRule(HANDLE hDevice, TCHAR* tcsIp);
	/*********************************************************************************************/
	/*
	��������: �Ƴ�һ�����ǽIP����
	��������: hDevice:����ǽ�豸���
			  tcsIp:Ҫ���Ƴ���ֹ������IP,����:"192.168.100.206"
	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע: 
	*/
	/*********************************************************************************************/
	BOOL FwRemovePointIpRule(HANDLE hDevice, TCHAR* tcsIp);

	/*********************************************************************************************/
	/*
	��������: ����һ�����ǽIP��Χ����
	��������: hDevice:����ǽ�豸���
			  tcsRangeIp:Ҫ����ֹ������IP��Χ,����:"192.168.100.205~192.168.100.207"
	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע:     �Լ�ƴ���ַ���,ע���м��и�"~"���ż��
	*/
	/*********************************************************************************************/
	BOOL FwAddRangeIpRule(HANDLE hDevice, TCHAR* tcsRangeIp);

	/*********************************************************************************************/
	/*
	��������: �Ƴ�һ�����ǽIP��Χ����
	��������: hDevice:����ǽ�豸���
			  tcsRangeIp:Ҫ���Ƴ���ֹ������IP��Χ,����:"192.168.100.205~192.168.100.207"
	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע:     �Լ�ƴ���ַ���,ע���м��и�"~"���ż��
	*/
	/*********************************************************************************************/
	BOOL FwRemoveRangeIpRule(HANDLE hDevice, TCHAR* tcsRangeIp);

	BOOL FwAddRangeIpRule(HANDLE hDevice, LARGE_INTEGER liIp);

	BOOL FwRemoveRangeIpRule(HANDLE hDevice, LARGE_INTEGER liIp);
	/*********************************************************************************************/
	/*
	��������: ����һ�����ǽDNS��������
	��������: hDevice:����ǽ�豸���
			  pthDnsName:Ҫ����ֹ������DNS����,����:"baidu.com"
	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע:     
	*/
	/*********************************************************************************************/
	BOOL FwAddDnsRule(HANDLE hDevice, TCHAR* pthDnsName);
	/*********************************************************************************************/
	/*
	��������: �Ƴ�һ�����ǽDNS��������
	��������: hDevice:����ǽ�豸���
			  pthDnsName:Ҫ���Ƴ���ֹ������DNS����,����:"baidu.com"
	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע:     
	*/
	/*********************************************************************************************/
	BOOL FwRemoveDnsRule(HANDLE hDevice, TCHAR* pthDnsName);
	/*********************************************************************************************/
	/*
	��������:����һ�����ǽ�ض������
	��������: hDevice:����ǽ�豸���
			  pthHost:Ҫ���ض���������host����,����:"baidu.com"
			  pthLink:Ҫ���ض���Ŀ��Url,����:"www.160.com"
	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע:     
	*/
	/*********************************************************************************************/
	BOOL FwAddRedirectRule(HANDLE hDevice, TCHAR* pthHost, TCHAR* pthLink);
	/*********************************************************************************************/
	/*
	��������: �Ƴ�һ�����ǽ�ض������
	��������: hDevice:����ǽ�豸���
			  pthHost:Ҫ��ɾ���ض���������host����,����:"baidu.com"
	��������: �ɹ�����TRUE, ���򷵻�FALSE
	��ע:     
	*/
	/*********************************************************************************************/
	BOOL FwRemoveRedirectRule(HANDLE hDevice, TCHAR* pthHost);

	BOOL FwAddLimitUpSpeed(HANDLE hDevice, DWORD Speed);

	BOOL FwAddLimitDownSpeed(HANDLE hDevice, DWORD Speed);
	/*
	ע��:����ǽ�����豸���,������UI�߳��л�ȡ(��),����ͨѶʧ��!!!
	�����������������ά��m_hDevice�豸�����,����ͨѶ��ʧ��,ԭ�������Ѿ�˵��
	by:lbz 2016-8-2 16:32
	*/
// 	private:
// 		HANDLE  m_hDevice; 

};

// extern LOADDRIVE_API int nLoadDrive;
// 
// LOADDRIVE_API int fnLoadDrive(void);
