// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 LOADDRIVE_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何其他项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// LOADDRIVE_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
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
	DWORD dwUpTpye;      //总上传流量
	DWORD dwDownTpye;    //总下载流量
	DWORD dwLimitUp;     //限制上传流量(对外网有效)
	DWORD dwLimitDown;   //限制下载流量(对外网有效)
	DWORD dwUpTpyeLAN;   //局域网上传流量
	DWORD dwDownTpyeLAN; //局域网下载流量
	DWORD dwUpTpyeWAN;   //外网上传流量
	DWORD dwDownTpyeWAN; //外网下载流量
}FlowInfo, *PFlowInfo;

#define FwRegePath _T("Software\\LBZ\\FwDriverLife") //防火墙规则路径

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

// 此类是从 LoadDrive.dll 导出的
class LOADDRIVE_API CLoadDrive {
public:
	CLoadDrive(void);
	~CLoadDrive();
	// TODO: 在此添加您的方法。
	BOOL Is64Bit_OS();
	/*********************************************************************************************/
	/*
	函数功能: 加载并启动保护驱动
	函数参数: [lpszDriverPath]:in	驱动文件路径

	函数返回: 成功返回TRUE, 否则返回FALSE
	备注: 
	*/
	/*********************************************************************************************/
	BOOL LoadProctectDriver(char* lpszDriverPath);
	/*********************************************************************************************/
	/*
	函数功能: 卸载保护驱动
	函数参数: 无

	函数返回: 成功返回TRUE, 否则返回FALSE
	备注: 
	*/
	/*********************************************************************************************/
	BOOL UnLoadProtectDriver();

	/*********************************************************************************************/
	/*
	函数功能:加载并启动驱动
	函数参数: [lpszDriverName]:in	驱动服务名
			  [lpszDriverPath]:in	驱动文件路径
			  [tcsErr]:out 错误信息,方便出错时查询

	函数返回: 成功返回TRUE, 否则返回FALSE
	备注: 
	*/
	/*********************************************************************************************/
	BOOL LoadNTDriver(char* lpszDriverName,char* lpszDriverPath, TCHAR* tcsErr);

	BOOL SendKernelData(char* LinkName, PVOID pInBuffer,int sizeIn, int inMSGCode, LPVOID lpOut, DWORD dwOutSize, TCHAR* tcsErr);
	/*********************************************************************************************/
	/*
	函数功能: 增加对指定的Pid进程进行保护,禁止任务管理器关闭
	函数参数: [ulPid]:in	要保护的进程pid

	函数返回: 成功返回TRUE, 否则返回FALSE
	备注: 
	*/
	/*********************************************************************************************/
	BOOL AddProtectPid(ULONG ulPid);
	/*********************************************************************************************/
	/*
	函数功能: 移除对指定的Pid进程进行保护
	函数参数: [ulPid]:in	要移除保护的进程pid

	函数返回: 成功返回TRUE, 否则返回FALSE
	备注: 
	*/
	/*********************************************************************************************/
	BOOL RemoveProtectPid(ULONG ulPid);
	/*********************************************************************************************/
	/*
	函数功能: 增加对进程名CRC32值的进程禁止其启动
	函数参数: [uinCrc32]:in	要禁止启动的进程名CRC32值

	函数返回: 成功返回TRUE, 否则返回FALSE
	备注:     要crc32的进程名不是全路径,而是文件名,如:QQ.exe(区分大小写),WiseUC.exe等
	*/
	/*********************************************************************************************/
	BOOL AddStopProc(UINT32 uinCrc32);

	//BOOL AddStopProc(TCHAR* tcsProcessName);

	BOOL AddStopProc(char* szProcessName);
	/*********************************************************************************************/
	/*
	函数功能: 移除已经禁止其启动的进程名crc32标志的进程
	函数参数: [uinCrc32]:in	进程名CRC32值

	函数返回: 成功返回TRUE, 否则返回FALSE
	备注:     要crc32的进程名不是全路径,而是文件名,如:QQ.exe(区分大小写),WiseUC.exe等
	*/
	/*********************************************************************************************/
	BOOL RemoveStopProc(UINT32 uinCrc32);

	BOOL RemoveStopProc(TCHAR* tcsProcessName);

	BOOL SendFwData(char* LinkName, PVOID pInBuffer,int sizeIn, int inMSGCode, LPVOID lpOut, DWORD dwOutSize, TCHAR* tcsErr);

	/*********************************************************************************************/
	/*
	函数功能: 根据服务名卸载其驱动
	函数参数: [szSvrName]:in	要卸载的驱动服务名

	函数返回: 成功返回TRUE, 否则返回FALSE
	备注:     要crc32的进程名不是全路径,而是文件名,如:QQ.exe(区分大小写),WiseUC.exe等
	*/
	/*********************************************************************************************/
	BOOL UnLoadNTDriver(char * szSvrName);

	/*-------------------------------------------------------------------------------------------*/
	/*********************************************************************************************/
	/**********                                                                      *************/
	/**********                          防火墙驱动相关                              *************/
	/**********                                                                      *************/
	/*********************************************************************************************/
	/*-------------------------------------------------------------------------------------------*/
	/*
	函数功能: 加载并防火墙驱动
	函数参数: [lpszDriverPath]:in	防火墙驱动文件路径

	函数返回: 成功返回TRUE, 否则返回FALSE
	备注: 
	*/
	/*********************************************************************************************/
	BOOL LoadFwDriver(char* lpszDriverPath);
	/*********************************************************************************************/
	/*
	函数功能: 卸载防火墙驱动
	函数参数: phDevice: 要被卸载的防火墙设备句柄

	函数返回: 成功返回TRUE, 否则返回FALSE
	备注: 
	*/
	/*********************************************************************************************/
	BOOL UnLoadFwDriver(PHANDLE phDevice);
	/*********************************************************************************************/
	/*
	函数功能: 增加一项防火墙进程规则
	函数参数: hDevice:防火墙设备句柄
			  pcProcessName:要被禁止联网的进程名(不是全路径),比如:QQ.exe
	函数返回: 成功返回TRUE, 否则返回FALSE
	备注: 
	*/
	/*********************************************************************************************/
	BOOL FwAddProcessRule(HANDLE hDevice, TCHAR* pcProcessName);
	/*********************************************************************************************/
	/*
	函数功能: 移除一项防火墙进程规则
	函数参数: hDevice:防火墙设备句柄
			  pcProcessName:要被移除禁止联网的进程名规则(不是全路径),比如:QQ.exe
	函数返回: 成功返回TRUE, 否则返回FALSE
	备注: 
	*/
	/*********************************************************************************************/
	BOOL FwRemoveProcessRule(HANDLE hDevice, TCHAR* pcProcessName);
	/*********************************************************************************************/
	/*
	函数功能: 增加一项防火墙IP规则
	函数参数: hDevice:防火墙设备句柄
			  tcsIp:要被禁止联网的IP,比如:"192.168.100.206"
	函数返回: 成功返回TRUE, 否则返回FALSE
	备注: 
	*/
	/*********************************************************************************************/
	BOOL FwAddPointIpRule(HANDLE hDevice, TCHAR* tcsIp);
	/*********************************************************************************************/
	/*
	函数功能: 移除一项防火墙IP规则
	函数参数: hDevice:防火墙设备句柄
			  tcsIp:要被移除禁止联网的IP,比如:"192.168.100.206"
	函数返回: 成功返回TRUE, 否则返回FALSE
	备注: 
	*/
	/*********************************************************************************************/
	BOOL FwRemovePointIpRule(HANDLE hDevice, TCHAR* tcsIp);

	/*********************************************************************************************/
	/*
	函数功能: 增加一项防火墙IP范围规则
	函数参数: hDevice:防火墙设备句柄
			  tcsRangeIp:要被禁止联网的IP范围,比如:"192.168.100.205~192.168.100.207"
	函数返回: 成功返回TRUE, 否则返回FALSE
	备注:     自己拼接字符串,注意中间有个"~"符号间隔
	*/
	/*********************************************************************************************/
	BOOL FwAddRangeIpRule(HANDLE hDevice, TCHAR* tcsRangeIp);

	/*********************************************************************************************/
	/*
	函数功能: 移除一项防火墙IP范围规则
	函数参数: hDevice:防火墙设备句柄
			  tcsRangeIp:要被移除禁止联网的IP范围,比如:"192.168.100.205~192.168.100.207"
	函数返回: 成功返回TRUE, 否则返回FALSE
	备注:     自己拼接字符串,注意中间有个"~"符号间隔
	*/
	/*********************************************************************************************/
	BOOL FwRemoveRangeIpRule(HANDLE hDevice, TCHAR* tcsRangeIp);

	BOOL FwAddRangeIpRule(HANDLE hDevice, LARGE_INTEGER liIp);

	BOOL FwRemoveRangeIpRule(HANDLE hDevice, LARGE_INTEGER liIp);
	/*********************************************************************************************/
	/*
	函数功能: 增加一项防火墙DNS域名规则
	函数参数: hDevice:防火墙设备句柄
			  pthDnsName:要被禁止联网的DNS域名,比如:"baidu.com"
	函数返回: 成功返回TRUE, 否则返回FALSE
	备注:     
	*/
	/*********************************************************************************************/
	BOOL FwAddDnsRule(HANDLE hDevice, TCHAR* pthDnsName);
	/*********************************************************************************************/
	/*
	函数功能: 移除一项防火墙DNS域名规则
	函数参数: hDevice:防火墙设备句柄
			  pthDnsName:要被移除禁止联网的DNS域名,比如:"baidu.com"
	函数返回: 成功返回TRUE, 否则返回FALSE
	备注:     
	*/
	/*********************************************************************************************/
	BOOL FwRemoveDnsRule(HANDLE hDevice, TCHAR* pthDnsName);
	/*********************************************************************************************/
	/*
	函数功能:增加一项防火墙重定向规则
	函数参数: hDevice:防火墙设备句柄
			  pthHost:要被重定向联网的host域名,比如:"baidu.com"
			  pthLink:要被重定向目标Url,比如:"www.160.com"
	函数返回: 成功返回TRUE, 否则返回FALSE
	备注:     
	*/
	/*********************************************************************************************/
	BOOL FwAddRedirectRule(HANDLE hDevice, TCHAR* pthHost, TCHAR* pthLink);
	/*********************************************************************************************/
	/*
	函数功能: 移除一项防火墙重定向规则
	函数参数: hDevice:防火墙设备句柄
			  pthHost:要被删除重定向联网的host域名,比如:"baidu.com"
	函数返回: 成功返回TRUE, 否则返回FALSE
	备注:     
	*/
	/*********************************************************************************************/
	BOOL FwRemoveRedirectRule(HANDLE hDevice, TCHAR* pthHost);

	BOOL FwAddLimitUpSpeed(HANDLE hDevice, DWORD Speed);

	BOOL FwAddLimitDownSpeed(HANDLE hDevice, DWORD Speed);
	/*
	注意:防火墙驱动设备句柄,必须在UI线程中获取(打开),否则通讯失败!!!
	本来想在这个导出类维护m_hDevice设备句柄的,但是通讯会失败,原因上面已经说了
	by:lbz 2016-8-2 16:32
	*/
// 	private:
// 		HANDLE  m_hDevice; 

};

// extern LOADDRIVE_API int nLoadDrive;
// 
// LOADDRIVE_API int fnLoadDrive(void);
