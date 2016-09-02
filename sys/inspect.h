/*++

Copyright (c) Microsoft Corporation. All rights reserved

Abstract:

   This header files declares common data types and function prototypes used
   throughout the Transport Inspect sample.

Environment:

    Kernel mode

--*/

#ifndef _TL_INSPECT_H_
#define _TL_INSPECT_H_

typedef enum TL_INSPECT_PACKET_TYPE_
{
   TL_INSPECT_CONNECT_PACKET,
   TL_INSPECT_DATA_PACKET,
   TL_INSPECT_REAUTH_PACKET
} TL_INSPECT_PACKET_TYPE;

//
// TL_INSPECT_PENDED_PACKET is the object type we used to store all information
// needed for out-of-band packet modification and re-injection. This type
// also points back to the flow context the packet belongs to.

#pragma warning(push)
#pragma warning(disable: 4201) //NAMELESS_STRUCT_UNION

typedef struct TL_INSPECT_PENDED_PACKET_
{
   LIST_ENTRY listEntry;

   ADDRESS_FAMILY addressFamily;
   TL_INSPECT_PACKET_TYPE type;
   FWP_DIRECTION  direction;
   
   UINT32 authConnectDecision;
   HANDLE completionContext;

   //
   // Common fields for inbound and outbound traffic.
   //
   UINT8 protocol;
   NET_BUFFER_LIST* netBufferList;
   COMPARTMENT_ID compartmentId;
   union
   {
      FWP_BYTE_ARRAY16 localAddr;
      UINT32 ipv4LocalAddr;
   };
   union
   {
      UINT16 localPort;
      UINT16 icmpType;
   };
   union
   {
      UINT16 remotePort;
      UINT16 icmpCode;
   };

   //
   // Data fields for outbound packet re-injection.
   //
   UINT64 endpointHandle;
   union
   {
      FWP_BYTE_ARRAY16 remoteAddr;
      UINT32 ipv4RemoteAddr;
   };

   SCOPE_ID remoteScopeId;
   WSACMSGHDR* controlData;
   ULONG controlDataLength;

   //
   // Data fields for inbound packet re-injection.
   //
   BOOLEAN ipSecProtected;
   ULONG nblOffset;
   UINT32 ipHeaderSize;
   UINT32 transportHeaderSize;
   IF_INDEX interfaceIndex;
   IF_INDEX subInterfaceIndex;

   BOOLEAN bLAN;

} TL_INSPECT_PENDED_PACKET;

#pragma warning(pop)

//
// Pooltags used by this callout driver.
//
#define TL_INSPECT_CONNECTION_POOL_TAG 'olfD'
#define TL_INSPECT_PENDED_PACKET_POOL_TAG 'kppD'
#define TL_INSPECT_CONTROL_DATA_POOL_TAG 'dcdD'

//
// Shared global data.
//
extern BOOLEAN configPermitTraffic;

extern HANDLE gRegistryKey;

extern HANDLE gInjectionHandle;

extern LIST_ENTRY gConnList;
extern KSPIN_LOCK gConnListLock;

extern LIST_ENTRY gPacketQueue;
extern KSPIN_LOCK gPacketQueueLock;

extern KEVENT gWorkerEvent;

extern BOOLEAN gDriverUnloading;

//
// Shared function prototypes
//

#if (NTDDI_VERSION >= NTDDI_WIN7)
// Version-1 of function invoked during classification when a callout filter 
// matches.
void 
TLInspectALEConnectClassify(
	__in const FWPS_INCOMING_VALUES0* inFixedValues,
	__in const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	__inout_opt void* layerData,
	__in_opt const void* classifyContext,
	__in const FWPS_FILTER1* filter,
	__in UINT64 flowContext,
	__out FWPS_CLASSIFY_OUT0* classifyOut
	);

#else
void
	TLInspectALEConnectClassify(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const FWPS_FILTER0* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT0* classifyOut
	);

#endif // (NTDDI_VERSION >= NTDDI_WIN7)

#if (NTDDI_VERSION >= NTDDI_WIN7)
// Version-1 of function invoked during classification when a callout filter 
// matches.
void 
	TLInspectALERecvAcceptClassify(
	__in const FWPS_INCOMING_VALUES0* inFixedValues,
	__in const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	__inout_opt void* layerData,
	__in_opt const void* classifyContext,
	__in const FWPS_FILTER1* filter,
	__in UINT64 flowContext,
	__out FWPS_CLASSIFY_OUT0* classifyOut
	);

#else
void
	TLInspectALERecvAcceptClassify(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const FWPS_FILTER0* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT0* classifyOut
	);

#endif // (NTDDI_VERSION >= NTDDI_WIN7)


#if (NTDDI_VERSION >= NTDDI_WIN7)
// Version-1 of function invoked during classification when a callout filter 
// matches.
void 
	TLInspectTransportClassify(
	__in const FWPS_INCOMING_VALUES0* inFixedValues,
	__in const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	__inout_opt void* layerData,
	__in_opt const void* classifyContext,
	__in const FWPS_FILTER1* filter,
	__in UINT64 flowContext,
	__out FWPS_CLASSIFY_OUT0* classifyOut
	);

#else
void
	TLInspectTransportClassify(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const FWPS_FILTER0* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT0* classifyOut
	);
#endif // (NTDDI_VERSION >= NTDDI_WIN7)


#if (NTDDI_VERSION >= NTDDI_WIN7)
// Version-1 of function that notifies the callout that a filter invoking it has
// been added/deleted.
NTSTATUS 
	TLInspectALEConnectNotify(
	__in FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	__in const GUID* filterKey,
	__inout FWPS_FILTER1* filter
	);

#else
NTSTATUS
	TLInspectALEConnectNotify(
	IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	IN const GUID* filterKey,
	IN const FWPS_FILTER0* filter
	);

#endif // (NTDDI_VERSION >= NTDDI_WIN7)

#if (NTDDI_VERSION >= NTDDI_WIN7)
// Version-1 of function that notifies the callout that a filter invoking it has
// been added/deleted.
NTSTATUS 
	TLInspectALERecvAcceptNotify(
	__in FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	__in const GUID* filterKey,
	__inout FWPS_FILTER1* filter
	);

#else
NTSTATUS
	TLInspectALERecvAcceptNotify(
	IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	IN const GUID* filterKey,
	IN const FWPS_FILTER0* filter
	);

#endif // (NTDDI_VERSION >= NTDDI_WIN7)


#if (NTDDI_VERSION >= NTDDI_WIN7)
// Version-1 of function that notifies the callout that a filter invoking it has
// been added/deleted.
NTSTATUS 
	TLInspectTransportNotify(
	__in FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	__in const GUID* filterKey,
	__inout FWPS_FILTER1* filter
	);

#else
NTSTATUS
	TLInspectTransportNotify(
	IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	IN const GUID* filterKey,
	IN const FWPS_FILTER0* filter
	);

#endif // (NTDDI_VERSION >= NTDDI_WIN7)



KSTART_ROUTINE TLInspectWorker;
void
TLInspectWorker(
   IN PVOID StartContext
   );

KSTART_ROUTINE ClearThread;
void ClearThread(IN void* pContext);

#define LimitUpSpeed CTL_CODE( FILE_DEVICE_NETWORK,0x811,METHOD_NEITHER,FILE_ANY_ACCESS )

#define LimitDownSpeed CTL_CODE( FILE_DEVICE_NETWORK,0x812,METHOD_NEITHER,FILE_ANY_ACCESS )

#define MonitorFlowData CTL_CODE( FILE_DEVICE_NETWORK,0x813,METHOD_NEITHER,FILE_ANY_ACCESS )

#define DEVICE_NAME L"\\Device\\FlowMonInspect"
#define DEVICE_DOSNAME L"\\DosDevices\\FlowMonInspect"

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
extern FlowInfo gFlowInfo;
extern KSPIN_LOCK gFlowQueueLock;

VOID MySleep(LONG msec);
/********************************************************************************/

extern LIST_ENTRY g_lFlowContextList;  //数据流链表，用于存放数据在层直接传播
extern KSPIN_LOCK g_kFlowContextListLock;//线程锁
extern UINT32              gAleFlowCalloutId;
extern UINT64              gAleFlowFilterId;
extern UINT32 gInboundTlCalloutIdV4;
extern UINT32 gOutboundTlCalloutIdV4;
extern KEVENT ThreadCloseOK;
extern BOOLEAN bStopThread;

#define TAG_NAME_CALLOUT 'CnoM'
#define TAG_NAME_BINDDATA 'BinM'
typedef struct _FLOW_DATA
{
	LIST_ENTRY  listEntry;
	UINT64      flowHandle;
	UINT64      flowContext;
	UINT64      calloutId;
	ULONG       localAddressV4;
	USHORT      localPort;
	USHORT      ipProto;
	ULONG       remoteAddressV4;
	USHORT      remotePort;
	WCHAR*      processPath;
	ULONG	   processID;
	BOOLEAN     deleting;
} FLOW_DATA;


#if(NTDDI_VERSION >= NTDDI_WIN7)
NTSTATUS MonitorCoFlowEstablishedCalloutV4(
	IN const FWPS_INCOMING_VALUES* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	IN VOID* packet,
	IN const void* classifyContext,
	IN const FWPS_FILTER* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT* classifyOut);

#else if(NTDDI_VERSION < NTDDI_WIN7)
NTSTATUS MonitorCoFlowEstablishedCalloutV4(
	IN const FWPS_INCOMING_VALUES* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	IN VOID* packet,
	IN const FWPS_FILTER* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT* classifyOut);
#endif

NTSTATUS MonitorCoFlowEstablishedNotifyV4(
	IN  FWPS_CALLOUT_NOTIFY_TYPE        notifyType,
	IN  const GUID*             filterKey,
	IN  const FWPS_FILTER*     filter);

VOID MonitorCoStreamFlowDeletion(
	IN UINT16 layerId,
	IN UINT32 calloutId,
	IN UINT64 flowContext);

#endif // _TL_INSPECT_H_

