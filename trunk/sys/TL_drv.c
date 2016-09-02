/*++

Copyright (c) Microsoft Corporation. All rights reserved

Abstract:

   Transport Inspect Proxy Callout Driver Sample.

   This sample callout driver intercepts all transport layer traffic (e.g. 
   TCP, UDP, and non-error ICMP) sent to or receive from a (configurable) 
   remote peer and queue them to a worker thread for out-of-band processing. 
   The sample performs inspection of inbound and outbound connections as 
   well as all packets belong to those connections.  In addition the sample 
   demonstrates special considerations required to be compatible with Windows 
   Vista and Windows Server 2008抯 IpSec implementation.

   Inspection parameters are configurable via the following registry 
   values --

   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Inspect
      
    o  BlockTraffic (REG_DWORD) : 0 (permit, default); 1 (block)
    o  RemoteAddressToInspect (REG_SZ) : literal IPv4/IPv6 string 
                                                (e.g. ?0.0.0.1?
   The sample is IP version agnostic. It performs inspection for 
   both IPv4 and IPv6 traffic.

Environment:

    Kernel mode

--*/

#include <ntddk.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>

#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>

#include "inspect.h"

#define INITGUID
#include <guiddef.h>

// 
// Configurable parameters (addresses and ports are in host order)
//

BOOLEAN configPermitTraffic = TRUE;

UINT8*   configInspectRemoteAddrV4 = NULL;
UINT8*   configInspectRemoteAddrV6 = NULL;

IN_ADDR  remoteAddrStorageV4;
IN6_ADDR remoteAddrStorageV6;

FlowInfo            gFlowInfo = {0};
KSPIN_LOCK          gFlowQueueLock;

LIST_ENTRY g_lFlowContextList;  //数据流链表，用于存放数据在层直接传播
KSPIN_LOCK g_kFlowContextListLock;//线程锁

UINT32              gAleFlowCalloutId = 0;
UINT64              gAleFlowFilterId = 0;
UINT64              gAleInBoundFilterId = 0;
UINT64              gAleOutBoundFilterId = 0;

KEVENT ThreadCloseOK;
BOOLEAN bStopThread = FALSE;
// 
// Callout and sublayer GUIDs
//

// ee93719d-ad5d-48c9-ae46-7270367d205c
DEFINE_GUID(
	DD_PROXY_FLOW_ESTABLISHED_CALLOUT_V4,
	0xee93719d,
	0xad5d,
	0x48c9,
	0xae, 0x46, 0x72, 0x70, 0x36, 0x7d, 0x20, 0x5c
	);

// bb6e405b-19f4-4ff3-b501-1a3dc01aae01
DEFINE_GUID(
    TL_INSPECT_OUTBOUND_TRANSPORT_CALLOUT_V4,
    0xbb6e405b,
    0x19f4,
    0x4ff3,
    0xb5, 0x01, 0x1a, 0x3d, 0xc0, 0x1a, 0xae, 0x01
);
// cabf7559-7c60-46c8-9d3b-2155ad5cf83f
DEFINE_GUID(
    TL_INSPECT_OUTBOUND_TRANSPORT_CALLOUT_V6,
    0xcabf7559,
    0x7c60,
    0x46c8,
    0x9d, 0x3b, 0x21, 0x55, 0xad, 0x5c, 0xf8, 0x3f
);
// 07248379-248b-4e49-bf07-24d99d52f8d0
DEFINE_GUID(
    TL_INSPECT_INBOUND_TRANSPORT_CALLOUT_V4,
    0x07248379,
    0x248b,
    0x4e49,
    0xbf, 0x07, 0x24, 0xd9, 0x9d, 0x52, 0xf8, 0xd0
);
// 6d126434-ed67-4285-925c-cb29282e0e06
DEFINE_GUID(
    TL_INSPECT_INBOUND_TRANSPORT_CALLOUT_V6,
    0x6d126434,
    0xed67,
    0x4285,
    0x92, 0x5c, 0xcb, 0x29, 0x28, 0x2e, 0x0e, 0x06
);
// 76b743d4-1249-4614-a632-6f9c4d08d25a
DEFINE_GUID(
    TL_INSPECT_ALE_CONNECT_CALLOUT_V4,
    0x76b743d4,
    0x1249,
    0x4614,
    0xa6, 0x32, 0x6f, 0x9c, 0x4d, 0x08, 0xd2, 0x5a
);

// ac80683a-5b84-43c3-8ae9-eddb5c0d23c2
DEFINE_GUID(
    TL_INSPECT_ALE_CONNECT_CALLOUT_V6,
    0xac80683a,
    0x5b84,
    0x43c3,
    0x8a, 0xe9, 0xed, 0xdb, 0x5c, 0x0d, 0x23, 0xc2
);

// 7ec7f7f5-0c55-4121-adc5-5d07d2ac0cef
DEFINE_GUID(
    TL_INSPECT_ALE_RECV_ACCEPT_CALLOUT_V4,
    0x7ec7f7f5,
    0x0c55,
    0x4121,
    0xad, 0xc5, 0x5d, 0x07, 0xd2, 0xac, 0x0c, 0xef
);

// b74ac2ed-4e71-4564-9975-787d5168a151
DEFINE_GUID(
    TL_INSPECT_ALE_RECV_ACCEPT_CALLOUT_V6,
    0xb74ac2ed,
    0x4e71,
    0x4564,
    0x99, 0x75, 0x78, 0x7d, 0x51, 0x68, 0xa1, 0x51
);

// 2e207682-d95f-4525-b966-969f26587f03
DEFINE_GUID(
    TL_INSPECT_SUBLAYER,
    0x2e207682,
    0xd95f,
    0x4525,
    0xb9, 0x66, 0x96, 0x9f, 0x26, 0x58, 0x7f, 0x03
);

// 
// Callout driver global variables
//

HANDLE gRegistryKey = NULL;

PDEVICE_OBJECT gDeviceObject;

HANDLE gEngineHandle = NULL;
UINT32 gAleConnectCalloutIdV4 = 0, gOutboundTlCalloutIdV4 = 0;
UINT32 gAleRecvAcceptCalloutIdV4 = 0, gInboundTlCalloutIdV4 = 0;
UINT32 gAleConnectCalloutIdV6 = 0, gOutboundTlCalloutIdV6 = 0;
UINT32 gAleRecvAcceptCalloutIdV6 = 0, gInboundTlCalloutIdV6 = 0;

HANDLE gInjectionHandle = NULL;

LIST_ENTRY gConnList;
KSPIN_LOCK gConnListLock;
LIST_ENTRY gPacketQueue;
KSPIN_LOCK gPacketQueueLock;

KEVENT gWorkerEvent;

BOOLEAN gDriverUnloading = FALSE;
PVOID gThreadObj = NULL;

// 
// Callout driver implementation
//

UCHAR gRegValueStorage[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 
                       INET6_ADDRSTRLEN * sizeof(WCHAR)]; 


DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
   IN  PDRIVER_OBJECT  driverObject,
   IN  PUNICODE_STRING registryPath
   );

DRIVER_UNLOAD DriverUnload;
VOID
DriverUnload(
   IN  PDRIVER_OBJECT driverObject
   );


void
TLInspectLoadConfig(
   IN  PUNICODE_STRING registryPath
   )
{
   NTSTATUS status;

   OBJECT_ATTRIBUTES objectAttributes;
   UNICODE_STRING valueName;
   KEY_VALUE_PARTIAL_INFORMATION* regValue = 
      (KEY_VALUE_PARTIAL_INFORMATION*)gRegValueStorage;
   ULONG resultLength;

   InitializeObjectAttributes(
      &objectAttributes,
      registryPath,
      OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
      NULL,
      NULL
      );

   status = ZwOpenKey(
               &gRegistryKey,
               KEY_READ,
               &objectAttributes
               );
   if (NT_SUCCESS(status))
   {
      RtlInitUnicodeString(
         &valueName,
         L"RemoteAddressToInspect"
         );

      status = ZwQueryValueKey(
                  gRegistryKey,
                  &valueName,
                  KeyValuePartialInformation,
                  regValue,
                  sizeof(gRegValueStorage),
                  &resultLength                                                                          
                  );

      if (NT_SUCCESS(status))
      {
         PWSTR terminator;

         status = RtlIpv4StringToAddressW(
                     (PCWSTR)(regValue->Data),
                     TRUE,
                     &terminator,
                     &remoteAddrStorageV4
                     );

         if (NT_SUCCESS(status))
         {
            remoteAddrStorageV4.S_un.S_addr = 
               RtlUlongByteSwap(remoteAddrStorageV4.S_un.S_addr);
            configInspectRemoteAddrV4 = &remoteAddrStorageV4.S_un.S_un_b.s_b1;
         }
         else
         {
            status = RtlIpv6StringToAddressW(
                        (PCWSTR)(regValue->Data),
                        &terminator,
                        &remoteAddrStorageV6
                        );

            if (NT_SUCCESS(status))
            {
               configInspectRemoteAddrV6 = (UINT8*)(&remoteAddrStorageV6.u.Byte[0]);
            }
         }
      }
   }
}

NTSTATUS
TLInspectAddFilter(
   IN const wchar_t* filterName,
   IN const wchar_t* filterDesc,
   IN const UINT8* remoteAddr,
   IN UINT64 context,
   IN const GUID* layerKey,
   IN const GUID* calloutKey
   )
{
   NTSTATUS status = STATUS_SUCCESS;

   FWPM_FILTER filter = {0};
   FWPM_FILTER_CONDITION filterConditions[3] = {0}; 
   UINT conditionIndex;
   UINT32 uinRemoteAddr = 0;

   filter.layerKey = *layerKey;
   filter.displayData.name = (wchar_t*)filterName;
   filter.displayData.description = (wchar_t*)filterDesc;

   filter.action.type = /*FWP_ACTION_CALLOUT_INSPECTION*/FWP_ACTION_CALLOUT_TERMINATING;
   filter.action.calloutKey = *calloutKey;
   filter.filterCondition = filterConditions;
   filter.subLayerKey = TL_INSPECT_SUBLAYER;
   filter.weight.type = FWP_EMPTY; // auto-weight.
   filter.rawContext = context;

   conditionIndex = 0;

//    if (remoteAddr != NULL)
//    {
   filterConditions[conditionIndex].fieldKey =  FWPM_CONDITION_IP_REMOTE_ADDRESS;
   filterConditions[conditionIndex].matchType = FWP_MATCH_NOT_EQUAL;
   filterConditions[conditionIndex].conditionValue.type = FWP_UINT32;
   filterConditions[conditionIndex].conditionValue.uint32 = uinRemoteAddr;
   conditionIndex++;
// 
//       if (IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||
//           IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4) ||
//           IsEqualGUID(layerKey, &FWPM_LAYER_INBOUND_TRANSPORT_V4) ||
//           IsEqualGUID(layerKey, &FWPM_LAYER_OUTBOUND_TRANSPORT_V4))
//       {
//          filterConditions[conditionIndex].conditionValue.type = FWP_UINT32;
//          filterConditions[conditionIndex].conditionValue.uint32 = 
//             *(UINT32*)remoteAddr;
//       }
//       else
//       {
//          filterConditions[conditionIndex].conditionValue.type = 
//             FWP_BYTE_ARRAY16_TYPE;
//          filterConditions[conditionIndex].conditionValue.byteArray16 = 
//             (FWP_BYTE_ARRAY16*)remoteAddr;
//       }
// 
//       conditionIndex++;
//    }

   filter.numFilterConditions = conditionIndex;

   status = FwpmFilterAdd(
               gEngineHandle,
               &filter,
               NULL,
               NULL);

   return status;
}

NTSTATUS
TLInspectRegisterALEClassifyCallouts(
   IN const GUID* layerKey,
   IN const GUID* calloutKey,
   IN void* deviceObject,
   OUT UINT32* calloutId
   )
/* ++

   This function registers callouts and filters at the following layers 
   to intercept inbound or outbound connect attempts.
   
      FWPM_LAYER_ALE_AUTH_CONNECT_V4
      FWPM_LAYER_ALE_AUTH_CONNECT_V6
      FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
      FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

-- */
{
   NTSTATUS status = STATUS_SUCCESS;

   FWPS_CALLOUT sCallout = {0};
   FWPM_CALLOUT mCallout = {0};

   FWPM_DISPLAY_DATA displayData = {0};

   BOOLEAN calloutRegistered = FALSE;

   sCallout.calloutKey = *calloutKey;

   if (IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||
       IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V6))
   {
      sCallout.classifyFn = TLInspectALEConnectClassify;
      sCallout.notifyFn = TLInspectALEConnectNotify;
   }
   else
   {
      sCallout.classifyFn = TLInspectALERecvAcceptClassify;
      sCallout.notifyFn = TLInspectALERecvAcceptNotify;
   }

   status = FwpsCalloutRegister(
               deviceObject,
               &sCallout,
               calloutId
               );
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }
   calloutRegistered = TRUE;

   displayData.name = L"Transport Inspect ALE Classify Callout";
   displayData.description = 
      L"Intercepts inbound or outbound connect attempts";

   mCallout.calloutKey = *calloutKey;
   mCallout.displayData = displayData;
   mCallout.applicableLayer = *layerKey;

   status = FwpmCalloutAdd(
               gEngineHandle,
               &mCallout,
               NULL,
               NULL
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   status = TLInspectAddFilter(
               L"Transport Inspect ALE Classify",
               L"Intercepts inbound or outbound connect attempts",
               (IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||
                IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4)) ? 
                  configInspectRemoteAddrV4 : configInspectRemoteAddrV6,
               0,
               layerKey,
               calloutKey
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

Exit:

   if (!NT_SUCCESS(status))
   {
      if (calloutRegistered)
      {
         FwpsCalloutUnregisterById(*calloutId);
         *calloutId = 0;
      }
   }

   return status;
}

NTSTATUS
TLInspectRegisterTransportCallouts(
   IN const GUID* layerKey,
   IN const GUID* calloutKey,
   IN void* deviceObject,
   OUT UINT32* calloutId
   )
/* ++

   This function registers callouts and filters that intercept transport 
   traffic at the following layers --

      FWPM_LAYER_OUTBOUND_TRANSPORT_V4
      FWPM_LAYER_OUTBOUND_TRANSPORT_V6
      FWPM_LAYER_INBOUND_TRANSPORT_V4
      FWPM_LAYER_INBOUND_TRANSPORT_V6

-- */
{
   NTSTATUS status = STATUS_SUCCESS;

   FWPS_CALLOUT sCallout = {0};
   FWPM_CALLOUT mCallout = {0};

   FWPM_DISPLAY_DATA displayData = {0};

   BOOLEAN calloutRegistered = FALSE;

   sCallout.calloutKey = *calloutKey;
   sCallout.classifyFn = TLInspectTransportClassify;
   sCallout.notifyFn = TLInspectTransportNotify;
//    sCallout.flowDeleteFn = MonitorCoStreamFlowDeletion;
//    sCallout.flags = FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW;

   status = FwpsCalloutRegister(
               deviceObject,
               &sCallout,
               calloutId
               );
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }
   calloutRegistered = TRUE;

   displayData.name = L"Transport Inspect Callout";
   displayData.description = L"Inspect inbound/outbound transport traffic";

   mCallout.calloutKey = *calloutKey;
   mCallout.displayData = displayData;
   mCallout.applicableLayer = *layerKey;

   status = FwpmCalloutAdd(
               gEngineHandle,
               &mCallout,
               NULL,
               NULL
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   configInspectRemoteAddrV4 = 0;
   configInspectRemoteAddrV6 = 0;

   status = TLInspectAddFilter(
               L"Transport Inspect Filter (Outbound)",
               L"Inspect inbound/outbound transport traffic",
               (IsEqualGUID(layerKey, &FWPM_LAYER_OUTBOUND_TRANSPORT_V4) ||
                IsEqualGUID(layerKey, &FWPM_LAYER_INBOUND_TRANSPORT_V4))? 
                  configInspectRemoteAddrV4 : configInspectRemoteAddrV6,
               0,
               layerKey,
               calloutKey
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

Exit:

   if (!NT_SUCCESS(status))
   {
      if (calloutRegistered)
      {
         FwpsCalloutUnregisterById(*calloutId);
         *calloutId = 0;
      }
   }

   return status;
}

NTSTATUS RegisterCalloutForLayer
	(
	IN void* deviceObject,
	IN const GUID* layerKey,
	IN const GUID* calloutKey,
	IN FWPS_CALLOUT_CLASSIFY_FN classifyFn,
	IN FWPS_CALLOUT_NOTIFY_FN notifyFn,
	IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteNotifyFn,
	OUT UINT32* calloutId,
	OUT UINT64* filterId
	)
{
	NTSTATUS        status = STATUS_SUCCESS;
	FWPS_CALLOUT    sCallout = {0};
	FWPM_FILTER     mFilter = {0};
	FWPM_FILTER_CONDITION mFilter_condition[1] = {0};
	FWPM_CALLOUT    mCallout = {0};
	FWPM_DISPLAY_DATA mDispData = {0};
	BOOLEAN         bCalloutRegistered = FALSE; 
	sCallout.calloutKey = *calloutKey;
	sCallout.classifyFn = classifyFn;
	sCallout.flowDeleteFn = flowDeleteNotifyFn;
	sCallout.notifyFn = notifyFn;
	//要使用哪个设备对象注册
	status = FwpsCalloutRegister( deviceObject/*gDevObj*/,&sCallout,calloutId );
	if( !NT_SUCCESS(status))
		goto exit;
	bCalloutRegistered = TRUE;
	mDispData.name = L"WFP_TEST";
	mDispData.description = L"DriverLife_WFP TEST";
	//你感兴趣的内容
	mCallout.applicableLayer = *layerKey;
	//你感兴趣的内容的GUID
	mCallout.calloutKey = *calloutKey;
	mCallout.displayData = mDispData;
	//mCallout.flags = FWPM_CALLOUT_FLAG_PERSISTENT; // Make this a persistent callout.
	//添加回调函数
	status = FwpmCalloutAdd( gEngineHandle,&mCallout,NULL,NULL);
	if( !NT_SUCCESS(status))
		goto exit;
	mFilter.action.calloutKey = *calloutKey;
	//在callout里决定
	mFilter.action.type = /*FWP_ACTION_CALLOUT_TERMINATING*/FWP_ACTION_CALLOUT_INSPECTION;	
	mFilter.displayData.name = L"WFP_TEST";
	mFilter.displayData.description = L"DriverLife_WFP TEST";
	mFilter.layerKey = *layerKey;
	mFilter.numFilterConditions = 0;
	mFilter.filterCondition = mFilter_condition;
	mFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
	mFilter.weight.type = FWP_EMPTY;
	//添加过滤器
	status = FwpmFilterAdd( gEngineHandle,&mFilter,NULL,filterId );
	if( !NT_SUCCESS( status))
		goto exit;
exit:
	if( !NT_SUCCESS(status))
	{
		if( bCalloutRegistered )
		{
			FwpsCalloutUnregisterById( *calloutId );
		}
	}
	return status;
}

NTSTATUS
TLInspectRegisterCallouts(
   IN void* deviceObject
   )
/* ++

   This function registers dynamic callouts and filters that intercept 
   transport traffic at ALE AUTH_CONNECT/AUTH_RECV_ACCEPT and 
   INBOUND/OUTBOUND transport layers.

   Callouts and filters will be removed during DriverUnload.

-- */
{
   NTSTATUS status = STATUS_SUCCESS;
   FWPM_SUBLAYER TLInspectSubLayer;

   BOOLEAN engineOpened = FALSE;
   BOOLEAN inTransaction = FALSE;

   FWPM_SESSION session = {0};

   session.flags = FWPM_SESSION_FLAG_DYNAMIC;

   status = FwpmEngineOpen(
                NULL,
                RPC_C_AUTHN_WINNT,
                NULL,
                &session,
                &gEngineHandle
                );
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }
   engineOpened = TRUE;

   status = FwpmTransactionBegin(gEngineHandle, 0);
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }
   inTransaction = TRUE;

   RtlZeroMemory(&TLInspectSubLayer, sizeof(FWPM_SUBLAYER0)); 

   TLInspectSubLayer.subLayerKey = TL_INSPECT_SUBLAYER;
   TLInspectSubLayer.displayData.name = L"Transport Inspect Sub-Layer";
   TLInspectSubLayer.displayData.description = 
      L"Sub-Layer for use by Transport Inspect callouts";
   TLInspectSubLayer.flags = 0/*FWPM_SUBLAYER_FLAG_PERSISTENT*/;
   TLInspectSubLayer.weight = 65535; // must be less than the weight of 
                                 // FWPM_SUBLAYER_UNIVERSAL to be
                                 // compatible with Vista's IpSec
                                 // implementation.

   status = FwpmSubLayerAdd(gEngineHandle, &TLInspectSubLayer, NULL);
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

//    //增加一个数据流连接层
//    InitializeListHead(&g_lFlowContextList);//
//    KeInitializeSpinLock(&g_kFlowContextListLock);
// 
//    status = RegisterCalloutForLayer(
// 	   deviceObject,
// 	   &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
// 	   &DD_PROXY_FLOW_ESTABLISHED_CALLOUT_V4,
// 	   MonitorCoFlowEstablishedCalloutV4,
// 	   MonitorCoFlowEstablishedNotifyV4,
// 	   NULL,
// 	   &gAleFlowCalloutId,
// 	   &gAleFlowFilterId);
// 
//    if( !NT_SUCCESS(status))
//    {
// 	   DbgPrint("RegisterCalloutForLayer-FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4 failed!\n");
// 	   goto Exit;
//    }


//   if (configInspectRemoteAddrV4 != NULL)
   {
//       status = TLInspectRegisterALEClassifyCallouts(
//                   &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
//                   &TL_INSPECT_ALE_CONNECT_CALLOUT_V4,
//                   deviceObject,
//                   &gAleConnectCalloutIdV4
//                   );
//       if (!NT_SUCCESS(status))
//       {
//          goto Exit;
//       }
// 
//       status = TLInspectRegisterALEClassifyCallouts(
//                   &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
//                   &TL_INSPECT_ALE_RECV_ACCEPT_CALLOUT_V4,
//                   deviceObject,
//                   &gAleRecvAcceptCalloutIdV4
//                   );
//       if (!NT_SUCCESS(status))
//       {
//          goto Exit;
//       }


// 	   status = RegisterCalloutForLayer(
// 		   deviceObject,
// 		   &FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
// 		   &TL_INSPECT_OUTBOUND_TRANSPORT_CALLOUT_V4,
// 		   TLInspectTransportClassify,
// 		   TLInspectTransportNotify,
// 		   NULL,
// 		   &gOutboundTlCalloutIdV4,
// 		   &gAleOutBoundFilterId);
	   status = TLInspectRegisterTransportCallouts(
		   &FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
		   &TL_INSPECT_OUTBOUND_TRANSPORT_CALLOUT_V4,
		   deviceObject,
		   &gOutboundTlCalloutIdV4
		   );
	   if (!NT_SUCCESS(status))
	   {
		   goto Exit;
	   }

      status = TLInspectRegisterTransportCallouts(
                  &FWPM_LAYER_INBOUND_TRANSPORT_V4,
                  &TL_INSPECT_INBOUND_TRANSPORT_CALLOUT_V4,
                  deviceObject,
                  &gInboundTlCalloutIdV4
                  );
      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }
   }

   configInspectRemoteAddrV6 = NULL;

   if (configInspectRemoteAddrV6 != NULL)
   {
      status = TLInspectRegisterALEClassifyCallouts(
                  &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                  &TL_INSPECT_ALE_CONNECT_CALLOUT_V6,
                  deviceObject,
                  &gAleConnectCalloutIdV6
                  );
      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }

      status = TLInspectRegisterALEClassifyCallouts(
                  &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                  &TL_INSPECT_ALE_RECV_ACCEPT_CALLOUT_V6,
                  deviceObject,
                  &gAleRecvAcceptCalloutIdV6
                  );
      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }

      status = TLInspectRegisterTransportCallouts(
                  &FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
                  &TL_INSPECT_OUTBOUND_TRANSPORT_CALLOUT_V6,
                  deviceObject,
                  &gOutboundTlCalloutIdV6
                  );
      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }

      status = TLInspectRegisterTransportCallouts(
                  &FWPM_LAYER_INBOUND_TRANSPORT_V6,
                  &TL_INSPECT_INBOUND_TRANSPORT_CALLOUT_V6,
                  deviceObject,
                  &gInboundTlCalloutIdV6
                  );
      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }
   }

   status = FwpmTransactionCommit(gEngineHandle);
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }
   inTransaction = FALSE;

Exit:

   if (!NT_SUCCESS(status))
   {
      if (inTransaction)
      {
         FwpmTransactionAbort(gEngineHandle);
      }
      if (engineOpened)
      {
         FwpmEngineClose(gEngineHandle);
         gEngineHandle = NULL;
      }
   }

   return status;
}

void
TLInspectUnregisterCallouts()
{


	if( gEngineHandle != 0 )
	{
		if(0 != gAleFlowFilterId)
			FwpmFilterDeleteById( gEngineHandle,gAleFlowFilterId );
		if(0 != gAleFlowCalloutId)
			FwpmCalloutDeleteById( gEngineHandle,gAleFlowCalloutId );

		gAleFlowFilterId = 0;

	}


   FwpmEngineClose(gEngineHandle);
   gEngineHandle = NULL;

   if (0 != gOutboundTlCalloutIdV6)
	   FwpsCalloutUnregisterById(gOutboundTlCalloutIdV6);
   if (0 != gOutboundTlCalloutIdV4)
	   FwpsCalloutUnregisterById(gOutboundTlCalloutIdV4);
   if (0 != gInboundTlCalloutIdV6)
	   FwpsCalloutUnregisterById(gInboundTlCalloutIdV6);
   if (0 != gInboundTlCalloutIdV4)
	   FwpsCalloutUnregisterById(gInboundTlCalloutIdV4);

   if (0 != gAleConnectCalloutIdV6)
	   FwpsCalloutUnregisterById(gAleConnectCalloutIdV6);
   if (0 != gAleConnectCalloutIdV4)
	   FwpsCalloutUnregisterById(gAleConnectCalloutIdV4);
   if (0 != gAleRecvAcceptCalloutIdV6)
	   FwpsCalloutUnregisterById(gAleRecvAcceptCalloutIdV6);
   if (0 != gAleRecvAcceptCalloutIdV4)
	   FwpsCalloutUnregisterById(gAleRecvAcceptCalloutIdV4);



}

VOID
DriverUnload(
   IN  PDRIVER_OBJECT driverObject
   )
{

   KLOCK_QUEUE_HANDLE connListLockHandle;
   KLOCK_QUEUE_HANDLE packetQueueLockHandle;

   UNREFERENCED_PARAMETER(driverObject);

   //关闭清除流量线程
   KeInitializeEvent(&ThreadCloseOK, SynchronizationEvent, FALSE);
   bStopThread = TRUE;
   KeWaitForSingleObject(&ThreadCloseOK, Executive, KernelMode, FALSE, 0);


   KeAcquireInStackQueuedSpinLock(
      &gConnListLock,
      &connListLockHandle
      );
   KeAcquireInStackQueuedSpinLock(
      &gPacketQueueLock,
      &packetQueueLockHandle
      );

   gDriverUnloading = TRUE;

   KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
   KeReleaseInStackQueuedSpinLock(&connListLockHandle);

   //    //等待一定的时间确认工作线程退出
   MySleep(800);

   if (IsListEmpty(&gConnList) && IsListEmpty(&gPacketQueue))
   {
      KeSetEvent(
         &gWorkerEvent,
         IO_NO_INCREMENT, 
         FALSE
         );
   }

   ASSERT(gThreadObj != NULL);

   KeWaitForSingleObject(
      gThreadObj,
      Executive,
      KernelMode,
      FALSE,
      NULL
      );

   ObDereferenceObject(gThreadObj);

   TLInspectUnregisterCallouts();

   FwpsInjectionHandleDestroy0(gInjectionHandle);

   IoDeleteDevice(gDeviceObject);

   ZwClose(gRegistryKey);
}

NTSTATUS
	WallDispatchRequest (
	IN PDEVICE_OBJECT deviceObject,
	IN PIRP irp
	)
{
	//LOG("into\n");

	return STATUS_SUCCESS;
}

NTSTATUS
	WallDispatchCreate (
	IN PDEVICE_OBJECT deviceObject,
	IN PIRP irp
	)
{
	NTSTATUS        status = STATUS_SUCCESS;

	//LOG("into\n");

	return STATUS_SUCCESS;
}

NTSTATUS
	WallDispatchClose (
	IN PDEVICE_OBJECT deviceObject,
	IN PIRP irp
	)
{
	//LOG("into\n");

	return STATUS_SUCCESS;
}

NTSTATUS
	WallDispatchCleanup (
	IN PDEVICE_OBJECT deviceObject,
	IN PIRP irp
	)
{
	//LOG("into\n");

	return STATUS_SUCCESS;
}

NTSTATUS
	WallDispatchDeviceControl (
	IN PDEVICE_OBJECT deviceObject,
	IN PIRP irp
	)
{
	PIO_STACK_LOCATION  irpSp = NULL;
	const char * d="@";
	ULONG ulBufLen = 0;
	PVOID pIoBuff = NULL;
	//LOG("into\n");

	//pIoBuff = irp->AssociatedIrp.SystemBuffer;

	irpSp = IoGetCurrentIrpStackLocation( irp );

	ulBufLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;

	pIoBuff = irpSp->Parameters.DeviceIoControl.Type3InputBuffer;

	KdPrint(("inBuffer=%x\n",irpSp->Parameters.DeviceIoControl.Type3InputBuffer));

	switch( irpSp->Parameters.DeviceIoControl.IoControlCode )
	{
	case MonitorFlowData:
		{
			__try
			{
				KIRQL irq;
				KeAcquireSpinLock(&gFlowQueueLock, &irq);

				RtlCopyMemory(pIoBuff, &gFlowInfo, sizeof(gFlowInfo));
// 				gFlowInfo.dwUpTpye = 0;
// 				gFlowInfo.dwDownTpye = 0;
// 				gFlowInfo.dwDownTpyeLAN = 0;
// 				gFlowInfo.dwDownTpyeWAN = 0;
// 				gFlowInfo.dwUpTpyeLAN = 0;
// 				gFlowInfo.dwUpTpyeWAN = 0;

				KeReleaseSpinLock(&gFlowQueueLock, irq);

				irp->IoStatus.Information = 0;
				irp->IoStatus.Status = STATUS_SUCCESS;

			}__except (EXCEPTION_EXECUTE_HANDLER)
			{
				irp->IoStatus.Status = GetExceptionCode();
			}
			break;
		}

	case LimitUpSpeed:
		{
			if (0 != ulBufLen && NULL != pIoBuff)
			{
				KIRQL irq;
				KeAcquireSpinLock(&gFlowQueueLock, &irq);
				gFlowInfo.dwLimitUp = *(PDWORD)pIoBuff;
				KeReleaseSpinLock(&gFlowQueueLock, irq);

			}
			irp->IoStatus.Information = 0;
			irp->IoStatus.Status = STATUS_SUCCESS;
			break;
		}

	case LimitDownSpeed:
		{
			if (ulBufLen && NULL != pIoBuff)
			{
				KIRQL irq;
				KeAcquireSpinLock(&gFlowQueueLock, &irq);
				//DbgPrint("[DriverLife]: LimitDownSpeed LockIn\n");
				gFlowInfo.dwLimitDown = *(PDWORD)pIoBuff;
				//DbgPrint("[DriverLife]: LimitDownSpeed LockOut\n");
				KeReleaseSpinLock(&gFlowQueueLock, irq);

			}
			irp->IoStatus.Information = 0;
			irp->IoStatus.Status = STATUS_SUCCESS;
			break;
		}

	default:
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_SUCCESS;
		break;
	}

	IoCompleteRequest( irp,IO_NO_INCREMENT );
	return STATUS_SUCCESS;
}


NTSTATUS
DriverEntry(
   IN  PDRIVER_OBJECT  driverObject,
   IN  PUNICODE_STRING registryPath
   )
{
   NTSTATUS status = STATUS_SUCCESS;
   UNICODE_STRING deviceName;
   UNICODE_STRING  deviceDosName;
   HANDLE threadHandle = NULL;
   HANDLE hThread = NULL;
   int i = 0;

//   TLInspectLoadConfig(registryPath);
//
//    if ((configInspectRemoteAddrV4 == NULL) && 
//        (configInspectRemoteAddrV6 == NULL))
//    {
//       status = STATUS_DEVICE_CONFIGURATION_ERROR;
//       goto Exit;
//    }


   for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
   {
	   driverObject->MajorFunction[i] = WallDispatchRequest;
   }
   driverObject->MajorFunction[IRP_MJ_CREATE] = WallDispatchCreate;
   driverObject->MajorFunction[IRP_MJ_CLOSE] = WallDispatchClose;
   driverObject->MajorFunction[IRP_MJ_CLEANUP] = WallDispatchCleanup;
   driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WallDispatchDeviceControl;

   RtlInitUnicodeString(
      &deviceName,
      DEVICE_NAME/*L"\\Device\\StreamEitor"*/
      );

   status = IoCreateDevice(
               driverObject, 
               0, 
               &deviceName, 
               FILE_DEVICE_NETWORK, 
               0, 
               FALSE, 
               &gDeviceObject
               );
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   RtlInitUnicodeString(&deviceDosName, DEVICE_DOSNAME);
   status = IoCreateSymbolicLink(&deviceDosName, &deviceName);
   if( !NT_SUCCESS( status ))
   {
	   KdPrint(("Create Symbolink name failed!\n"));
	   goto Exit;
   }

   status = FwpsInjectionHandleCreate0(
               AF_UNSPEC,
               FWPS_INJECTION_TYPE_TRANSPORT,
               &gInjectionHandle
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   InitializeListHead(&gConnList);
   KeInitializeSpinLock(&gConnListLock);   

   InitializeListHead(&gPacketQueue);
   KeInitializeSpinLock(&gPacketQueueLock);  

   KeInitializeEvent(
      &gWorkerEvent,
      NotificationEvent,
      FALSE
      );

   status = TLInspectRegisterCallouts(
               gDeviceObject
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   status = PsCreateSystemThread(
               &threadHandle,
               THREAD_ALL_ACCESS,
               NULL,
               NULL,
               NULL,
               TLInspectWorker,
               NULL
               );

   if (!NT_SUCCESS(status))
   {
      
   }

   status = ObReferenceObjectByHandle(
               threadHandle,
               0,
               NULL,
               KernelMode,
               &gThreadObj,
               NULL
               );
   ASSERT(NT_SUCCESS(status));

   ZwClose(threadHandle);


   //创建一条线程来清空一秒的流量
   status = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, ClearThread, NULL);
   if (NT_SUCCESS(status))
	   ZwClose(hThread);
   else
	   goto Exit;

   driverObject->DriverUnload = DriverUnload;

Exit:
   
   if (!NT_SUCCESS(status))
   {
      if (gEngineHandle != NULL)
      {
         TLInspectUnregisterCallouts();
      }
      if (gInjectionHandle != NULL)
      {
         FwpsInjectionHandleDestroy(gInjectionHandle);
      }
      if (gDeviceObject)
      {
         IoDeleteDevice(gDeviceObject);
      }
      
      if(gRegistryKey != NULL)
      {
        ZwClose(gRegistryKey);
      }
   }

   return status;
}


