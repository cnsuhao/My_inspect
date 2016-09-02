/*++

Copyright (c) Microsoft Corporation. All rights reserved

Abstract:

   This file implements the classifyFn callout functions for the ALE connect,
   recv-accept, and transport callouts. In addition the system worker thread 
   that performs the actual packet inspection is also implemented here along 
   with the eventing mechanisms shared between the classify function and the
   worker thread.

   connect/Packet inspection is done out-of-band by a system worker thread 
   using the reference-drop-clone-reinject as well as ALE pend/complete 
   mechanism. Therefore the sample can serve as a base in scenarios where 
   filtering decision cannot be made within the classifyFn() callout and 
   instead must be made, for example, by an user-mode application.

Environment:

    Kernel mode

--*/

#include "ntddk.h"

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include "fwpsk.h"

#pragma warning(pop)

#include "fwpmk.h"

#include "inspect.h"
#include "utils.h"

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
	)

#else
void
	TLInspectALEConnectClassify(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const FWPS_FILTER0* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT0* classifyOut
	)

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
/* ++

   This is the classifyFn function for the ALE connect (v4 and v6) callout.
   For an initial classify (where the FWP_CONDITION_FLAG_IS_REAUTHORIZE flag
   is not set), it is queued to the connection list for inspection by the
   worker thread. For re-auth, we first check if it is triggered by an ealier
   FwpsCompleteOperation0 call by looking for an pended connect that has been
   inspected. If found, we remove it from the connect list and return the 
   inspection result; otherwise we can conclude that the re-auth is triggered 
   by policy change so we queue it to the packet queue to be process by the 
   worker thread like any other regular packets.

-- */
{
   NTSTATUS status;

   KLOCK_QUEUE_HANDLE connListLockHandle;
   KLOCK_QUEUE_HANDLE packetQueueLockHandle;

   TL_INSPECT_PENDED_PACKET* pendedConnect = NULL;
   TL_INSPECT_PENDED_PACKET* pendedPacket = NULL;

   ADDRESS_FAMILY addressFamily;
   FWPS_PACKET_INJECTION_STATE packetState;
   BOOLEAN signalWorkerThread;

   UNREFERENCED_PARAMETER(flowContext);
   UNREFERENCED_PARAMETER(filter);

   //
   // We don't have the necessary right to alter the classify, exit.
   //
   if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
   {
      goto Exit;
   }

   if (layerData != NULL)
   {
      //
      // We don't re-inspect packets that we've inspected earlier.
      //
      packetState = FwpsQueryPacketInjectionState0(
                     gInjectionHandle,
                     layerData,
                     NULL
                     );

      if ((packetState == FWPS_PACKET_INJECTED_BY_SELF) ||
          (packetState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF))
      {
         classifyOut->actionType = FWP_ACTION_PERMIT;
         goto Exit;
      }
   }

   addressFamily = GetAddressFamilyForLayer(inFixedValues->layerId);

   if (!IsAleReauthorize(inFixedValues))
   {
      //
      // If the classify is the initial authorization for a connection, we 
      // queue it to the pended connection list and notify the worker thread
      // for out-of-band processing.
      //
      pendedConnect = AllocateAndInitializePendedPacket(
                           inFixedValues,
                           inMetaValues,
                           addressFamily,
                           layerData,
                           TL_INSPECT_CONNECT_PACKET,
                           FWP_DIRECTION_OUTBOUND
                           );

      if (pendedConnect == NULL)
      {
         classifyOut->actionType = FWP_ACTION_BLOCK;
         classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
         goto Exit;
      }

      ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, 
                                            FWPS_METADATA_FIELD_COMPLETION_HANDLE));

      //
      // Pend the ALE_AUTH_CONNECT classify.
      //
      status = FwpsPendOperation0(
                  inMetaValues->completionHandle,
                  &pendedConnect->completionContext
                  );

      if (!NT_SUCCESS(status))
      {
         classifyOut->actionType = FWP_ACTION_BLOCK;
         classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
         goto Exit;
      }

      KeAcquireInStackQueuedSpinLock(
         &gConnListLock,
         &connListLockHandle
         );
      KeAcquireInStackQueuedSpinLock(
         &gPacketQueueLock,
         &packetQueueLockHandle
         );

      signalWorkerThread = IsListEmpty(&gConnList) && 
                           IsListEmpty(&gPacketQueue);

      InsertTailList(&gConnList, &pendedConnect->listEntry);
      pendedConnect = NULL; // ownership transferred

      KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
      KeReleaseInStackQueuedSpinLock(&connListLockHandle);

      classifyOut->actionType = FWP_ACTION_BLOCK;
      classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;

      if (signalWorkerThread)
      {
         KeSetEvent(
            &gWorkerEvent, 
            0, 
            FALSE
            );
      }
   }
   else // re-auth @ ALE_AUTH_CONNECT
   {
      FWP_DIRECTION packetDirection;
      //
      // The classify is the re-authorization for an existing connection, it 
      // could have been triggered for one of the three cases --
      //
      //    1) The re-auth is triggered by a FwpsCompleteOperation0 call to
      //       complete a ALE_AUTH_CONNECT classify pended earlier. 
      //    2) The re-auth is triggered by an outbound packet sent immediately
      //       after a policy change at ALE_AUTH_CONNECT layer.
      //    3) The re-auth is triggered by an inbound packet received 
      //       immediately after a policy change at ALE_AUTH_CONNECT layer.
      //

      ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, 
                                            FWPS_METADATA_FIELD_PACKET_DIRECTION));
      packetDirection = inMetaValues->packetDirection;

      if (packetDirection == FWP_DIRECTION_OUTBOUND)
      {
         LIST_ENTRY* listEntry;
         BOOLEAN authComplete = FALSE;

         //
         // We first check whether this is a FwpsCompleteOperation0- triggered
         // reauth by looking for a pended connect that has the inspection
         // decision recorded. If found, we return that decision and remove
         // the pended connect from the list.
         //

         KeAcquireInStackQueuedSpinLock(
            &gConnListLock,
            &connListLockHandle
            );

         for (listEntry = gConnList.Flink;
              listEntry != &gConnList;
              listEntry = listEntry->Flink)
         {
            pendedConnect = CONTAINING_RECORD(
                              listEntry,
                              TL_INSPECT_PENDED_PACKET,
                              listEntry
                              );

            if (IsMatchingConnectPacket(
                     inFixedValues,
                     addressFamily,
                     packetDirection,
                     pendedConnect
                  ) && (pendedConnect->authConnectDecision != 0))
            {
               ASSERT((pendedConnect->authConnectDecision == FWP_ACTION_PERMIT) ||
                      (pendedConnect->authConnectDecision == FWP_ACTION_BLOCK));
               
               classifyOut->actionType = pendedConnect->authConnectDecision;

               RemoveEntryList(&pendedConnect->listEntry);
               
               if (!gDriverUnloading &&
                   (pendedConnect->netBufferList != NULL) &&
                   (pendedConnect->authConnectDecision == FWP_ACTION_PERMIT))
               {
                  //
                  // Now the outbound connection has been authorized. If the
                  // pended connect has a net buffer list in it, we need it
                  // morph it into a data packet and queue it to the packet
                  // queue for send injecition.
                  //
                  pendedConnect->type = TL_INSPECT_DATA_PACKET;

                  KeAcquireInStackQueuedSpinLock(
                     &gPacketQueueLock,
                     &packetQueueLockHandle
                     );

                  signalWorkerThread = IsListEmpty(&gPacketQueue) &&
                                       IsListEmpty(&gConnList);

                  InsertTailList(&gPacketQueue, &pendedConnect->listEntry);
                  pendedConnect = NULL; // ownership transferred

                  KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
                  
                  if (signalWorkerThread)
                  {
                     KeSetEvent(
                        &gWorkerEvent, 
                        0, 
                        FALSE
                        );
                  }
               }

               authComplete = TRUE;
               break;
            }
         }

         KeReleaseInStackQueuedSpinLock(&connListLockHandle);

         if (authComplete)
         {
            goto Exit;
         }
      }

      //
      // If we reach here it means this is a policy change triggered re-auth
      // for an pre-existing connection. For such a packet (inbound or 
      // outbound) we queue it to the packet queue and inspect it just like
      // other regular data packets from TRANSPORT layers.
      //

      ASSERT(layerData != NULL);

      pendedPacket = AllocateAndInitializePendedPacket(
                        inFixedValues,
                        inMetaValues,
                        addressFamily,
                        layerData,
                        TL_INSPECT_REAUTH_PACKET,
                        packetDirection
                        );

      if (pendedPacket == NULL)
      {
         classifyOut->actionType = FWP_ACTION_BLOCK;
         classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
         goto Exit;
      }

      if (packetDirection == FWP_DIRECTION_INBOUND)
      {
         pendedPacket->ipSecProtected = IsSecureConnection(inFixedValues);
      }

      KeAcquireInStackQueuedSpinLock(
         &gConnListLock,
         &connListLockHandle
         );
      KeAcquireInStackQueuedSpinLock(
         &gPacketQueueLock,
         &packetQueueLockHandle
         );

      if (!gDriverUnloading)
      {
         signalWorkerThread = IsListEmpty(&gPacketQueue) &&
                              IsListEmpty(&gConnList);

         InsertTailList(&gPacketQueue, &pendedPacket->listEntry);
         pendedPacket = NULL; // ownership transferred

         classifyOut->actionType = FWP_ACTION_BLOCK;
         classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
      }
      else
      {
         //
         // Driver is being unloaded, permit any connect classify.
         //
         signalWorkerThread = FALSE;

         classifyOut->actionType = FWP_ACTION_PERMIT;
      }

      KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
      KeReleaseInStackQueuedSpinLock(&connListLockHandle);

      if (signalWorkerThread)
      {
         KeSetEvent(
            &gWorkerEvent, 
            0, 
            FALSE
            );
      }

   }

Exit:

   if (pendedPacket != NULL)
   {
      FreePendedPacket(pendedPacket);
   }
   if (pendedConnect != NULL)
   {
      FreePendedPacket(pendedConnect);
   }

   return;
}

#if (NTDDI_VERSION >= NTDDI_WIN7)
// Version-1 of function that notifies the callout that a filter invoking it has
// been added/deleted.
NTSTATUS 
	TLInspectALEConnectNotify(
	__in FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	__in const GUID* filterKey,
	__inout FWPS_FILTER1* filter
	)

#else
NTSTATUS
	TLInspectALEConnectNotify(
	IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	IN const GUID* filterKey,
	IN const FWPS_FILTER0* filter
	)

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
{
   UNREFERENCED_PARAMETER(notifyType);
   UNREFERENCED_PARAMETER(filterKey);
   UNREFERENCED_PARAMETER(filter);

   return STATUS_SUCCESS;
}

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
	)

#else
void
	TLInspectALERecvAcceptClassify(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const FWPS_FILTER0* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT0* classifyOut
	)

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
/* ++

   This is the classifyFn function for the ALE Recv-Accept (v4 and v6) callout.
   For an initial classify (where the FWP_CONDITION_FLAG_IS_REAUTHORIZE flag
   is not set), it is queued to the connection list for inspection by the
   worker thread. For re-auth, it is queued to the packet queue to be process 
   by the worker thread like any other regular packets.

-- */
{
   NTSTATUS status;

   KLOCK_QUEUE_HANDLE connListLockHandle;
   KLOCK_QUEUE_HANDLE packetQueueLockHandle;

   TL_INSPECT_PENDED_PACKET* pendedRecvAccept = NULL;
   TL_INSPECT_PENDED_PACKET* pendedPacket = NULL;

   ADDRESS_FAMILY addressFamily;
   FWPS_PACKET_INJECTION_STATE packetState;
   BOOLEAN signalWorkerThread;

   UNREFERENCED_PARAMETER(flowContext);
   UNREFERENCED_PARAMETER(filter);


   //
   // We don't have the necessary right to alter the classify, exit.
   //
   if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
   {
      goto Exit;
   }

  ASSERT(layerData != NULL);

   //
   // We don't re-inspect packets that we've inspected earlier.
   //
   packetState = FwpsQueryPacketInjectionState0(
                     gInjectionHandle,
                     layerData,
                     NULL
                     );

   if ((packetState == FWPS_PACKET_INJECTED_BY_SELF) ||
       (packetState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF))
   {
      classifyOut->actionType = FWP_ACTION_PERMIT;
      goto Exit;
   }

   addressFamily = GetAddressFamilyForLayer(inFixedValues->layerId);

   if (!IsAleReauthorize(inFixedValues))
   {
      //
      // If the classify is the initial authorization for a connection, we 
      // queue it to the pended connection list and notify the worker thread
      // for out-of-band processing.
      //
      pendedRecvAccept = AllocateAndInitializePendedPacket(
                              inFixedValues,
                              inMetaValues,
                              addressFamily,
                              layerData,
                              TL_INSPECT_CONNECT_PACKET,
                              FWP_DIRECTION_INBOUND
                              );

      if (pendedRecvAccept == NULL)
      {
         classifyOut->actionType = FWP_ACTION_BLOCK;
         classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
         goto Exit;
      }

      ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, 
                                            FWPS_METADATA_FIELD_COMPLETION_HANDLE));

      //
      // Pend the ALE_AUTH_RECV_ACCEPT classify.
      //
      status = FwpsPendOperation0(
                  inMetaValues->completionHandle,
                  &pendedRecvAccept->completionContext
                  );

      if (!NT_SUCCESS(status))
      {
         classifyOut->actionType = FWP_ACTION_BLOCK;
         classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
         goto Exit;
      }

      KeAcquireInStackQueuedSpinLock(
         &gConnListLock,
         &connListLockHandle
         );
      KeAcquireInStackQueuedSpinLock(
         &gPacketQueueLock,
         &packetQueueLockHandle
         );

      signalWorkerThread = IsListEmpty(&gConnList) && 
                           IsListEmpty(&gPacketQueue);

      InsertTailList(&gConnList, &pendedRecvAccept->listEntry);
      pendedRecvAccept = NULL; // ownership transferred

      KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
      KeReleaseInStackQueuedSpinLock(&connListLockHandle);

      classifyOut->actionType = FWP_ACTION_BLOCK;
      classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;

      if (signalWorkerThread)
      {
         KeSetEvent(
            &gWorkerEvent, 
            0, 
            FALSE
            );
      }

   }
   else // re-auth @ ALE_AUTH_RECV_ACCEPT
   {
      FWP_DIRECTION packetDirection;
      //
      // The classify is the re-authorization for a existing connection, it 
      // could have been triggered for one of the two cases --
      //
      //    1) The re-auth is triggered by an outbound packet sent immediately
      //       after a policy change at ALE_AUTH_RECV_ACCEPT layer.
      //    2) The re-auth is triggered by an inbound packet received 
      //       immediately after a policy change at ALE_AUTH_RECV_ACCEPT layer.
      //

      ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, 
                                            FWPS_METADATA_FIELD_PACKET_DIRECTION));
      packetDirection = inMetaValues->packetDirection;

      pendedPacket = AllocateAndInitializePendedPacket(
                        inFixedValues,
                        inMetaValues,
                        addressFamily,
                        layerData,
                        TL_INSPECT_REAUTH_PACKET,
                        packetDirection
                        );

      if (pendedPacket == NULL)
      {
         classifyOut->actionType = FWP_ACTION_BLOCK;
         classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
         goto Exit;
      }

      if (packetDirection == FWP_DIRECTION_INBOUND)
      {
         pendedPacket->ipSecProtected = IsSecureConnection(inFixedValues);
      }

      KeAcquireInStackQueuedSpinLock(
         &gConnListLock,
         &connListLockHandle
         );
      KeAcquireInStackQueuedSpinLock(
         &gPacketQueueLock,
         &packetQueueLockHandle
         );

      if (!gDriverUnloading)
      {
         signalWorkerThread = IsListEmpty(&gPacketQueue) &&
                              IsListEmpty(&gConnList);

         InsertTailList(&gPacketQueue, &pendedPacket->listEntry);
         pendedPacket = NULL; // ownership transferred

         classifyOut->actionType = FWP_ACTION_BLOCK;
         classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
      }
      else
      {
         //
         // Driver is being unloaded, permit any connect classify.
         //
         signalWorkerThread = FALSE;

         classifyOut->actionType = FWP_ACTION_PERMIT;
      }

      KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
      KeReleaseInStackQueuedSpinLock(&connListLockHandle);

      if (signalWorkerThread)
      {
         KeSetEvent(
            &gWorkerEvent, 
            0, 
            FALSE
            );
      }
   }

Exit:

   if (pendedPacket != NULL)
   {
      FreePendedPacket(pendedPacket);
   }
   if (pendedRecvAccept != NULL)
   {
      FreePendedPacket(pendedRecvAccept);
   }

   return;
}

#if (NTDDI_VERSION >= NTDDI_WIN7)
// Version-1 of function that notifies the callout that a filter invoking it has
// been added/deleted.
NTSTATUS 
	TLInspectALERecvAcceptNotify(
	__in FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	__in const GUID* filterKey,
	__inout FWPS_FILTER1* filter
	)

#else
NTSTATUS
	TLInspectALERecvAcceptNotify(
	IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	IN const GUID* filterKey,
	IN const FWPS_FILTER0* filter
	)

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
{
   UNREFERENCED_PARAMETER(notifyType);
   UNREFERENCED_PARAMETER(filterKey);
   UNREFERENCED_PARAMETER(filter);

   return STATUS_SUCCESS;
}


BOOLEAN IsLAN(ULONG ulRemoteAddress)
{
	BOOLEAN bRet = FALSE;
	unsigned char uc1 = 0;
	unsigned char uc2 = 0;

	if (0 == ulRemoteAddress)
	{
		return bRet;
	}
	uc1 = (unsigned char)(ulRemoteAddress>>24)&0xFF;
	uc2 = (unsigned char)(ulRemoteAddress>>16)&0xFF;

	if (uc1 == 192)
	{
		if (uc2 == 168)
		{
			bRet = TRUE;
		}
	}else if (uc1 == 10)
	{
		bRet = TRUE;
	}else if (uc1 == 172)
	{
		if (uc2 > 16 && uc2 < 31)
		{
			bRet = TRUE;
		}
	}



	return bRet;
}

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
	)

#else
void
	TLInspectTransportClassify(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const FWPS_FILTER0* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT0* classifyOut
	)
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
/* ++

   This is the classifyFn function for the Transport (v4 and v6) callout.
   packets (inbound or outbound) are ueued to the packet queue to be processed 
   by the worker thread.

-- */
{

   KLOCK_QUEUE_HANDLE connListLockHandle;
   KLOCK_QUEUE_HANDLE packetQueueLockHandle;

   TL_INSPECT_PENDED_PACKET* pendedPacket = NULL;
   FWP_DIRECTION packetDirection;

   ADDRESS_FAMILY addressFamily;
   FWPS_PACKET_INJECTION_STATE packetState;
   BOOLEAN signalWorkerThread;

   UNREFERENCED_PARAMETER(flowContext);
   UNREFERENCED_PARAMETER(filter);   

   //
   // We don't have the necessary right to alter the classify, exit.
   //
   if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
   {
      goto Exit;
   }

  ASSERT(layerData != NULL);

   //
   // We don't re-inspect packets that we've inspected earlier.
   //
   packetState = FwpsQueryPacketInjectionState0(
                     gInjectionHandle,
                     layerData,
                     NULL
                     );

   if ((packetState == FWPS_PACKET_INJECTED_BY_SELF) ||
       (packetState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF))
   {
      classifyOut->actionType = FWP_ACTION_PERMIT;
      goto Exit;
   }

   addressFamily = GetAddressFamilyForLayer(inFixedValues->layerId);

   packetDirection = 
      GetPacketDirectionForLayer(inFixedValues->layerId);

   if (packetDirection == FWP_DIRECTION_INBOUND)
   {
      if (IsAleClassifyRequired(inFixedValues, inMetaValues))
      {
         //
         // Inbound transport packets that are destined to ALE Recv-Accept 
         // layers, for initial authorization or reauth, should be inspected 
         // at the ALE layer. We permit it from Tranport here.
         //
         classifyOut->actionType = FWP_ACTION_PERMIT;
         goto Exit;
      }
      else
      {
         //
         // To be compatible with Vista's IpSec implementation, we must not
         // intercept not-yet-detunneled IpSec traffic.
         //
         FWPS_PACKET_LIST_INFORMATION0 packetInfo = {0};
         FwpsGetPacketListSecurityInformation0(
            layerData,
            FWPS_PACKET_LIST_INFORMATION_QUERY_IPSEC |
            FWPS_PACKET_LIST_INFORMATION_QUERY_INBOUND,
            &packetInfo
            );

         if (packetInfo.ipsecInformation.inbound.isTunnelMode &&
             !packetInfo.ipsecInformation.inbound.isDeTunneled)
         {
            classifyOut->actionType = FWP_ACTION_PERMIT;
            goto Exit;
         }
      }
   }

   pendedPacket = AllocateAndInitializePendedPacket(
                     inFixedValues,
                     inMetaValues,
                     addressFamily,
                     layerData,
                     TL_INSPECT_DATA_PACKET,
                     packetDirection
                     );

   if (pendedPacket == NULL)
   {
      classifyOut->actionType = FWP_ACTION_BLOCK;
      classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
      goto Exit;
   }

   //增加一个判断是否是局域网包的标志
   if (packetDirection == FWP_DIRECTION_INBOUND)
   {
	   pendedPacket->bLAN = IsLAN(inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32);
   } 
   else
   {
	   pendedPacket->bLAN = IsLAN(inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32);
   }
   

   KeAcquireInStackQueuedSpinLock(
      &gConnListLock,
      &connListLockHandle
      );
   KeAcquireInStackQueuedSpinLock(
      &gPacketQueueLock,
      &packetQueueLockHandle
      );

   if (!gDriverUnloading)
   {
      signalWorkerThread = IsListEmpty(&gPacketQueue) &&
                           IsListEmpty(&gConnList);

      InsertTailList(&gPacketQueue, &pendedPacket->listEntry);
      pendedPacket = NULL; // ownership transferred

      classifyOut->actionType = FWP_ACTION_BLOCK;
      classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
   }
   else
   {
      //
      // Driver is being unloaded, permit any connect classify.
      //
      signalWorkerThread = FALSE;

      classifyOut->actionType = FWP_ACTION_PERMIT;
   }

   KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
   KeReleaseInStackQueuedSpinLock(&connListLockHandle);

   if (signalWorkerThread)
   {
      KeSetEvent(
         &gWorkerEvent, 
         0, 
         FALSE
         );
   }

Exit:

   if (pendedPacket != NULL)
   {
      FreePendedPacket(pendedPacket);
   }

   return;
}

#if (NTDDI_VERSION >= NTDDI_WIN7)
// Version-1 of function that notifies the callout that a filter invoking it has
// been added/deleted.
NTSTATUS 
	TLInspectTransportNotify(
	__in FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	__in const GUID* filterKey,
	__inout FWPS_FILTER1* filter
	)

#else
NTSTATUS
	TLInspectTransportNotify(
	IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	IN const GUID* filterKey,
	IN const FWPS_FILTER0* filter
	)

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
{
   UNREFERENCED_PARAMETER(notifyType);
   UNREFERENCED_PARAMETER(filterKey);
   UNREFERENCED_PARAMETER(filter);

   return STATUS_SUCCESS;
}

void TLInspectInjectComplete(
   IN void* context,
   IN OUT NET_BUFFER_LIST* netBufferList,
   IN BOOLEAN dispatchLevel
   )
{
   TL_INSPECT_PENDED_PACKET* packet = context;

   UNREFERENCED_PARAMETER(dispatchLevel);   

   FwpsFreeCloneNetBufferList(netBufferList, 0);

   FreePendedPacket(packet);
}

NTSTATUS
TLInspectCloneReinjectOutbound(
   IN TL_INSPECT_PENDED_PACKET* packet
   )
/* ++

   This function clones the outbound net buffer list and reinject it back.

-- */
{
   NTSTATUS status = STATUS_SUCCESS;

   NET_BUFFER_LIST* clonedNetBufferList = NULL;
   FWPS_TRANSPORT_SEND_PARAMS sendArgs = {0};

   status = FwpsAllocateCloneNetBufferList(
               packet->netBufferList,
               NULL,
               NULL,
               0,
               &clonedNetBufferList
               );
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   sendArgs.remoteAddress = (UINT8*)(&packet->remoteAddr);
   sendArgs.remoteScopeId = packet->remoteScopeId;
   sendArgs.controlData = packet->controlData;
   sendArgs.controlDataLength = packet->controlDataLength;

   //
   // Send-inject the cloned net buffer list.
   //

   status = FwpsInjectTransportSendAsync(
               gInjectionHandle,
               NULL,
               packet->endpointHandle,
               0,
               &sendArgs,
               packet->addressFamily,
               packet->compartmentId,
               clonedNetBufferList,
               TLInspectInjectComplete,
               packet
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   clonedNetBufferList = NULL; // ownership transferred to the 
                               // completion function.

Exit:

   if (clonedNetBufferList != NULL)
   {
      FwpsFreeCloneNetBufferList(clonedNetBufferList, 0);
   }

   return status;
}

NTSTATUS
TLInspectCloneReinjectInbound(
   IN OUT TL_INSPECT_PENDED_PACKET* packet
   )
/* ++

   This function clones the inbound net buffer list and, if needed, 
   rebuild the IP header to remove the IpSec headers and receive-injects 
   the clone back to the tcpip stack.

-- */
{
   NTSTATUS status = STATUS_SUCCESS;

   NET_BUFFER_LIST* clonedNetBufferList = NULL;
   NET_BUFFER* netBuffer;
   ULONG nblOffset;

   //
   // For inbound net buffer list, we can assume it contains only one 
   // net buffer.
   //
   netBuffer = NET_BUFFER_LIST_FIRST_NB(packet->netBufferList);
   
   nblOffset = NET_BUFFER_DATA_OFFSET(netBuffer);

   //
   // The TCP/IP stack could have retreated the net buffer list by the 
   // transportHeaderSize amount; detect the condition here to avoid
   // retreating twice.
   //
   if (nblOffset != packet->nblOffset)
   {
      ASSERT(packet->nblOffset - nblOffset == packet->transportHeaderSize);
      packet->transportHeaderSize = 0;
   }

   //
   // Adjust the net buffer list offset to the start of the IP header.
   //
   NdisRetreatNetBufferDataStart(
      netBuffer,
      packet->ipHeaderSize + packet->transportHeaderSize,
      0,
      NULL
      );

   //
   // Note that the clone will inherit the original net buffer list's offset.
   //

   status = FwpsAllocateCloneNetBufferList(
               packet->netBufferList,
               NULL,
               NULL,
               0,
               &clonedNetBufferList
               );

   //
   // Undo the adjustment on the original net buffer list.
   //

   NdisAdvanceNetBufferDataStart(
      netBuffer,
      packet->ipHeaderSize + packet->transportHeaderSize,
      FALSE,
      NULL
      );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   if (packet->ipSecProtected)
   {
      //
      // When an IpSec protected packet is indicated to AUTH_RECV_ACCEPT or 
      // INBOUND_TRANSPORT layers, for performance reasons the tcpip stack
      // does not remove the AH/ESP header from the packet. And such 
      // packets cannot be recv-injected back to the stack w/o removing the
      // AH/ESP header. Therefore before re-injection we need to "re-build"
      // the cloned packet.
      // 
#if (NTDDI_VERSION >= NTDDI_WIN6SP1)

      status = FwpsConstructIpHeaderForTransportPacket(
                  clonedNetBufferList,
                  packet->ipHeaderSize,
                  packet->addressFamily,
                  (UINT8*)&packet->remoteAddr, 
                  (UINT8*)&packet->localAddr,  
                  packet->protocol,
                  0,
                  NULL,
                  0,
                  0,
                  NULL,
                  0,
                  0
                  );
#else
      ASSERT(FALSE); // Prior to Vista SP1, IP address needs to be updated 
                     // manually (including updating IP checksum).

      status = STATUS_NOT_IMPLEMENTED;
#endif

      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }
   }

   if (packet->completionContext != NULL)
   {
      ASSERT(packet->type == TL_INSPECT_CONNECT_PACKET);

      FwpsCompleteOperation(
         packet->completionContext,
         clonedNetBufferList
         );

      packet->completionContext = NULL;
   }

   status = FwpsInjectTransportReceiveAsync(
               gInjectionHandle,
               NULL,
               NULL,
               0,
               packet->addressFamily,
               packet->compartmentId,
               packet->interfaceIndex,
               packet->subInterfaceIndex,
               clonedNetBufferList,
               TLInspectInjectComplete,
               packet
               );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   clonedNetBufferList = NULL; // ownership transferred to the 
                               // completion function.

Exit:

   if (clonedNetBufferList != NULL)
   {
      FwpsFreeCloneNetBufferList(clonedNetBufferList, 0);
   }

   return status;
}

void
TlInspectCompletePendedConnection(
   IN OUT TL_INSPECT_PENDED_PACKET** pendedConnect,
   BOOLEAN permitTraffic
   )
/* ++

   This function completes the pended connection (inbound or outbound)
   with the inspection result.

-- */
{

   TL_INSPECT_PENDED_PACKET* pendedConnectLocal = *pendedConnect;

   if (pendedConnectLocal->direction == FWP_DIRECTION_OUTBOUND)
   {
      HANDLE completionContext = pendedConnectLocal->completionContext;

      pendedConnectLocal->authConnectDecision = 
         permitTraffic ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;

      //
      // For pended ALE_AUTH_CONNECT, FwpsCompleteOperation0 will trigger
      // a re-auth during which the inspection decision is to be returned.
      // Here we don't remove the pended entry from the list such that the
      // re-auth can find it along with the recorded inspection result.
      //
      pendedConnectLocal->completionContext = NULL;

      FwpsCompleteOperation(
         completionContext,
         NULL
         );

      *pendedConnect = NULL; // ownership transferred to the re-auth path.
   }
   else
   {
      if (!configPermitTraffic)
      {
         FreePendedPacket(pendedConnectLocal);
         *pendedConnect = NULL;
      }

      //
      // Permitted ALE_RECV_ACCEPT will pass thru and be processed by
      // TLInspectCloneReinjectInbound. FwpsCompleteOperation0 will be called
      // then when the net buffer list is cloned; after which the clone will
      // be recv-injected.
      //
   }
}

VOID MySleep(LONG msec)
{
#define DELAY_ONE_MICROSECOND 	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode,0,&my_interval);
}

BOOLEAN IsDelayInBound(IN TL_INSPECT_PENDED_PACKET* packet)
{
	BOOLEAN bRet = FALSE;

	if (packet->direction == FWP_DIRECTION_INBOUND)
	{
		PNET_BUFFER_LIST        netBufferList = NULL;
		PNET_BUFFER             netBuffer = NULL;
		PMDL                    mdl = NULL;
		DWORD                 dwCount = 0;
		KIRQL irq;
		PBYTE             va = NULL;

		netBufferList = packet->netBufferList;
		if (netBufferList == NULL)
			return bRet;

		netBuffer = NET_BUFFER_LIST_FIRST_NB( netBufferList );
		if (netBuffer == NULL)
			return bRet;

		mdl = NET_BUFFER_FIRST_MDL( netBuffer );

		for( ; mdl != NULL; mdl = mdl->Next)
		{
			dwCount += MmGetMdlByteCount( mdl );
			//va = (PBYTE)MmGetMdlVirtualAddress(mdl);
		}
		// 		KeAcquireSpinLock(&gFlowQueueLock, &irq);
		// 		gFlowInfo.dwDownTpye += dwCount;
		// 		KeReleaseSpinLock(&gFlowQueueLock, irq);

		DbgPrint("[DriverLife]: 接收dwDownTpyeWAN:%d,dwDownTpyeLAN:%d,dwLimitDown:%d,dwCount:%d\n", gFlowInfo.dwDownTpyeWAN, gFlowInfo.dwDownTpyeLAN, gFlowInfo.dwLimitDown, dwCount);
		KeAcquireSpinLock(&gFlowQueueLock, &irq);
		//DbgPrint("[DriverLife]: InBound LockIn\n");
		//区分包是外网的还是局域网的
		if (packet->bLAN)
		{
			//局域网的包
			
			gFlowInfo.dwDownTpyeLAN += dwCount;
			gFlowInfo.dwDownTpye += dwCount;
		} 
		else
		{
			//外网的包
			gFlowInfo.dwDownTpyeWAN += dwCount;
			gFlowInfo.dwDownTpye += dwCount;
		}

		if (gFlowInfo.dwLimitDown != 0)
		{
			if (gFlowInfo.dwLimitDown <= gFlowInfo.dwDownTpyeWAN)
			{
				gFlowInfo.dwDownTpyeWAN -= dwCount;
				gFlowInfo.dwDownTpye -= dwCount;
				
				//这个函数是线程里面执行的,
				bRet = TRUE;
			}
		}
		//DbgPrint("[DriverLife]: InBound LockOut\n");
		KeReleaseSpinLock(&gFlowQueueLock, irq);

	}

	return bRet;
}

BOOLEAN IsDelayOutBound(IN TL_INSPECT_PENDED_PACKET* packet)
{
	BOOLEAN bRet = FALSE;

	if (packet->direction == FWP_DIRECTION_OUTBOUND)
	{
		PNET_BUFFER_LIST        netBufferList = NULL;
		PNET_BUFFER             netBuffer = NULL;
		PMDL                    mdl = NULL;
		DWORD                 dwCount = 0;
		KIRQL irq;

		netBufferList = packet->netBufferList;
		if (netBufferList == NULL)
			return bRet;
		netBuffer = NET_BUFFER_LIST_FIRST_NB( netBufferList );
		if (netBuffer == NULL)
			return bRet;
		mdl = NET_BUFFER_FIRST_MDL( netBuffer );

		for( ; mdl != NULL; mdl = mdl->Next)
		{
			dwCount += MmGetMdlByteCount( mdl );
		}

// 		区分包是外网的还是局域网的
// 				if (packet->bLAN)
// 				{
// 					//局域网的包
// 					KeAcquireSpinLock(&gFlowQueueLock, &irq);
// 					gFlowInfo.dwUpTpyeLAN += dwCount;
// 					gFlowInfo.dwUpTpye += dwCount;
// 					KeReleaseSpinLock(&gFlowQueueLock, irq);
// 				} 
// 				else
// 				{
// 					//外网的包
// 					KeAcquireSpinLock(&gFlowQueueLock, &irq);
// 					gFlowInfo.dwUpTpyeWAN += dwCount;
// 					gFlowInfo.dwUpTpye += dwCount;
// 					KeReleaseSpinLock(&gFlowQueueLock, irq);
// 				}
// 		
// 		
// 		
// 				if (gFlowInfo.dwLimitUp != 0)
// 				{
// 					//只限制外网的流量
// 					if (gFlowInfo.dwLimitUp <= gFlowInfo.dwUpTpyeWAN)
// 					{
// 						KeAcquireSpinLock(&gFlowQueueLock, &irq);
// 						gFlowInfo.dwUpTpyeWAN -= dwCount;
// 						gFlowInfo.dwUpTpye -= dwCount;
// 						KeReleaseSpinLock(&gFlowQueueLock, irq);
// 						bRet = TRUE;
// 					}
// 				}
		DbgPrint("[DriverLife]: 发送dwUpTpyeWAN:%d,dwUpTpyeLAN:%d,dwLimitUp:%d,dwCount:%d\n", gFlowInfo.dwUpTpyeWAN, gFlowInfo.dwUpTpyeLAN, gFlowInfo.dwLimitUp, dwCount);
		KeAcquireSpinLock(&gFlowQueueLock, &irq);
		//DbgPrint("[DriverLife]: OutBound LockIn\n");
		if (gFlowInfo.dwLimitUp != 0 && gFlowInfo.dwLimitUp <= gFlowInfo.dwUpTpyeWAN/*dwUpTpye*/)
			bRet = TRUE;
		else
		{
			if (packet->bLAN)
				gFlowInfo.dwUpTpyeLAN += dwCount;
			else
				gFlowInfo.dwUpTpyeWAN += dwCount;
			gFlowInfo.dwUpTpye += dwCount;
		}
		//DbgPrint("[DriverLife]: OutBound LockOut\n");
		KeReleaseSpinLock(&gFlowQueueLock, irq);
	}

	return bRet;
}

void ClearLimit()
{
	PLIST_ENTRY le;
	KIRQL _irql;
	KIRQL irq;
	KeRaiseIrql(DISPATCH_LEVEL, &_irql);
//	KeAcquireSpinLock(&pro_spinlock, &irql);
	KeAcquireSpinLock(&gFlowQueueLock, &irq);
	gFlowInfo.dwUpTpye = 0;
	gFlowInfo.dwDownTpye = 0;
	gFlowInfo.dwDownTpyeLAN = 0;
	gFlowInfo.dwDownTpyeWAN = 0;
	gFlowInfo.dwUpTpyeLAN = 0;
	gFlowInfo.dwUpTpyeWAN = 0;

	KeReleaseSpinLock(&gFlowQueueLock, irq);
//	KeReleaseSpinLock(&pro_spinlock, irql);
	KeLowerIrql(_irql);
}

void ClearThread(IN void* pContext)
{
	LARGE_INTEGER timeout;
	timeout.QuadPart = -1 * 1000 * 1000 * 10;//负数表示从现在开始计数，KeWaitForSingleObject的timeout是100ns为单位的。

	//负数表示从现在开始计数，KeWaitForSingleObject的timeout是100ns为单位的。  
	do
	{
		KeDelayExecutionThread(KernelMode, FALSE, &timeout);
		//a = 0;
		ClearLimit();

	} while (!bStopThread);
	KeSetEvent(&ThreadCloseOK, (KPRIORITY)0, TRUE);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

void
TLInspectWorker(
   IN PVOID StartContext
   )
/* ++

   This worker thread waits for the connect and packet queue event when the 
   queues are empty; and it will be woken up when there are connects/packets 
   queued needing to be inspected. Once awaking, It will run in a loop to 
   complete the pended ALE classifies and/or clone-reinject packets back 
   until both queues are exhausted (and it will go to sleep waiting for more 
   work).

   The worker thread will end once it detected the driver is unloading.

-- */
{
   NTSTATUS status;

   TL_INSPECT_PENDED_PACKET* packet = NULL;
   LIST_ENTRY* listEntry;

   KLOCK_QUEUE_HANDLE packetQueueLockHandle;
   KLOCK_QUEUE_HANDLE connListLockHandle;

   UNREFERENCED_PARAMETER(StartContext);

   for(;;)
   {
      KeWaitForSingleObject(
         &gWorkerEvent,
         Executive, 
         KernelMode, 
         FALSE, 
         NULL
         );

      if (gDriverUnloading)
      {
         break;
      }

      configPermitTraffic = IsTrafficPermitted();

      listEntry = NULL;

      KeAcquireInStackQueuedSpinLock(
         &gConnListLock,
         &connListLockHandle
         );

      if (!IsListEmpty(&gConnList))
      {
         listEntry = gConnList.Flink;

         packet = CONTAINING_RECORD(
                           listEntry,
                           TL_INSPECT_PENDED_PACKET,
                           listEntry
                           );
         if (packet->direction == FWP_DIRECTION_INBOUND)
         {
            RemoveEntryList(&packet->listEntry);
         }

         //
         // Leave the pended ALE_AUTH_CONNECT in the connection list, it will
         // be processed and removed from the list during re-auth.
         //
      }

      KeReleaseInStackQueuedSpinLock(&connListLockHandle);

      if (listEntry == NULL)
      {
         //ASSERT(!IsListEmpty(&gPacketQueue));

         KeAcquireInStackQueuedSpinLock(
            &gPacketQueueLock,
            &packetQueueLockHandle
            );

         listEntry = RemoveHeadList(&gPacketQueue);

         packet = CONTAINING_RECORD(
                           listEntry,
                           TL_INSPECT_PENDED_PACKET,
                           listEntry
                           );

         KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
      }

      if (packet->type == TL_INSPECT_CONNECT_PACKET)
      {
		  //ExFreePoolWithTag(packet, TL_INSPECT_PENDED_PACKET_POOL_TAG);
		  packet = NULL;

//          TlInspectCompletePendedConnection(
//             &packet,
//             configPermitTraffic);
      }

	  do 
	  {
		  if ((packet != NULL) && configPermitTraffic)
		  {
			  if (packet->direction == FWP_DIRECTION_OUTBOUND)
			  {
				  //延时方案
// 				  if (IsDelayOutBound(packet))
// 					  MySleep(980);
// 				  status = TLInspectCloneReinjectOutbound(packet);

				  //丢包方案
				  if (IsDelayOutBound(packet))
					  break;
				  status = TLInspectCloneReinjectOutbound(packet);
			  }
			  else
			  {
				  //延时方案
//  				  if (IsDelayInBound(packet))
//  					  MySleep(200);
//  				  status = TLInspectCloneReinjectInbound(packet);

				  //丢包方案
				  if (IsDelayInBound(packet))
					  break;
				  status = TLInspectCloneReinjectInbound(packet);

			  }

			  if (NT_SUCCESS(status))
			  {
				  packet = NULL; // ownership transferred.
			  }

		  }

	  } while (FALSE);

      if (packet != NULL)
      {
         FreePendedPacket(packet);
		 packet = NULL;
      }

      KeAcquireInStackQueuedSpinLock(
         &gConnListLock,
         &connListLockHandle
         );
      KeAcquireInStackQueuedSpinLock(
         &gPacketQueueLock,
         &packetQueueLockHandle
         );

      if (IsListEmpty(&gConnList) && IsListEmpty(&gPacketQueue) &&
          !gDriverUnloading)
      {
         KeClearEvent(&gWorkerEvent);
      }

      KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
      KeReleaseInStackQueuedSpinLock(&connListLockHandle);
   }

   ASSERT(gDriverUnloading);

   while (!IsListEmpty(&gConnList))
   {
      packet = NULL;

      KeAcquireInStackQueuedSpinLock(
         &gConnListLock,
         &connListLockHandle
         );

      if (!IsListEmpty(&gConnList))
      {
         listEntry = gConnList.Flink;
         packet = CONTAINING_RECORD(
                           listEntry,
                           TL_INSPECT_PENDED_PACKET,
                           listEntry
                           );
      }

      KeReleaseInStackQueuedSpinLock(&connListLockHandle);

      if (packet != NULL)
      {
         TlInspectCompletePendedConnection(&packet, FALSE);
         ASSERT(packet == NULL);
      }
   }

   //
   // Discard all the pended packets if driver is being unloaded.
   //

   while (!IsListEmpty(&gPacketQueue))
   {
      packet = NULL;

      KeAcquireInStackQueuedSpinLock(
         &gPacketQueueLock,
         &packetQueueLockHandle
         );

      if (!IsListEmpty(&gPacketQueue))
      {
         listEntry = RemoveHeadList(&gPacketQueue);

         packet = CONTAINING_RECORD(
                           listEntry,
                           TL_INSPECT_PENDED_PACKET,
                           listEntry
                           );
      }

      KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
      
      if (packet != NULL)
      {
         FreePendedPacket(packet);
      }
   }

   PsTerminateSystemThread(STATUS_SUCCESS);

}
/************************************************************************************************************/



NTSTATUS
	MonitorCoInsertFlowContext(
	IN FLOW_DATA* flowContext)
{
	KLOCK_QUEUE_HANDLE lockHandle;
	NTSTATUS status;

	KeAcquireInStackQueuedSpinLock(&g_kFlowContextListLock, &lockHandle);

	// Catch the case where we disabled monitoring after we had intended to
	// associate the context to the flow so that we don't bugcheck due to
	// our driver being unloaded and then receiving a call for a particular
	// flow or leak the memory because we unloaded without freeing it.

	//DoTraceMessage(TRACE_FLOW_ESTABLISHED, "Creating flow for traffic.\r\n");

	InsertTailList(&g_lFlowContextList, &flowContext->listEntry);
	status = STATUS_SUCCESS;


	KeReleaseInStackQueuedSpinLock(&lockHandle);
	return status;
}

VOID
	MonitorCoRemoveFlowContext(
	IN FLOW_DATA* flowContext)
{
	KLOCK_QUEUE_HANDLE lockHandle;

	KeAcquireInStackQueuedSpinLock(&g_kFlowContextListLock, &lockHandle);

	RemoveEntryList(&flowContext->listEntry);

	KeReleaseInStackQueuedSpinLock(&lockHandle);
}

void
MonitorCoCleanupFlowContext(
   IN FLOW_DATA*  flowContext)
/*
Routine Description

    Called to cleanup a flow context on flow deletion.

Arguments
    [IN] FLOW_DATA*     flowContext -  Context associated with the flow now
                                       being deleted.

Return values

    None.

Notes


*/
{
   //
   // If we're already being deleted from the list then we mustn't try to 
   // remove ourselves here.
   //
   if (!flowContext->deleting)
   {
      MonitorCoRemoveFlowContext(flowContext);
   }

   if (flowContext->processPath)
   {
      ExFreePoolWithTag(flowContext->processPath, TAG_NAME_CALLOUT);
   }
   ExFreePoolWithTag(flowContext, TAG_NAME_CALLOUT);
}

UINT64
MonitorCoCreateFlowContext(
   IN const FWPS_INCOMING_VALUES* inFixedValues,
   IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   OUT UINT64* flowHandle)
/*
Routine Description

    Creates a flow context that is associated with the current flow

Arguments
    [IN] FWPS_CALLOUT_NOTIFY_TYPE        notifyType  -   Type of notification

    [IN] GUID*                  filterKey   -   Key of the filter that was
                                                added/deleted/modified.

    [IN] struct FWPS_FILTER_*  filter      -   pointer to the Filter itself.

Return values

    STATUS_SUCCESS or a specific error code.

Notes


*/
{
   FLOW_DATA*     flowContext = NULL;
   NTSTATUS       status;
   FWP_BYTE_BLOB* processPath;
   UINT32         index;

   if (!FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_PATH))
   {
      status = STATUS_NOT_FOUND;
      goto cleanup;
   }

   processPath = inMetaValues->processPath;

   //  Flow context is always created at the Flow established layer.

   // flowContext gets deleted in MonitorCoCleanupFlowContext 
   #pragma warning( suppress : 28197 )
   flowContext = ExAllocatePoolWithTag(NonPagedPool,
                                       sizeof(FLOW_DATA),
                                       TAG_NAME_CALLOUT);

   if (!flowContext)
   {
      return (UINT64) NULL;
   }

   RtlZeroMemory(flowContext, sizeof(FLOW_DATA));

   flowContext->deleting = FALSE;
   flowContext->flowHandle = inMetaValues->flowHandle;
   *flowHandle = flowContext->flowHandle;

   index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS;
   flowContext->localAddressV4 = inFixedValues->incomingValue[index].value.uint32;


   index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT;
   flowContext->localPort = inFixedValues->incomingValue[index].value.uint16;

   index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS;
   flowContext->remoteAddressV4 = inFixedValues->incomingValue[index].value.uint32;

   index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT;
   flowContext->remotePort = inFixedValues->incomingValue[index].value.uint16;

   index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL;
   flowContext->ipProto = inFixedValues->incomingValue[index].value.uint16;

   // flowContext->processPath gets deleted in MonitorCoCleanupFlowContext 
   #pragma warning( suppress : 28197 )
   flowContext->processPath = ExAllocatePoolWithTag(NonPagedPool,
                                                    processPath->size,
                                                    TAG_NAME_CALLOUT);
   flowContext->processID = inMetaValues->processId;
   if (!flowContext->processPath)
   {
      status = STATUS_NOT_FOUND;
      goto cleanup;
   }

   memcpy(flowContext->processPath, processPath->data, processPath->size);
  // DbgPrint("processPath: %ws  %d ", flowContext->processPath, processPath->size);
 //  DbgPrint("processPath: %ls \n", flowContext->processPath);
   status = MonitorCoInsertFlowContext(flowContext);

cleanup:

   if (!NT_SUCCESS(status) && flowContext)
   {
      MonitorCoCleanupFlowContext(flowContext);

      flowContext = NULL;
   }

   return (UINT64) flowContext;
}

NTSTATUS MonitorCoFlowEstablishedNotifyV4(
    IN  FWPS_CALLOUT_NOTIFY_TYPE        notifyType,
    IN  const GUID*             filterKey,
    IN  const FWPS_FILTER*     filter)
/*
Routine Description

    Notification routine that is called whenever a filter is added, deleted or
    modified on the layer that our callout is registered against.

Arguments
    [IN] FWPS_CALLOUT_NOTIFY_TYPE       notifyType  -   Type of notification

    [IN] GUID*                  filterKey   -   Key of the filter that was
                                                added/deleted/modified.

    [IN] struct FWPS_FILTER_*  filter      -   pointer to the Filter itself.

Return values

    STATUS_SUCCESS or a specific error code.

Notes


*/
{
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    switch (notifyType)
    {
    case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
        //DoTraceMessage(TRACE_LAYER_NOTIFY, "Filter Added to Flow Established layer.\r\n");

       break;
    case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
        //DoTraceMessage(TRACE_LAYER_NOTIFY, "Filter Deleted from Flow Established layer.\r\n");
       break;
    }

    return STATUS_SUCCESS;
}


#if(NTDDI_VERSION >= NTDDI_WIN7)
NTSTATUS MonitorCoFlowEstablishedCalloutV4(
   IN const FWPS_INCOMING_VALUES* inFixedValues,
   IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   IN VOID* packet,
   IN const void* classifyContext,
   IN const FWPS_FILTER* filter,
   IN UINT64 flowContext,
   OUT FWPS_CLASSIFY_OUT* classifyOut)

#else if(NTDDI_VERSION < NTDDI_WIN7)
NTSTATUS MonitorCoFlowEstablishedCalloutV4(
   IN const FWPS_INCOMING_VALUES* inFixedValues,
   IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   IN VOID* packet,
   IN const FWPS_FILTER* filter,
   IN UINT64 flowContext,
   OUT FWPS_CLASSIFY_OUT* classifyOut)
#endif
/*
Routine Description

   Our flow established callout for Ipv4 traffic.

Arguments
   [IN] const FWPS_INCOMING_VALUES* inFixedValues -  The fixed values passed in
                                                      based on the traffic.
   [IN] const FWPS_INCOMING_METADATA_VALUES* inMetaValues - Metadata the
                                                             provides additional
                                                             information about the
                                                             connection.
   [IN] VOID* packet - Depending on the layer and protocol this can be NULL or a
                       layer specific type.
   [IN] const FWPS_FILTER* filter - The filter that has specified this callout.

   [IN] UINT64 flowContext - Flow context associated with a flow
   [OUT] FWPS_CLASSIFY_OUT* classifyOut - Out parameter that is used to inform
                                           the filter engine of our decision

Return values

    STATUS_SUCCESS or a specific error code.

Notes


*/
{

   NTSTATUS status = STATUS_SUCCESS;
   UINT64   flowHandle;
   UINT64   flowContextLocal;

   UNREFERENCED_PARAMETER(packet);
   #if(NTDDI_VERSION >= NTDDI_WIN7)
   UNREFERENCED_PARAMETER(classifyContext);
   #endif
   UNREFERENCED_PARAMETER(filter);
   UNREFERENCED_PARAMETER(flowContext);


      flowContextLocal = MonitorCoCreateFlowContext(inFixedValues, inMetaValues, &flowHandle);

      if (!flowContextLocal)
      {
         classifyOut->actionType = FWP_ACTION_CONTINUE;
         goto cleanup;
      }

	  status = FwpsFlowAssociateContext(flowHandle,
		  FWPS_LAYER_INBOUND_TRANSPORT_V4,
		  gInboundTlCalloutIdV4,
		  flowContextLocal);


// 	  if (inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION].value.uint32 == FWP_DIRECTION_OUTBOUND)
// 	  {
// 		  status = FwpsFlowAssociateContext(flowHandle,
// 			  FWPS_LAYER_OUTBOUND_TRANSPORT_V4,
// 			  gOutboundTlCalloutIdV4,
// 			  flowContextLocal);
// 	  }else if (inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION].value.uint32 == FWP_DIRECTION_INBOUND)
// 	  {
// 		  status = FwpsFlowAssociateContext(flowHandle,
// 			  FWPS_LAYER_INBOUND_TRANSPORT_V4,
// 			  gInboundTlCalloutIdV4,
// 			  flowContextLocal);
// 	  }else
// 		  status = 0xc0000006;

      if (!NT_SUCCESS(status))
      {
         classifyOut->actionType = FWP_ACTION_CONTINUE;
         goto cleanup;
      }

   classifyOut->actionType = FWP_ACTION_PERMIT;

cleanup:

   return status;
}

VOID MonitorCoStreamFlowDeletion(
	IN UINT16 layerId,
	IN UINT32 calloutId,
	IN UINT64 flowContext)
{
	FLOW_DATA** flowData;
	UINT64* flow;

	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);

	flow = &flowContext;
	flowData = ((FLOW_DATA**)flow);

	MonitorCoCleanupFlowContext(*flowData);
}




