---
layout: post
title: Stealthier communications & Port Knocking via Windows Filtering Platform (WFP)
date: 2019-06-05 13:30:07
categories: posts
en: true
description: Example of how WFP can be used to communicate with an infected machine
keywords: "Port Knocking, Windows Filtering Platform, Malware, RedTeam, Red Team, WPF"
authors:
    - X-C3LL
---
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
One of the key points of improvement that can be identified during an exercise between Red Team and Blue Team is the effectiveness in identifying compromised machines and eradicating deployed backdoors. A common problem we have found is that the Blue Team focuses its analysis only on those machines where high activity has been detected, leaving aside those with which the attacker has been able to interact but has done nothing "remarkable".

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
To detect this type of problem, in our case it is common to leave __"clean boxes"__ where a backdoor is simply implanted that allows, once the DFIR is finished by the Blue Team, to ensure persistence and retake control of the infrastructure. By "clean boxes" we mean those that are not used for pivoting or active use during the intrusion. Leaving behind this compromised machines, as a kind of canary, it is possible to detect if Blue Team has been able to trace all the machines the Red Team has had access to, or if there are blind spots in the detection that need to be remedied.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
When the backdoor is implanted, it remains in hibernation mode, without any type of communication with the outside. It simply executes the necessary actions to persist in the host waiting to pass from "hibernation" mode to "active" mode. How do we tell the backdoor to activate? That's where __Windows Filtering Platform__ comes in.


## 0x00 Windows Filtering Platform (WFP)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Quoting official documentation:

> _Windows Filtering Platform (WFP) is a set of API and system services that provide a platform for creating network filtering applications. The WFP API allows developers to write code that interacts with the packet processing that takes place at several layers in the networking stack of the operating system. Network data can be filtered and also modified before it reaches its destination._

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Our backdoor instead of leaving some kind of port to listen to receive a packet that triggers some action (for example "switch to active mode" or anything else) what it will do is analyze, through the WFP APIs, the events of dropped UDP packets. In this way, without having to leave a suspicious listening socket, we can communicate with the backdoor. Of course there are tons of other approachs to accomplish this.


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The MSDN has a [great example](https://docs.microsoft.com/es-es/windows/desktop/FWP/displaying-net-events) of how we can snoop around net events:

```c
#include <windows.h>
#include <fwpmtypes.h>
#include <fwpmu.h>
#include <stdio.h>

#pragma comment (lib, "fwpuclnt.lib")

#define EXIT_ON_ERROR(err) if((err) != ERROR_SUCCESS) {goto CLEANUP;}

//#pragma comment (lib, "fwpuclnt.lib")

DWORD InitFilterConditions(
         __in_opt PCWSTR appPath,
         __in_opt const SOCKADDR* localAddr,
         __in_opt UINT8 ipProtocol,
         __in UINT32 numCondsIn,
         __out_ecount_part(numCondsIn, *numCondsOut) FWPM_FILTER_CONDITION0* conds,
         __out UINT32* numCondsOut,
         __deref_out FWP_BYTE_BLOB** appId
         )
{
   *numCondsOut = 0;
   return ERROR_SUCCESS;
}


DWORD FindRecentEvents(
         __in HANDLE engine,
         __in_opt PCWSTR appPath,
         __in_opt const SOCKADDR* localAddr,
         __in_opt UINT8 ipProtocol,
         __in UINT32 seconds,
         __deref_out_ecount(*numEvents) FWPM_NET_EVENT0*** events,
         __out UINT32* numEvents
         )
{
   DWORD result = ERROR_SUCCESS;
   FWPM_NET_EVENT_ENUM_TEMPLATE0 enumTempl;
   ULARGE_INTEGER ulTime;
   FWPM_FILTER_CONDITION0 conds[4];
   UINT32 numConds;
   FWP_BYTE_BLOB* appBlob = NULL;
   HANDLE enumHandle = NULL;

   memset(&enumTempl, 0, sizeof(enumTempl));

   // Use the current time as the end time of the window.
   GetSystemTimeAsFileTime(&(enumTempl.endTime));

   // Subtract the number of seconds specified by the caller to find the start
   // time.
   ulTime.LowPart = enumTempl.endTime.dwLowDateTime;
   ulTime.HighPart = enumTempl.endTime.dwHighDateTime;
   ulTime.QuadPart -= seconds * 10000000ui64;
   enumTempl.startTime.dwLowDateTime = ulTime.LowPart;
   enumTempl.startTime.dwHighDateTime = ulTime.HighPart;

   result = InitFilterConditions(
               appPath,
               &localAddr,
               ipProtocol,
               ARRAYSIZE(conds),
               conds,
               &numConds,
               &appBlob
               );
   EXIT_ON_ERROR(result);

   enumTempl.numFilterConditions = numConds;
   if (numConds > 0)
   {
      enumTempl.filterCondition = conds;
   }

   result = FwpmNetEventCreateEnumHandle0(
               engine,
               &enumTempl,
               &enumHandle
               );
   EXIT_ON_ERROR(result);

   result = FwpmNetEventEnum0(
               engine,
               enumHandle,
               INFINITE,
               events,
               numEvents
               );
   EXIT_ON_ERROR(result);

CLEANUP:
   FwpmNetEventDestroyEnumHandle0(engine, enumHandle);
   FwpmFreeMemory0((void**)&appBlob);
   return result;
}

DWORD wmain(int argc,
            wchar_t* argv[])
{
   UNREFERENCED_PARAMETER(argc);
   UNREFERENCED_PARAMETER(argv);
   
   HANDLE engineHandle = 0;
   FWPM_NET_EVENT0** events = NULL, *event;
   UINT32 numEvents = 0, i;
   FILETIME ft;
   SYSTEMTIME st;
   static const char* const types[] =
   {
      "FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE",
      "FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE",
      "FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE",
      "FWPM_NET_EVENT_TYPE_CLASSIFY_DROP",
      "FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP"
   };
   const char* type;
   
   // Use dynamic sessions for efficiency and safety:
   //  - All objects associated with the dynamic session are deleted with one call.
   //  - Filtering policy objects are deleted even when the application crashes. 
   FWPM_SESSION0 session;
   memset(&session, 0, sizeof(session));
   session.flags = FWPM_SESSION_FLAG_DYNAMIC;

   DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engineHandle);
   if (ERROR_SUCCESS == result)
   {
        result = FindRecentEvents(
         engineHandle,
         0,
         0,
         0,
         100,
         &events,
         &numEvents
         );
   }

   if (numEvents == 0)
   {
      printf("No events matched.\n");
   }
   else
   {
      printf("Matching events:\n");

      for (i = 0; i < numEvents; ++i)
      {
         event = events[i];

         FileTimeToLocalFileTime(&(event->header.timeStamp), &ft);
         FileTimeToSystemTime(&ft, &st);

         type = (event->type < ARRAYSIZE(types)) ? types[event->type]
                                                 : "<unknown>";

         printf(
            "   %04hu/%02hu/%02hu:%02hu:%02hu:%02hu.%03hu - %s\n",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond,
            st.wMilliseconds,
            type
            );
      }
   }
   return result;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
This fragment of code is perfect to use as a base template to build our functionality. Let's play! __:)__ 


## 0x01 Playing with events

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The __FWPM_NET_EVENT0__ struct contains next fields:

```c
typedef struct FWPM_NET_EVENT0_ {
  FWPM_NET_EVENT_HEADER0 header;
  FWPM_NET_EVENT_TYPE    type;
  union {
    FWPM_NET_EVENT_IKEEXT_MM_FAILURE0 *ikeMmFailure;
    FWPM_NET_EVENT_IKEEXT_QM_FAILURE0 *ikeQmFailure;
    FWPM_NET_EVENT_IKEEXT_EM_FAILURE0 *ikeEmFailure;
    FWPM_NET_EVENT_CLASSIFY_DROP0     *classifyDrop;
    FWPM_NET_EVENT_IPSEC_KERNEL_DROP0 *ipsecDrop;
    FWPM_NET_EVENT_IPSEC_DOSP_DROP0   *idpDrop;
  };
} FWPM_NET_EVENT0;
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
And the __header__ struct:
```c
typedef struct FWPM_NET_EVENT_HEADER0_ {
  FILETIME       timeStamp;
  UINT32         flags;
  FWP_IP_VERSION ipVersion;
  UINT8          ipProtocol;
  union {
    UINT32           localAddrV4;
    FWP_BYTE_ARRAY16 localAddrV6;
  };
  union {
    UINT32           remoteAddrV4;
    FWP_BYTE_ARRAY16 remoteAddrV6;
  };
  UINT16         localPort;
  UINT16         remotePort;
  UINT32         scopeId;
  FWP_BYTE_BLOB  appId;
  SID            *userId;
} FWPM_NET_EVENT_HEADER0;
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As we can see, it is easy to retrieve the key information from the event, so we can know what port was hitted (and what was the remote address the package came from). We can display this information with a minimal modification from previous code snippet:


```c
/* Based on https://docs.microsoft.com/es-es/windows/desktop/FWP/displaying-net-events */


#include <windows.h>
#include <fwpmtypes.h>
#include <fwpmu.h>
#include <stdio.h>
#include <winsock.h>

#pragma comment (lib, "fwpuclnt.lib")
#pragma comment (lib, "Ws2_32.lib")

#define EXIT_ON_ERROR(err) if((err) != ERROR_SUCCESS) {goto CLEANUP;}


FILETIME ft;


DWORD InitFilterConditions(
	__in_opt PCWSTR appPath,
	__in_opt const SOCKADDR* localAddr,
	__in_opt UINT8 ipProtocol,
	__in UINT32 numCondsIn,
	__out_ecount_part(numCondsIn, *numCondsOut) FWPM_FILTER_CONDITION0* conds,
	__out UINT32* numCondsOut,
	__deref_out FWP_BYTE_BLOB** appId
)
{
	*numCondsOut = 0;
	return ERROR_SUCCESS;
}


DWORD FindRecentEvents(
	__in HANDLE engine,
	__in_opt PCWSTR appPath,
	__in_opt const SOCKADDR* localAddr,
	__in_opt UINT8 ipProtocol,
	__in UINT32 seconds,
	__deref_out_ecount(*numEvents) FWPM_NET_EVENT0*** events,
	__out UINT32* numEvents
)
{
	DWORD result = ERROR_SUCCESS;
	FWPM_NET_EVENT_ENUM_TEMPLATE0 enumTempl;
	ULARGE_INTEGER ulTime;
	FWPM_FILTER_CONDITION0 conds[4];
	UINT32 numConds;
	FWP_BYTE_BLOB* appBlob = NULL;
	HANDLE enumHandle = NULL;

	memset(&enumTempl, 0, sizeof(enumTempl));

	// Use the current time as the end time of the window.
	GetSystemTimeAsFileTime(&(enumTempl.endTime));

	// Subtract the number of seconds specified by the caller to find the start
	// time.
	ulTime.LowPart = enumTempl.endTime.dwLowDateTime;
	ulTime.HighPart = enumTempl.endTime.dwHighDateTime;
	ulTime.QuadPart -= seconds * 10000000ui64;
	enumTempl.startTime.dwLowDateTime = ulTime.LowPart;
	enumTempl.startTime.dwHighDateTime = ulTime.HighPart;

	result = InitFilterConditions(
		appPath,
		&localAddr,
		ipProtocol,
		ARRAYSIZE(conds),
		conds,
		&numConds,
		&appBlob
	);
	EXIT_ON_ERROR(result);

	enumTempl.numFilterConditions = numConds;
	if (numConds > 0)
	{
		enumTempl.filterCondition = conds;
	}

	result = FwpmNetEventCreateEnumHandle0(
		engine,
		&enumTempl,
		&enumHandle
	);
	EXIT_ON_ERROR(result);

	result = FwpmNetEventEnum0(
		engine,
		enumHandle,
		INFINITE,
		events,
		numEvents
	);
	EXIT_ON_ERROR(result);

CLEANUP:
	FwpmNetEventDestroyEnumHandle0(engine, enumHandle);
	FwpmFreeMemory0((void**)&appBlob);
	return result;
}

void detectHit(void) {
	struct in_addr rinaddr;
	HANDLE engineHandle = 0;
	FWPM_NET_EVENT0** events = NULL, *event;
	UINT32 numEvents = 0, i;


	static const char* const types[] =
	{
	   "FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE",
	   "FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE",
	   "FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE",
	   "FWPM_NET_EVENT_TYPE_CLASSIFY_DROP",
	   "FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP"
	};
	const char* type;

	// Use dynamic sessions for efficiency and safety:
	//  - All objects associated with the dynamic session are deleted with one call.
	//  - Filtering policy objects are deleted even when the application crashes. 
	FWPM_SESSION0 session;
	memset(&session, 0, sizeof(session));
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engineHandle);
	if (ERROR_SUCCESS == result)
	{
		result = FindRecentEvents(
			engineHandle,
			0,
			0,
			0,
			100,
			&events,
			&numEvents
		);
	}

	if (numEvents != 0)
	{
		for (i = 0; i < numEvents; ++i)
		{
			event = events[i];


			type = (event->type < ARRAYSIZE(types)) ? types[event->type]
				: "<unknown>";

			if (event->header.ipVersion == FWP_IP_VERSION_V4 && event->header.ipProtocol == IPPROTO_UDP
				&& ( event->header.timeStamp.dwHighDateTime > ft.dwHighDateTime 
					|| ( event->header.timeStamp.dwHighDateTime == ft.dwHighDateTime && event->header.timeStamp.dwLowDateTime > ft.dwLowDateTime )
					)
				)
			{
				rinaddr.s_addr = htonl(event->header.remoteAddrV4);
				ft.dwHighDateTime = event->header.timeStamp.dwHighDateTime;
				ft.dwLowDateTime = event->header.timeStamp.dwLowDateTime;
				printf("[%s] - %d - %d\n", inet_ntoa(rinaddr), event->header.localPort, event->header.remotePort);
			}
		}
	}
}


int main(int argc, char ** argv[]) {
	ft.dwHighDateTime = 0;
	ft.dwLowDateTime = 0;
	for (;;) {
		detectHit();
		Sleep(1000);
	}
	return 0;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Running a nmap with -sU:
```
PS D:\Debug> .\WPM_PoC.exe
[192.168.252.197] - 5050 - 58982
[192.168.252.197] - 1900 - 58982
[192.168.252.197] - 3702 - 58982
[192.168.252.197] - 123 - 58982
(...)
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
It's trivial to retrieve the remote and local port, and the remote IP, from the event. We can use this information to build the triggers needed, for example, swaping from "hibernation mode" to "active mode" when a particular port sequence is detected (building a __Port Knocking__ engine this way). Or, another example, we can trigger predefined actions based on the packet source port. The source port can be set via Scapy, for example:

```python
from scapy.all import *

send(IP(dst="192.168.252.1")/UDP(dport=123,sport=666)/Raw(load="Use stealthier packet in a real operation, pls"))
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
With a simple switch we can evaluate what action to perform:

```c
(...)
if (event->header.localPort == 123) {
	switch(event->header.remotePort) {
		case 1337:
			printf("COMMAND: 1337 - Activate Backdoor\n");
			break;
		case 666:
			printf("COMMAND: 666 - Reverse Shell\n");
			break;
		default:
			break;
	}
}
(...)
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
And testing it with scapy:
```
PS D:\Debug> .\WPM_PoC.exe
COMMAND: 1337 - Activate Backdoor
COMMAND: 666 - Reverse Shell
(...)
```


## 0x02 Conclusions

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
I encourage you to play a bit with the Windows Filtering Platform in order to build defensive and offensive toys. If you find useful this article, or wanna point me to an error or a typo, feel free to contact me at twitter [https://twitter.com/TheXC3LL](@TheXC3LL).
