#pragma once
#include "FreshyCalls/freshycalls.hpp"
#include <DbgHelp.h>
#pragma comment (lib, "Dbghelp.lib")

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_RANDOM_ACCESS 0x00000800
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeparation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	_SystemPowerInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS;

typedef struct __SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	__UNICODE_STRING ImageName;
	LONG BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} _SYSTEM_PROCESS_INFORMATION, * _PSYSTEM_PROCESS_INFORMATION;


typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	__UNICODE_STRING* ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
     (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
     (p)->RootDirectory = r; \
     (p)->Attributes = a; \
     (p)->ObjectName = n; \
     (p)->SecurityDescriptor = s; \
     (p)->SecurityQualityOfService = NULL; \
}
typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _IO_STATUS_BLOCK {
	ULONG Status;
	ULONG Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef enum {
	PSS_CAPTURE_NONE,
	PSS_CAPTURE_VA_CLONE,
	PSS_CAPTURE_RESERVED_00000002,
	PSS_CAPTURE_HANDLES,
	PSS_CAPTURE_HANDLE_NAME_INFORMATION,
	PSS_CAPTURE_HANDLE_BASIC_INFORMATION,
	PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION,
	PSS_CAPTURE_HANDLE_TRACE,
	PSS_CAPTURE_THREADS,
	PSS_CAPTURE_THREAD_CONTEXT,
	PSS_CAPTURE_THREAD_CONTEXT_EXTENDED,
	PSS_CAPTURE_RESERVED_00000400,
	PSS_CAPTURE_VA_SPACE,
	PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION,
	PSS_CAPTURE_IPT_TRACE,
	PSS_CAPTURE_RESERVED_00004000,
	PSS_CREATE_BREAKAWAY_OPTIONAL,
	PSS_CREATE_BREAKAWAY,
	PSS_CREATE_FORCE_BREAKAWAY,
	PSS_CREATE_USE_VM_ALLOCATIONS,
	PSS_CREATE_MEASURE_PERFORMANCE,
	PSS_CREATE_RELEASE_SECTION
} PSS_CAPTURE_FLAGS;
