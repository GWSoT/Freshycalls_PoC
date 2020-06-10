#pragma once
#include <Windows.h>

typedef struct ___ANSI_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PCHAR  Buffer;
} __ANSI_STRING;

typedef struct ___UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} __UNICODE_STRING;

typedef struct ___RTL_DRIVE_LETTER_CURDIR {
  USHORT Flags;
  USHORT Length;
  ULONG TimeStamp;
  __UNICODE_STRING DosPath;
} __RTL_DRIVE_LETTER_CURDIR, *__PRTL_DRIVE_LETTER_CURDIR;

typedef struct __RTL_USER_PROCESS_PARAMETERS {
  ULONG MaximumLength;
  ULONG Length;
  ULONG Flags;
  ULONG DebugFlags;
  PVOID ConsoleHandle;
  ULONG ConsoleFlags;
  HANDLE StdInputHandle;
  HANDLE StdOutputHandle;
  HANDLE StdErrorHandle;
  __UNICODE_STRING CurrentDirectoryPath;
  HANDLE CurrentDirectoryHandle;
  __UNICODE_STRING DllPath;
  __UNICODE_STRING ImagePathName;
  __UNICODE_STRING CommandLine;
  PVOID Environment;
  ULONG StartingPositionLeft;
  ULONG StartingPositionTop;
  ULONG Width;
  ULONG Height;
  ULONG CharWidth;
  ULONG CharHeight;
  ULONG ConsoleTextAttributes;
  ULONG WindowFlags;
  ULONG ShowWindowFlags;
  __UNICODE_STRING WindowTitle;
  __UNICODE_STRING DesktopName;
  __UNICODE_STRING ShellInfo;
  __UNICODE_STRING RuntimeData;
  __RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[20];
} __RTL_USER_PROCESS_PARAMETERS, *__PRTL_USER_PROCESS_PARAMETERS;

typedef struct ___LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  __UNICODE_STRING FullDllName;
  __UNICODE_STRING BaseDllName;
  ULONG Flags;
  USHORT LoadCount;
  USHORT TlsIndex;
  union {
	LIST_ENTRY HashLinks;
	struct {
	  PVOID SectionPointer;
	  ULONG CheckSum;
	};
  };
  union {
	ULONG TimeDateStamp;
	PVOID LoadedImports;
  };
  PVOID EntryPointActivationContext;
  PVOID PatchInformation;
} __LDR_DATA_TABLE_ENTRY, *__PLDR_DATA_TABLE_ENTRY;

typedef struct ___PEB_LDR_DATA {
  ULONG Length;
  BOOLEAN Initialized;
  HANDLE SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID EntryInProgress;
  BOOLEAN ShutdownInProgress;
  HANDLE ShutdownThreadId;
} __PEB_LDR_DATA, *__PPEB_LDR_DATA;

typedef struct ___PEB_FREE_BLOCK {
  struct ___PEB_FREE_BLOCK *Next;
  ULONG Size;
} __PEB_FREE_BLOCK, *__PPEB_FREE_BLOCK;

typedef struct ___PEB {
  BOOLEAN InheritedAddressSpace;
  BOOLEAN ReadImageFileExecOptions;
  BOOLEAN BeingDebugged;
  BOOLEAN Spare;
  HANDLE Mutant;
  PVOID ImageBaseAddress;
  __PPEB_LDR_DATA Ldr;
  __PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID SubSystemData;
  PVOID ProcessHeap;
  PVOID FastPebLock;
  PVOID FastPebLockRoutine;
  PVOID FastPebUnlockRoutine;
  ULONG EnvironmentUpdateCount;
  PVOID *KernelCallbackTable;
  PVOID EventLogSection;
  PVOID EventLog;
  __PPEB_FREE_BLOCK FreeList;
  ULONG TlsExpansionCounter;
  PVOID TlsBitmap;
  ULONG TlsBitmapBits[2];
  PVOID ReadOnlySharedMemoryBase;
  PVOID ReadOnlySharedMemoryHeap;
  PVOID *ReadOnlyStaticServerData;
  PVOID AnsiCodePageData;
  PVOID OemCodePageData;
  PVOID UnicodeCaseTableData;
  ULONG NumberOfProcessors;
  ULONG NtGlobalFlag;
  BYTE Spare2[4];
  LARGE_INTEGER CriticalSectionTimeout;
  ULONG HeapSegmentReserve;
  ULONG HeapSegmentCommit;
  ULONG HeapDeCommitTotalFreeThreshold;
  ULONG HeapDeCommitFreeBlockThreshold;
  ULONG NumberOfHeaps;
  ULONG MaximumNumberOfHeaps;
  PVOID **ProcessHeaps;
  PVOID GdiSharedHandleTable;
  PVOID ProcessStarterHelper;
  PVOID GdiDCAttributeList;
  PVOID LoaderLock;
  ULONG OSMajorVersion;
  ULONG OSMinorVersion;
  ULONG OSBuildNumber;
  ULONG OSPlatformId;
  ULONG ImageSubSystem;
  ULONG ImageSubSystemMajorVersion;
  ULONG ImageSubSystemMinorVersion;
  ULONG GdiHandleBuffer[22];
  ULONG PostProcessInitRoutine;
  ULONG TlsExpansionBitmap;
  BYTE TlsExpansionBitmapBits[80];
  ULONG SessionId;
} __PEB, *__PPEB;

typedef LONG KPRIORITY;

typedef struct ___PROCESS_BASIC_INFORMATION {
  NTSTATUS ExitStatus;
  __PPEB PebBaseAddress;
  ULONG_PTR AffinityMask;
  KPRIORITY BasePriority;
  HANDLE UniqueProcessId;
  HANDLE InheritedFromUniqueProcessId;
} __PROCESS_BASIC_INFORMATION, *__PPROCESS_BASIC_INFORMATION;
