#pragma once

#include <ntdlllib/csrss.h>
#include <Windows.h>

namespace ntdlllib
{
	typedef void (NTAPI* pfRtlInitAnsiString)(PANSI_STRING DestinationString, PCSZ SourceString);
	typedef NTSTATUS(NTAPI* pfRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

	/*
		General API
	*/
	typedef NTSTATUS (NTAPI* pfNtClose)(IN HANDLE Handle);
	typedef NTSTATUS (NTAPI* pfNtQueryObject)(
		IN HANDLE					ObjectHandle,
		IN OBJECT_INFORMATION_CLASS	ObjectInformationClass,
		OUT PVOID					ObjectInformation,
		IN ULONG					ObjectInformationLength,
		OUT PULONG					ReturnLength OPTIONAL
		);
	typedef NTSTATUS (NTAPI* pfNtSetSystemInformation)(
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		IN PVOID					SystemInformation,
		IN ULONG					SystemInformationLength);
	typedef NTSTATUS (NTAPI* pfNtQuerySystemInformation)(
		__in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
		__inout    PVOID					SystemInformation,
		__in       ULONG					SystemInformationLength,
		__out_opt  PULONG					ReturnLength
		);
	typedef NTSTATUS(NTAPI * pfRtlGetVersion)(
		IN OUT PRTL_OSVERSIONINFOEXW  lpVersionInformation
		);

	/*
		DLL API
	*/
	typedef NTSTATUS(NTAPI* pfLdrLoadDll)(
		IN PWCHAR               PathToFile OPTIONAL,
		IN PULONG               Flags OPTIONAL,
		IN PUNICODE_STRING      ModuleFileName,
		OUT PHANDLE             ModuleHandle
		);
	typedef NTSTATUS(NTAPI* pfLdrGetDllHandle)(
		IN PWORD				pwPath OPTIONAL,
		IN PVOID				Unused OPTIONAL,
		IN PUNICODE_STRING		ModuleFileName,
		OUT PHANDLE				ModuleHandle
		);
	typedef NTSTATUS(NTAPI* pfLdrGetProcedureAddress)(IN HMODULE ModuleHandle, IN PANSI_STRING FunctionName OPTIONAL, IN WORD Ordinal OPTIONAL, OUT PVOID* FunctionAddress);

	/*
		Process API
	*/
	typedef NTSTATUS(NTAPI* pfNtOpenThread)(
		OUT PHANDLE ThreadHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN PCLIENT_ID ClientId
		);
	typedef NTSTATUS(NTAPI* pfNtQueryInformationThread)(
		IN HANDLE ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		IN OUT PVOID ThreadInformation,
		IN ULONG ThreadInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);

	typedef NTSTATUS(NTAPI* pfNtQueryInformationProcess)(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);
	typedef NTSTATUS(NTAPI* pfRtlSetCurrentDirectory_U)(const UNICODE_STRING* dir);
	typedef ULONG(NTAPI* pfRtlGetCurrentDirectory_U)(ULONG buflen, LPWSTR buf);
	typedef NTSTATUS(NTAPI* pfNtCreateToken)(
		OUT PHANDLE				TokenHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		IN TOKEN_TYPE			Type,
		IN PLUID				AuthenticationId,
		IN PLARGE_INTEGER		ExpirationTime,
		IN PTOKEN_USER			User,
		IN PTOKEN_GROUPS		Groups,
		IN PTOKEN_PRIVILEGES	Privileges,
		IN PTOKEN_OWNER			Owner,
		IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
		IN PTOKEN_DEFAULT_DACL	DefaultDacl,
		IN PTOKEN_SOURCE		Source
		);
	typedef NTSTATUS(NTAPI* pfNtTerminateProcess)(IN HANDLE ProcessHandle, IN ULONG ProcessExitCode);
	typedef NTSTATUS(NTAPI* pfNtCreateProcess)(
		OUT PHANDLE				ProcessHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes OPTIONAL,
		IN HANDLE				ParentProcess,
		IN BOOLEAN				InheritObjectTable,
		IN HANDLE				SectionHandle OPTIONAL,
		IN HANDLE				DebugPort OPTIONAL,
		IN HANDLE				ExceptionPort OPTIONAL
		);
	typedef NTSTATUS(NTAPI *pfNtCreateProcessEx)(
		__out PHANDLE 					ProcessHandle,
		__in ACCESS_MASK 				DesiredAccess,
		__in_opt POBJECT_ATTRIBUTES 	ObjectAttributes,
		__in HANDLE 					ParentProcess,
		__in ULONG 						Flags,
		__in_opt HANDLE 				SectionHandle,
		__in_opt HANDLE 				DebugPort,
		__in_opt HANDLE 				ExceptionPort,
		__in ULONG 						JobMemberLevel
		);
	typedef	NTSTATUS(NTAPI * pfNtCreateUserProcess)(
		OUT PHANDLE 						ProcessHandle,
		OUT PHANDLE 						ThreadHandle,
		IN ACCESS_MASK 						ProcessDesiredAccess,
		IN ACCESS_MASK 						ThreadDesiredAccess,
		IN POBJECT_ATTRIBUTES 				ProcessObjectAttributes OPTIONAL,
		IN POBJECT_ATTRIBUTES 				ThreadObjectAttributes OPTIONAL,
		IN ULONG 							ProcessFlags,
		IN ULONG 							ThreadFlags,
		IN PRTL_USER_PROCESS_PARAMETERS 	ProcessParameters OPTIONAL,
		__in_opt PPS_CREATE_INFO 			CreateInfo,
		IN PPS_ATTRIBUTE_LIST 				AttributeList OPTIONAL
		);

	/*
		Synchronization Objects (Section, Event, Mutex, Semaphore) API
	*/
	typedef	NTSTATUS (NTAPI* pfNtCreateSection)(
		OUT PHANDLE				SectionHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		IN PLARGE_INTEGER		SectionSize OPTIONAL,
		IN ULONG				Protect,
		IN ULONG				Attributes,
		IN HANDLE				FileHandle
		);
	typedef NTSTATUS (NTAPI* pfNtOpenSection)(
		OUT PHANDLE				SectionHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes
		);
	typedef NTSTATUS (NTAPI* pfNtMapViewOfSection)(
		__in HANDLE					SectionHandle,
		__in HANDLE					ProcessHandle,
		__inout PVOID				*BaseAddress,
		__in ULONG_PTR				ZeroBits,
		__in SIZE_T					CommitSize,
		__inout_opt PLARGE_INTEGER	SectionOffset,
		__inout PSIZE_T				ViewSize,
		__in SECTION_INHERIT		InheritDisposition,
		__in ULONG					AllocationType,
		__in ULONG					Win32Protect
		);
	typedef NTSTATUS (NTAPI* pfNtUnmapViewOfSection)(
		__in HANDLE		ProcessHandle,
		__in_opt PVOID	BaseAddress
		);
	typedef NTSTATUS (NTAPI* pfNtCreateEvent)(
		OUT PHANDLE				EventHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		IN EVENT_TYPE			EventType,
		IN BOOLEAN				InitialState
		);
	typedef NTSTATUS (NTAPI* pfNtOpenEvent)(
		OUT PHANDLE				EventHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes
		);
	typedef NTSTATUS (NTAPI* pfNtCreateMutant)(
		OUT PHANDLE				MutantHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		IN BOOLEAN				InitialOwner
		);
	typedef NTSTATUS (NTAPI* pfNtOpenMutant)(
		OUT PHANDLE				MutantHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes
		);
	typedef NTSTATUS (NTAPI* pfNtCreateSemaphore)(
		OUT PHANDLE				SemaphoreHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		IN LONG					InitialCount,
		IN LONG					MaximumCount
		);
	typedef NTSTATUS (NTAPI* pfNtOpenSemaphore)(
		OUT PHANDLE				SemaphoreHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes
		);
	typedef NTSTATUS (NTAPI* pfNtWaitForSingleObject)(
		IN HANDLE				ObjectHandle,
		IN BOOLEAN				Alertable,
		IN PLARGE_INTEGER		Timeout OPTIONAL
		);
	typedef NTSTATUS (NTAPI* pfNtWaitForMultipleObjects)(
		IN ULONG                ObjectCount,
		IN PHANDLE              ObjectsArray,
		IN OBJECT_WAIT_TYPE     WaitType,
		IN BOOLEAN              Alertable,
		IN PLARGE_INTEGER       TimeOut OPTIONAL
		);
	typedef NTSTATUS (NTAPI* pfNtReleaseMutant)(
		IN HANDLE	MutantHandle,
		IN PLONG	ReleaseCount OPTIONAL
		);
	typedef NTSTATUS (NTAPI* pfNtSetEvent)(
		IN HANDLE EventHandle,
		OUT PLONG PreviousState OPTIONAL
		);
	typedef NTSTATUS(NTAPI* pfNtClearEvent)(
		IN HANDLE EventHandle
		);

	/*
		File API
	*/
	typedef NTSTATUS (NTAPI* pfNtCreateNamedPipeFile)(
		OUT PHANDLE				FileHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		OUT PIO_STATUS_BLOCK	IoStatusBlock,
		IN ULONG				ShareAccess,
		IN ULONG				CreateDisposition,
		IN ULONG				CreateOptions,
		IN ULONG				TypeMessage,
		IN ULONG				ReadmodeMessage,
		IN ULONG				Nonblocking,
		IN ULONG				MaxInstances,
		IN ULONG				InBufferSize,
		IN ULONG				OutBufferSize,
		IN PLARGE_INTEGER		DefaultTimeout OPTIONAL
		);
	typedef NTSTATUS (NTAPI* pfNtCreateMailslotFile)(
		 OUT PHANDLE			FileHandle,
		 IN ACCESS_MASK			DesiredAccess,
		 IN POBJECT_ATTRIBUTES	ObjectAttributes,
		 OUT PIO_STATUS_BLOCK	IoStatusBlock,
		 IN ULONG				CreateOptions,
		 IN ULONG				InBufferSize,
		 IN ULONG				MaxMessageSize,
		 IN PLARGE_INTEGER		ReadTimeout OPTIONAL
		 );
	typedef NTSTATUS (NTAPI* pfNtCreateFile)(
		OUT PHANDLE             FileHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		OUT PIO_STATUS_BLOCK    IoStatusBlock,
		IN PLARGE_INTEGER       AllocationSize OPTIONAL,
		IN ULONG                FileAttributes,
		IN ULONG                ShareAccess,
		IN ULONG                CreateDisposition,
		IN ULONG                CreateOptions,
		IN PVOID                EaBuffer OPTIONAL,
		IN ULONG                EaLength
		);
	typedef NTSTATUS (NTAPI* pfNtOpenFile)(
		OUT PHANDLE             FileHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		OUT PIO_STATUS_BLOCK    IoStatusBlock,
		IN ULONG                ShavbvvreAccess,
		IN ULONG                OpenOptions
		);
	typedef NTSTATUS (NTAPI* pfNtDeleteFile)(
		IN POBJECT_ATTRIBUTES   ObjectAttributes
		);
	typedef NTSTATUS (NTAPI* pfNtReadFile)(
		IN HANDLE				FileHandle,
		IN HANDLE				Event OPTIONAL,
		IN PIO_APC_ROUTINE		ApcRoutine OPTIONAL,
		IN PVOID				ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK	IoStatusBlock,
		OUT PVOID				Buffer,
		IN ULONG				Length,
		IN PLARGE_INTEGER		ByteOffset OPTIONAL,
		IN PULONG				Key OPTIONAL
		);
	typedef NTSTATUS (NTAPI* pfNtWriteFile)(
		IN HANDLE				FileHandle,
		IN HANDLE				Event OPTIONAL,
		IN PIO_APC_ROUTINE		ApcRoutine OPTIONAL,
		IN PVOID				ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK	IoStatusBlock,
		IN PVOID				Buffer,
		IN ULONG				Length,
		IN PLARGE_INTEGER		ByteOffset OPTIONAL,
		IN PULONG				Key OPTIONAL
		);
	typedef NTSTATUS (NTAPI* pfNtNotifyChangeDirectoryFile)(
		IN HANDLE						FileHandle,
		IN HANDLE						Event OPTIONAL,
		IN PIO_APC_ROUTINE				ApcRoutine OPTIONAL,
		IN PVOID						ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK			IoStatusBlock,
		OUT PFILE_NOTIFY_INFORMATION	Buffer,
		IN ULONG						BufferLength,
		IN ULONG						NotifyFilter,
		IN BOOLEAN						WatchSubtree
	);
	typedef NTSTATUS (NTAPI* pfNtQueryInformationFile)(
		IN HANDLE					FileHandle,
		OUT PIO_STATUS_BLOCK		IoStatusBlock,
		OUT PVOID					FileInformation,
		IN ULONG					FileInformationLength,
		IN FILE_INFORMATION_CLASS	FileInformationClass
		);
	typedef NTSTATUS (NTAPI* pfNtSetInformationFile)(
		IN HANDLE					FileHandle,
		OUT PIO_STATUS_BLOCK		IoStatusBlock,
		IN PVOID					FileInformation,
		IN ULONG					FileInformationLength,
		IN FILE_INFORMATION_CLASS	FileInformationClass
		);
	typedef NTSTATUS (NTAPI* pfNtQueryAttributesFile)(
		IN POBJECT_ATTRIBUTES		ObjectAttributes,
		OUT PFILE_BASIC_INFORMATION	FileInformation
		);
	typedef NTSTATUS (NTAPI* pfNtQueryFullAttributesFile)(
		IN POBJECT_ATTRIBUTES				ObjectAttributes,
		OUT PFILE_NETWORK_OPEN_INFORMATION	FileInformation
		);
	typedef NTSTATUS (NTAPI* pfNtQueryDirectoryFile)(
		IN HANDLE					FileHandle,
		IN HANDLE					Event OPTIONAL,
		IN PIO_APC_ROUTINE			ApcRoutine OPTIONAL,
		IN PVOID					ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK		IoStatusBlock,
		OUT PVOID					FileInformation,
		IN ULONG					FileInformationLength,
		IN FILE_INFORMATION_CLASS	FileInformationClass,
		IN BOOLEAN					ReturnSingleEntry,
		IN PUNICODE_STRING			FileName OPTIONAL,
		IN BOOLEAN					RestartScan
		);
	typedef NTSTATUS (NTAPI* pfNtQueryVolumeInformationFile)(
		IN HANDLE				FileHandle,
		OUT PIO_STATUS_BLOCK	IoStatusBlock,
		OUT PVOID				VolumeInformation,
		IN ULONG				VolumeInformationLength,
		IN FS_INFORMATION_CLASS VolumeInformationClass
		);
	typedef NTSTATUS (NTAPI* pfNtSetVolumeInformationFile)(
		IN HANDLE				FileHandle,
		OUT PIO_STATUS_BLOCK	IoStatusBlock,
		IN PVOID				Buffer,
		IN ULONG				BufferLength,
		IN FS_INFORMATION_CLASS VolumeInformationClass
		);
	typedef NTSTATUS (NTAPI* pfNtFsControlFile)(
		IN HANDLE				FileHandle,
		IN HANDLE				Event OPTIONAL,
		IN PIO_APC_ROUTINE		ApcRoutine OPTIONAL,
		IN PVOID				ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK	IoStatusBlock,
		IN ULONG				FsControlCode,
		IN PVOID				InputBuffer OPTIONAL,
		IN ULONG				InputBufferLength,
		OUT PVOID				OutputBuffer OPTIONAL,
		IN ULONG				OutputBufferLength
		); 
	typedef NTSTATUS (NTAPI* pfNtDeviceIoControlFile)( 
		IN HANDLE				FileHandle, 
		IN HANDLE				Event OPTIONAL, 
		IN PIO_APC_ROUTINE		ApcRoutine OPTIONAL, 
		IN PVOID				ApcContext OPTIONAL, 
		OUT PIO_STATUS_BLOCK	IoStatusBlock, 
		IN ULONG				IoControlCode, 
		IN PVOID				InputBuffer OPTIONAL, 
		IN ULONG				InputBufferLength, 
		OUT PVOID				OutputBuffer OPTIONAL, 
		IN ULONG				OutputBufferLength 
		);

	/*
		Directory API
	*/
	typedef NTSTATUS(NTAPI* pfNtOpenDirectoryObject)(
		OUT PHANDLE				DirectoryHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes
		);
	typedef NTSTATUS(NTAPI* pfNtCreateDirectoryObject)(
		OUT PHANDLE				DirectoryHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes
		);
	typedef NTSTATUS(NTAPI* pfNtCreateDirectoryObjectEx)(
		OUT PHANDLE				DirectoryHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		IN DWORD				UNKNOWN1,
		IN DWORD				UNKNOWN2
		);
	typedef NTSTATUS(NTAPI* pfNtQueryDirectoryObject)(
		IN HANDLE		DirectoryHandle,
		OUT PVOID		Buffer,
		IN ULONG		BufferLength,
		IN BOOLEAN		ReturnSingleEntry,
		IN BOOLEAN		RestartScan,
		IN OUT PULONG	Context,
		OUT PULONG		ReturnLength OPTIONAL
		);
	/*
		SymbolicLink API
	*/
	typedef NTSTATUS(NTAPI* pfNtOpenSymbolicLinkObject)(
		OUT PHANDLE				SymbolicLinkHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes
		);
	typedef NTSTATUS(NTAPI* pfNtCreateSymbolicLinkObject)(
		OUT PHANDLE				SymbolicLinkHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		IN PUNICODE_STRING		TargetName
		);
	typedef NTSTATUS(NTAPI* pfNtQuerySymbolicLinkObject)(
		IN HANDLE				SymbolicLinkHandle,
		IN OUT PUNICODE_STRING	TargetName,
		OUT PULONG				ReturnLength OPTIONAL
		);

	/*
		Registry API
	*/
	typedef NTSTATUS (NTAPI* pfNtCompactKeys)(
		IN ULONG  Count,  
		IN PHANDLE  KeyArray 
		);
	typedef NTSTATUS (NTAPI* pfNtCompressKey)(
		IN HANDLE  Key 
		);
	typedef NTSTATUS (NTAPI* pfNtCreateKey)(
		OUT PHANDLE				KeyHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		IN ULONG				TitleIndex,
		IN PUNICODE_STRING		Class OPTIONAL,
		IN ULONG				CreateOptions,
		OUT PULONG				Disposition OPTIONAL
		);
	typedef NTSTATUS (NTAPI* pfNtCreateKeyTransacted)(
		OUT PHANDLE				KeyHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		IN ULONG				TitleIndex,
		IN PUNICODE_STRING		Class OPTIONAL,
		IN ULONG				CreateOptions,
		OUT PULONG				Disposition OPTIONAL,
		IN PHANDLE				TransactionHandle
		);
	typedef NTSTATUS (NTAPI* pfNtOpenKey)(
		OUT PHANDLE				KeyHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes
		);
	typedef NTSTATUS (NTAPI* pfNtOpenKeyEx)(
		OUT PHANDLE				KeyHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		IN ULONG				OpenOptions
		);
	typedef NTSTATUS (NTAPI* pfNtOpenKeyTransacted)(
		OUT PHANDLE				KeyHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		IN PHANDLE				TransactionHandle
		);
	typedef NTSTATUS (NTAPI* pfNtOpenKeyTransactedEx)(
		OUT PHANDLE				KeyHandle,
		IN ACCESS_MASK			DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		IN ULONG				OpenOptions,
		IN PHANDLE				TransactionHandle
		);
	typedef NTSTATUS (NTAPI* pfNtDeleteKey)(
		IN HANDLE KeyHandle
		);
	typedef NTSTATUS (NTAPI* pfNtQueryKey)(
		IN HANDLE					KeyHandle,
		IN KEY_INFORMATION_CLASS	KeyInformationClass,
		OUT PVOID					KeyInformation,
		IN ULONG					KeyInformationLength,
		OUT PULONG					ResultLength
		);
	typedef NTSTATUS (NTAPI* pfNtEnumerateKey)(
		IN HANDLE					KeyHandle,
		IN ULONG					Index,
		IN KEY_INFORMATION_CLASS	KeyInformationClass,
		OUT PVOID					KeyInformation,
		IN ULONG					KeyInformationLength,
		OUT PULONG					ResultLength
		);
	typedef NTSTATUS (NTAPI* pfNtDeleteValueKey)(
		IN HANDLE			KeyHandle,
		IN PUNICODE_STRING	ValueName
		);
	typedef NTSTATUS (NTAPI* pfNtSetValueKey)(
		IN HANDLE			KeyHandle,
		IN PUNICODE_STRING	ValueName,
		IN ULONG			TitleIndex,
		IN ULONG			Type,
		IN PVOID			Data,
		IN ULONG			DataSize
		);
	typedef NTSTATUS (NTAPI* pfNtQueryValueKey)(
		IN HANDLE						KeyHandle,
		IN PUNICODE_STRING				ValueName,
		IN KEY_VALUE_INFORMATION_CLASS	KeyValueInformationClass,
		OUT PVOID						KeyValueInformation,
		IN ULONG						KeyValueInformationLength,
		OUT PULONG						ResultLength
		);
	typedef NTSTATUS (NTAPI* pfNtEnumerateValueKey)(
		IN HANDLE						KeyHandle,
		IN ULONG						Index,
		IN KEY_VALUE_INFORMATION_CLASS	KeyValueInformationClass,
		OUT PVOID						KeyValueInformation,
		IN ULONG						KeyValueInformationLength,
		OUT PULONG						ResultLength
		);
	typedef NTSTATUS (NTAPI* pfNtQueryMultipleValueKey)(
		IN HANDLE				KeyHandle,
		IN OUT PKEY_VALUE_ENTRY	ValueList,
		IN ULONG				NumberOfValues,
		OUT PVOID				Buffer,
		IN OUT PULONG			Length,
		OUT PULONG				ReturnLength
		);
	typedef NTSTATUS (NTAPI* pfNtFlushKey)(
		IN HANDLE	KeyHandle								   
		);
	typedef NTSTATUS (NTAPI* pfNtSaveKey)(
		IN HANDLE	KeyHandle,
		IN HANDLE	FileHandle
		);
	typedef NTSTATUS (NTAPI* pfNtSaveKeyEx)(
		IN HANDLE	KeyHandle,
		IN HANDLE	FileHandle,
		IN ULONG	Flags
		);
	typedef NTSTATUS (NTAPI* pfNtSaveMergedKeys)(
		IN HANDLE	KeyHandle1,
		IN HANDLE	KeyHandle2,
		IN HANDLE	FileHandle
		);
	typedef NTSTATUS (NTAPI* pfNtRestoreKey)(
		IN HANDLE	KeyHandle,
		IN HANDLE	FileHandle,
		IN ULONG	Flags
		);
	typedef NTSTATUS (NTAPI* pfNtLoadKey)(
		IN POBJECT_ATTRIBUTES	KeyObjectAttributes,
		IN POBJECT_ATTRIBUTES	FileObjectAttributes
		);
	typedef NTSTATUS (NTAPI* pfNtLoadKey2)(
		IN POBJECT_ATTRIBUTES	KeyObjectAttributes,
		IN POBJECT_ATTRIBUTES	FileObjectAttributes,
		IN ULONG				Flags
		);
	typedef NTSTATUS (NTAPI* pfNtLoadKeyEx)(
		IN POBJECT_ATTRIBUTES	KeyObjectAttributes,
		IN POBJECT_ATTRIBUTES	FileObjectAttributes,
		IN ULONG				Flags,
		ULONG_PTR				Unknown1,
		ULONG_PTR				Unknown2,
		IN ACCESS_MASK			DesiredAccess,
		OUT PHANDLE				KeyHandle,
		ULONG_PTR				Unknown3
		);
	typedef NTSTATUS (NTAPI* pfNtLockRegistryKey)(IN HANDLE KeyHandle);
	typedef NTSTATUS (NTAPI* pfNtUnloadKey)(
		IN POBJECT_ATTRIBUTES	KeyObjectAttributes
		);
	typedef NTSTATUS (NTAPI* pfNtUnloadKey2)(
		IN POBJECT_ATTRIBUTES	KeyObjectAttributes,
		IN ULONG				Flags
		);
	typedef NTSTATUS (NTAPI* pfNtUnloadKeyEx)(
		IN POBJECT_ATTRIBUTES	KeyObjectAttributes,
		IN HANDLE				EventHandle
		);
	typedef NTSTATUS (NTAPI* pfNtQueryOpenSubKeys)(
		IN POBJECT_ATTRIBUTES	KeyObjectAttributes,
		OUT PULONG				NumberOfKeys
		);
	typedef NTSTATUS (NTAPI* pfNtQueryOpenSubKeysEx)(
		IN POBJECT_ATTRIBUTES	KeyObjectAttributes,
		IN ULONG				BufferLength,
		IN PVOID				Buffer,
		IN PULONG				RequiredSize
		);
	typedef NTSTATUS (NTAPI* pfNtReplaceKey)(
		IN POBJECT_ATTRIBUTES	NewFileObjectAttributes,
		IN HANDLE				KeyHandle,
		IN POBJECT_ATTRIBUTES	OldFileObjectAttributes
		);
	typedef NTSTATUS (NTAPI* pfNtSetInformationKey)(
		IN HANDLE						KeyHandle,
		IN KEY_SET_INFORMATION_CLASS	KeyInformationClass,
		IN PVOID						KeyInformation,
		IN ULONG						KeyInformationLength
		);
	typedef NTSTATUS (NTAPI* pfNtRenameKey)(
		IN HANDLE			KeyHandle,
		IN PUNICODE_STRING	NewName
		);
	typedef NTSTATUS (NTAPI* pfNtNotifyChangeKey)(
		IN HANDLE				KeyHandle,
		IN HANDLE				EventHandle OPTIONAL,
		IN PIO_APC_ROUTINE		ApcRoutine OPTIONAL,
		IN PVOID				ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK	IoStatusBlock,
		IN ULONG				NotifyFilter,
		IN BOOLEAN				WatchSubtree,
		IN PVOID				Buffer,
		IN ULONG				BufferLength,
		IN BOOLEAN				Asynchrous
		);
	typedef NTSTATUS (NTAPI* pfNtNotifyChangeMultipleKeys)(
		IN HANDLE				KeyHandle,
		IN ULONG				Flags,
		IN POBJECT_ATTRIBUTES	KeyObjectAttributes,
		IN HANDLE				EventHandle OPTIONAL,
		IN PIO_APC_ROUTINE		ApcRoutine OPTIONAL,
		IN PVOID				ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK	IoStatusBlock,
		IN ULONG				NotifyFilter,
		IN BOOLEAN				WatchSubtree,
		IN PVOID				Buffer,
		IN ULONG				BufferLength,
		IN BOOLEAN				Asynchronous
		);
	typedef NTSTATUS (NTAPI* pfNtInitializeRegistry)(
		IN BOOLEAN	Setup
		);

	/*
		Port API
	*/
	typedef NTSTATUS (NTAPI* pfNtCreatePort)(
		OUT PHANDLE				PortHandle,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		IN ULONG				MaxDataSize,
		IN ULONG				MaxMessageSize,
		IN ULONG				Reserved
		);
	typedef NTSTATUS (NTAPI* pfNtCreateWaitablePort)(
		OUT PHANDLE				PortHandle,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		IN ULONG				MaxDataSize,
		IN ULONG				MaxMessageSize,
		IN ULONG				Reserved
		);
	typedef NTSTATUS (NTAPI* pfNtConnectPort)(
		OUT PHANDLE						PortHandle,
		IN PUNICODE_STRING				PortName,
		IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
		IN OUT PPORT_SECTION_WRITE		WriteSection OPTIONAL,
		IN OUT PPORT_SECTION_READ		ReadSection OPTIONAL,
		OUT PULONG						MaxMessageSize OPTIONAL,
		IN OUT PVOID					ConnectData OPTIONAL,
		IN OUT PULONG					ConnectDataLength OPTIONAL
		);
	typedef NTSTATUS (NTAPI* pfNtSecureConnectPort)(
		OUT PHANDLE						PortHandle,
		IN PUNICODE_STRING				PortName,
		IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
		IN OUT PPORT_SECTION_WRITE		WriteSection OPTIONAL,
		IN PSID							ServerSid OPTIONAL,
		IN OUT PPORT_SECTION_READ		ReadSection OPTIONAL,
		OUT PULONG						MaxMessageSize OPTIONAL,
		IN OUT PVOID					ConnectData OPTIONAL,
		IN OUT PULONG					ConnectDataLength OPTIONAL
		);
	typedef NTSTATUS (NTAPI* pfNtAlpcCreatePort)(
		__out PHANDLE					PortHandle,
		__in POBJECT_ATTRIBUTES			ObjectAttributes,
		__in_opt PALPC_PORT_ATTRIBUTES	PortAttributes
		);
	typedef NTSTATUS (NTAPI* pfNtAlpcConnectPort)(
		__out PHANDLE							PortHandle,
		__in PUNICODE_STRING					PortName,
		__in POBJECT_ATTRIBUTES					ObjectAttributes,
		__in_opt PALPC_PORT_ATTRIBUTES			PortAttributes,
		__in ULONG								Flags,
		__in_opt PSID							RequiredServerSid,
		__inout PPORT_MESSAGE					ConnectionMessage,
		__inout_opt PULONG						BufferLength,
		__inout_opt PALPC_MESSAGE_ATTRIBUTES	OutMessageAttributes,
		__inout_opt PALPC_MESSAGE_ATTRIBUTES	InMessageAttributes,
		__in_opt PLARGE_INTEGER					Timeout
		);
	typedef NTSTATUS (NTAPI* pfNtAlpcConnectPortEx)(
		__out PHANDLE							PortHandle,
		__in POBJECT_ATTRIBUTES					PortName,
		__in POBJECT_ATTRIBUTES					ObjectAttributes,
		__in_opt PALPC_PORT_ATTRIBUTES			PortAttributes,
		__in ULONG								Flags,
		__in_opt PSID							RequiredServerSid,
		__inout PPORT_MESSAGE					ConnectionMessage,
		__inout_opt PULONG						BufferLength,
		__inout_opt PALPC_MESSAGE_ATTRIBUTES	OutMessageAttributes,
		__inout_opt PALPC_MESSAGE_ATTRIBUTES	InMessageAttributes,
		__in_opt PLARGE_INTEGER					Timeout
		);

	/*
		Atom API
	*/
	typedef NTSTATUS (NTAPI* pfNtAddAtom)(
		IN PWSTR String,
		IN ULONG StringLength,
		OUT PUSHORT Atom
		);
	typedef NTSTATUS (NTAPI* pfNtAddAtomEx)(
		IN PWSTR String,
		IN ULONG StringLength,
		OUT PUSHORT Atom,
		ULONG Unknown
		);
	typedef NTSTATUS (NTAPI* pfNtFindAtom)(
		IN PWSTR String,
		IN ULONG StringLength,
		OUT PUSHORT Atom
		);

	/*
		Driver API
	*/
	typedef NTSTATUS(NTAPI* pfNtLoadDriver)(
		IN PUNICODE_STRING DriverServiceName
		);
	typedef NTSTATUS(NTAPI* pfNtUnloadDriver)(
		IN PUNICODE_STRING DriverServiceName
		);

	/*
		Transaction API
	*/
	typedef NTSTATUS(NTAPI* pfNtCreateTransaction)(
		__out PHANDLE				TransactionHandle,
		__in ACCESS_MASK			DesiredAccess,
		__in_opt PVOID				ObjectAttributes,
		__in_opt LPGUID				Uow,
		__in_opt HANDLE				TmHandle,
		__in_opt ULONG				CreateOptions,
		__in_opt ULONG				IsolationLevel,
		__in_opt ULONG				IsolationFlags,
		__in_opt PLARGE_INTEGER		Timeout,
		__in_opt PUNICODE_STRING	Description);
	typedef NTSTATUS(NTAPI* pfNtOpenTransaction)(
		__out PHANDLE		TransactionHandle,
		__in ACCESS_MASK	DesiredAccess,
		__in_opt PVOID		ObjectAttributes,
		__in LPGUID			Uow,
		__in_opt HANDLE		TmHandle);
	typedef NTSTATUS(NTAPI* pfNtCommitTransaction)(IN PHANDLE  TransactionHandle, IN BOOLEAN  Wait);
	typedef NTSTATUS(NTAPI* pfNtRollbackTransaction)(IN PHANDLE  TransactionHandle, IN BOOLEAN  Wait);

	/*
		Security API
	*/
	typedef NTSTATUS(NTAPI* pfNtQuerySecurityObject)(
		IN HANDLE					Handle,
		IN SECURITY_INFORMATION		SecurityInformation,
		OUT PSECURITY_DESCRIPTOR	SecurityDescriptor,
		IN ULONG					SecurityDescriptorLength,
		OUT PULONG					ReturnLength
		);
	typedef NTSTATUS(NTAPI* pfNtSetSecurityObject)(
		IN HANDLE					Handle,
		IN SECURITY_INFORMATION		SecurityInformation,
		IN PSECURITY_DESCRIPTOR		SecurityDescriptor
		);
	typedef BOOLEAN(NTAPI* pfRtlFlushSecureMemoryCache)(
		IN PVOID					MemoryCache,
		IN SIZE_T					MemoryLength
		);

	class ntdllapi
	{
	public:

		pfRtlInitAnsiString RtlInitAnsiString;
		pfRtlInitUnicodeString RtlInitUnicodeString;

		/*
			General API
		*/
		pfNtClose NtClose;
		pfNtQueryObject NtQueryObject;
		pfNtSetSystemInformation NtSetSystemInformation;
		pfNtQuerySystemInformation NtQuerySystemInformation;
		pfRtlGetVersion RtlGetVersion;

		/*
			DLL API
		*/
		pfLdrGetProcedureAddress LdrGetProcedureAddress;
		pfLdrLoadDll LdrLoadDll;
		pfLdrGetDllHandle LdrGetDllHandle;

		/*
			Process API
		*/
		pfNtOpenThread NtOpenThread;
		pfNtQueryInformationThread NtQueryInformationThread;
		pfNtQueryInformationProcess NtQueryInformationProcess;
		pfRtlGetCurrentDirectory_U RtlGetCurrentDirectory_U;
		pfRtlSetCurrentDirectory_U RtlSetCurrentDirectory_U;
		pfNtCreateToken NtCreateToken;
		pfNtTerminateProcess NtTerminateProcess;
		pfNtCreateProcess NtCreateProcess;
		pfNtCreateProcessEx NtCreateProcessEx;
		pfNtCreateUserProcess NtCreateUserProcess;

		/*
			Synchronization Objects (Section, Event, Mutex, Semaphore) API
		*/
		pfNtOpenSection NtOpenSection;
		pfNtCreateSection NtCreateSection;
		pfNtMapViewOfSection NtMapViewOfSection;
		pfNtUnmapViewOfSection NtUnmapViewOfSection;
		pfNtOpenEvent NtOpenEvent;
		pfNtCreateEvent NtCreateEvent;
		pfNtOpenMutant NtOpenMutant;
		pfNtCreateMutant NtCreateMutant;
		pfNtOpenSemaphore NtOpenSemaphore;
		pfNtCreateSemaphore NtCreateSemaphore;
		pfNtWaitForSingleObject NtWaitForSingleObject;
		pfNtWaitForMultipleObjects NtWaitForMultipleObjects;
		pfNtReleaseMutant NtReleaseMutant;
		pfNtSetEvent NtSetEvent;
		pfNtClearEvent NtClearEvent;

		/*
			File API
		*/
		pfNtCreateNamedPipeFile NtCreateNamedPipeFile;
		pfNtCreateMailslotFile NtCreateMailslotFile;
		pfNtCreateFile NtCreateFile;
		pfNtOpenFile NtOpenFile;
		pfNtDeleteFile NtDeleteFile;
		pfNtReadFile NtReadFile;
		pfNtWriteFile NtWriteFile;
		pfNtNotifyChangeDirectoryFile NtNotifyChangeDirectoryFile;
		pfNtQueryAttributesFile NtQueryAttributesFile;
		pfNtQueryFullAttributesFile NtQueryFullAttributesFile;
		pfNtQueryInformationFile NtQueryInformationFile;
		pfNtSetInformationFile NtSetInformationFile;
		pfNtQueryDirectoryFile NtQueryDirectoryFile;
		pfNtQueryVolumeInformationFile NtQueryVolumeInformationFile;
		pfNtFsControlFile NtFsControlFile;
		pfNtDeviceIoControlFile NtDeviceIoControlFile;

		/*
			Directory API
		*/
		pfNtOpenDirectoryObject NtOpenDirectoryObject;
		pfNtCreateDirectoryObject NtCreateDirectoryObject;
		pfNtCreateDirectoryObjectEx NtCreateDirectoryObjectEx;
		pfNtQueryDirectoryObject NtQueryDirectoryObject;

		/*
			SymbolicLink API
		*/
		pfNtOpenSymbolicLinkObject NtOpenSymbolicLinkObject;
		pfNtCreateSymbolicLinkObject NtCreateSymbolicLinkObject;
		pfNtQuerySymbolicLinkObject NtQuerySymbolicLinkObject;

		/*
			Registry API
		*/
		pfNtCompactKeys NtCompactKeys;
		pfNtCompressKey NtCompressKey;
		pfNtCreateKey NtCreateKey;
		pfNtCreateKeyTransacted NtCreateKeyTransacted;
		pfNtOpenKey NtOpenKey;
		pfNtOpenKeyEx NtOpenKeyEx;
		pfNtOpenKeyTransacted NtOpenKeyTransacted;
		pfNtOpenKeyTransactedEx NtOpenKeyTransactedEx;
		pfNtDeleteKey NtDeleteKey;
		pfNtQueryKey NtQueryKey;
		pfNtEnumerateKey NtEnumerateKey;
		pfNtDeleteValueKey NtDeleteValueKey;
		pfNtSetValueKey NtSetValueKey;
		pfNtQueryValueKey NtQueryValueKey;
		pfNtEnumerateValueKey NtEnumerateValueKey;
		pfNtQueryMultipleValueKey NtQueryMultipleValueKey;
		pfNtFlushKey NtFlushKey;
		pfNtSaveKey NtSaveKey;
		pfNtSaveKeyEx NtSaveKeyEx;
		pfNtSaveMergedKeys NtSaveMergedKeys;
		pfNtRestoreKey NtRestoreKey;
		pfNtLoadKey NtLoadKey;
		pfNtLoadKey2 NtLoadKey2;
		pfNtLoadKeyEx NtLoadKeyEx;
		pfNtUnloadKey NtUnloadKey;
		pfNtUnloadKey2 NtUnloadKey2;
		pfNtUnloadKeyEx NtUnloadKeyEx;
		pfNtQueryOpenSubKeys NtQueryOpenSubKeys;
		pfNtQueryOpenSubKeysEx NtQueryOpenSubKeysEx;
		pfNtReplaceKey NtReplaceKey;
		pfNtSetInformationKey NtSetInformationKey;
		pfNtRenameKey NtRenameKey;
		pfNtNotifyChangeKey NtNotifyChangeKey;
		pfNtNotifyChangeMultipleKeys NtNotifyChangeMultipleKeys;
		pfNtInitializeRegistry NtInitializeRegistry;
		pfNtLockRegistryKey NtLockRegistryKey;

		/*
			Port API
		*/
		pfNtCreatePort NtCreatePort;
		pfNtCreateWaitablePort NtCreateWaitablePort;
		pfNtConnectPort NtConnectPort;
		pfNtSecureConnectPort NtSecureConnectPort;
		pfNtAlpcCreatePort NtAlpcCreatePort;
		pfNtAlpcConnectPort NtAlpcConnectPort;
		pfNtAlpcConnectPortEx NtAlpcConnectPortEx;

		/*
			Atom API
		*/
		pfNtAddAtom NtAddAtom;
		pfNtAddAtomEx NtAddAtomEx;
		pfNtFindAtom NtFindAtom;

		/*
			Driver API
		*/
		pfNtLoadDriver NtLoadDriver;
		pfNtUnloadDriver NtUnloadDriver;

		/*
			Transaction API
		*/
		pfNtCreateTransaction NtCreateTransaction;
		pfNtOpenTransaction NtOpenTransaction;
		pfNtRollbackTransaction NtRollbackTransaction;
		pfNtCommitTransaction NtCommitTransaction;

		/*
			Security API
		*/
		pfNtQuerySecurityObject NtQuerySecurityObject;
		pfNtSetSecurityObject NtSetSecurityObject;
		pfRtlFlushSecureMemoryCache RtlFlushSecureMemoryCache;
		
		static ntdllapi* GetInstance();
	protected:
		ntdllapi(void);
		virtual ~ntdllapi(void);

	private:
	};

}