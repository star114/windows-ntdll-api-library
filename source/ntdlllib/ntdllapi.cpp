#include <ntdlllib/all.h>

namespace ntdlllib
{

ntdllapi::ntdllapi(void)
{
	HMODULE hModule = ::GetModuleHandleW(L"ntdll.dll");
	if (NULL == hModule) hModule = ::LoadLibraryW(L"ntdll.dll");
	if (NULL == hModule) throw;

	RtlInitAnsiString = (pfRtlInitAnsiString)::GetProcAddress(hModule, "RtlInitAnsiString");
	RtlInitUnicodeString = (pfRtlInitUnicodeString)::GetProcAddress(hModule, "RtlInitUnicodeString");

	/*
		General API
	*/
	NtClose = (pfNtClose)::GetProcAddress(hModule, "NtClose");
	NtQueryObject = (pfNtQueryObject)::GetProcAddress(hModule, "NtQueryObject");
	NtQuerySystemInformation = (pfNtQuerySystemInformation)::GetProcAddress(hModule, "NtQuerySystemInformation");
	NtSetSystemInformation = (pfNtSetSystemInformation)::GetProcAddress(hModule, "NtSetSystemInformation");
	RtlGetVersion = (pfRtlGetVersion)::GetProcAddress(hModule, "RtlGetVersion");

	/*
		DLL API
	*/
	LdrGetProcedureAddress = (pfLdrGetProcedureAddress)::GetProcAddress(hModule, "LdrGetProcedureAddress");
	LdrLoadDll = (pfLdrLoadDll)::GetProcAddress(hModule, "LdrLoadDll");
	LdrGetDllHandle = (pfLdrGetDllHandle)::GetProcAddress(hModule, "LdrGetDllHandle");

	/*
		Process API
	*/
	NtOpenThread = (pfNtOpenThread)::GetProcAddress(hModule, "NtOpenThread");
	NtQueryInformationThread = (pfNtQueryInformationThread)::GetProcAddress(hModule, "NtQueryInformationThread");
	NtQueryInformationProcess = (pfNtQueryInformationProcess)::GetProcAddress(hModule, "NtQueryInformationProcess");
	RtlGetCurrentDirectory_U = (pfRtlGetCurrentDirectory_U)::GetProcAddress(hModule, "RtlGetCurrentDirectory_U");
	RtlSetCurrentDirectory_U = (pfRtlSetCurrentDirectory_U)::GetProcAddress(hModule, "RtlSetCurrentDirectory_U");
	NtCreateToken = (pfNtCreateToken)::GetProcAddress(hModule, "NtCreateToken");
	NtTerminateProcess = (pfNtTerminateProcess)::GetProcAddress(hModule, "NtTerminateProcess");
	NtCreateProcess = (pfNtCreateProcess)::GetProcAddress(hModule, "NtCreateProcess");
	NtCreateProcessEx = (pfNtCreateProcessEx)::GetProcAddress(hModule, "NtCreateProcessEx");
	NtCreateUserProcess = (pfNtCreateUserProcess)::GetProcAddress(hModule, "NtCreateUserProcess");

	/*
		Synchronization Objects (Section, Event, Mutex, Semaphore) API
	*/
	NtOpenSection = (pfNtOpenSection)::GetProcAddress(hModule, "NtOpenSection");
	NtCreateSection = (pfNtCreateSection)::GetProcAddress(hModule, "NtCreateSection");
	NtMapViewOfSection = (pfNtMapViewOfSection)::GetProcAddress(hModule, "NtMapViewOfSection");
	NtUnmapViewOfSection = (pfNtUnmapViewOfSection)::GetProcAddress(hModule, "NtUnmapViewOfSection");
	NtOpenEvent = (pfNtOpenEvent)::GetProcAddress(hModule, "NtOpenEvent");
	NtCreateEvent = (pfNtCreateEvent)::GetProcAddress(hModule, "NtCreateEvent");
	NtOpenMutant = (pfNtOpenMutant)::GetProcAddress(hModule, "NtOpenMutant");
	NtCreateMutant = (pfNtCreateMutant)::GetProcAddress(hModule, "NtCreateMutant");
	NtOpenSemaphore = (pfNtOpenSemaphore)::GetProcAddress(hModule, "NtOpenSemaphore");
	NtCreateSemaphore = (pfNtCreateSemaphore)::GetProcAddress(hModule, "NtCreateSemaphore");
	NtWaitForSingleObject = (pfNtWaitForSingleObject)::GetProcAddress(hModule, "NtWaitForSingleObject");
	NtWaitForMultipleObjects = (pfNtWaitForMultipleObjects)::GetProcAddress(hModule, "NtWaitForMultipleObjects");
	NtReleaseMutant = (pfNtReleaseMutant)::GetProcAddress(hModule, "NtReleaseMutant");
	NtSetEvent = (pfNtSetEvent)::GetProcAddress(hModule, "NtSetEvent");
	NtClearEvent = (pfNtClearEvent)::GetProcAddress(hModule, "NtClearEvent");
	
	/*
		File API
	*/
	NtCreateNamedPipeFile = (pfNtCreateNamedPipeFile)::GetProcAddress(hModule, "NtCreateNamedPipeFile");
	NtCreateMailslotFile = (pfNtCreateMailslotFile)::GetProcAddress(hModule, "NtCreateMailslotFile");
	NtCreateFile = (pfNtCreateFile)::GetProcAddress(hModule, "NtCreateFile");
	NtOpenFile = (pfNtOpenFile)::GetProcAddress(hModule, "NtOpenFile");
	NtDeleteFile = (pfNtDeleteFile)::GetProcAddress(hModule, "NtDeleteFile");
	NtReadFile = (pfNtReadFile)::GetProcAddress(hModule, "NtReadFile");
	NtWriteFile = (pfNtWriteFile)::GetProcAddress(hModule, "NtWriteFile");
	NtNotifyChangeDirectoryFile = (pfNtNotifyChangeDirectoryFile)::GetProcAddress(hModule, "NtNotifyChangeDirectoryFile");
	NtQueryAttributesFile = (pfNtQueryAttributesFile)::GetProcAddress(hModule, "NtQueryAttributesFile");
	NtQueryFullAttributesFile = (pfNtQueryFullAttributesFile)::GetProcAddress(hModule, "NtQueryFullAttributesFile");
	NtQueryInformationFile = (pfNtQueryInformationFile)::GetProcAddress(hModule, "NtQueryInformationFile");
	NtSetInformationFile = (pfNtSetInformationFile)::GetProcAddress(hModule, "NtSetInformationFile");
	NtQueryDirectoryFile = (pfNtQueryDirectoryFile)::GetProcAddress(hModule, "NtQueryDirectoryFile");
	NtQueryVolumeInformationFile = (pfNtQueryVolumeInformationFile)::GetProcAddress(hModule, "NtQueryVolumeInformationFile");
	NtFsControlFile = (pfNtFsControlFile)::GetProcAddress(hModule, "NtFsControlFile");
	NtDeviceIoControlFile = (pfNtDeviceIoControlFile)::GetProcAddress(hModule, "NtDeviceIoControlFile");

	/*
		Directory API
	*/
	NtOpenDirectoryObject = (pfNtOpenDirectoryObject)::GetProcAddress(hModule, "NtOpenDirectoryObject");
	NtCreateDirectoryObject = (pfNtCreateDirectoryObject)::GetProcAddress(hModule, "NtCreateDirectoryObject");
	NtCreateDirectoryObjectEx = (pfNtCreateDirectoryObjectEx)::GetProcAddress(hModule, "NtCreateDirectoryObjectEx");
	NtQueryDirectoryObject = (pfNtQueryDirectoryObject)::GetProcAddress(hModule, "NtQueryDirectoryObject");

	/*
		SymbolicLink API
	*/
	NtOpenSymbolicLinkObject = (pfNtOpenSymbolicLinkObject)::GetProcAddress(hModule, "NtOpenSymbolicLinkObject");
	NtCreateSymbolicLinkObject = (pfNtCreateSymbolicLinkObject)::GetProcAddress(hModule, "NtCreateSymbolicLinkObject");
	NtQuerySymbolicLinkObject = (pfNtQuerySymbolicLinkObject)::GetProcAddress(hModule, "NtQuerySymbolicLinkObject");

	/*
		Registry API
	*/
	NtCompactKeys = (pfNtCompactKeys)::GetProcAddress(hModule, "NtCompactKeys");
	NtCompressKey = (pfNtCompressKey)::GetProcAddress(hModule, "NtCompressKey");
	NtCreateKey = (pfNtCreateKey)::GetProcAddress(hModule, "NtCreateKey");
	NtCreateKeyTransacted = (pfNtCreateKeyTransacted)::GetProcAddress(hModule, "NtCreateKeyTransacted");
	NtOpenKey = (pfNtOpenKey)::GetProcAddress(hModule, "NtOpenKey");
	NtOpenKeyEx = (pfNtOpenKeyEx)::GetProcAddress(hModule, "NtOpenKeyEx");
	NtOpenKeyTransacted = (pfNtOpenKeyTransacted)::GetProcAddress(hModule, "NtOpenKeyTransacted");
	NtOpenKeyTransactedEx = (pfNtOpenKeyTransactedEx)::GetProcAddress(hModule, "NtOpenKeyTransactedEx");
	NtDeleteKey = (pfNtDeleteKey)::GetProcAddress(hModule, "NtDeleteKey");
	NtQueryKey = (pfNtQueryKey)::GetProcAddress(hModule, "NtQueryKey");
	NtEnumerateKey = (pfNtEnumerateKey)::GetProcAddress(hModule, "NtEnumerateKey");
	NtDeleteValueKey = (pfNtDeleteValueKey)::GetProcAddress(hModule, "NtDeleteValueKey");
	NtSetValueKey = (pfNtSetValueKey)::GetProcAddress(hModule, "NtSetValueKey");
	NtQueryValueKey = (pfNtQueryValueKey)::GetProcAddress(hModule, "NtQueryValueKey");
	NtEnumerateValueKey = (pfNtEnumerateValueKey)::GetProcAddress(hModule, "NtEnumerateValueKey");
	NtQueryMultipleValueKey = (pfNtQueryMultipleValueKey)::GetProcAddress(hModule, "NtQueryMultipleValueKey");
	NtFlushKey = (pfNtFlushKey)::GetProcAddress(hModule, "NtFlushKey");
	NtSaveKey = (pfNtSaveKey)::GetProcAddress(hModule, "NtSaveKey");
	NtSaveKeyEx = (pfNtSaveKeyEx)::GetProcAddress(hModule, "NtSaveKeyEx");
	NtSaveMergedKeys = (pfNtSaveMergedKeys)::GetProcAddress(hModule, "NtSaveMergedKeys");
	NtRestoreKey = (pfNtRestoreKey)::GetProcAddress(hModule, "NtRestoreKey");
	NtLoadKey = (pfNtLoadKey)::GetProcAddress(hModule, "NtLoadKey");
	NtLoadKey2 = (pfNtLoadKey2)::GetProcAddress(hModule, "NtLoadKey2");
	NtLoadKeyEx = (pfNtLoadKeyEx)::GetProcAddress(hModule, "NtLoadKeyEx");
	NtUnloadKey = (pfNtUnloadKey)::GetProcAddress(hModule, "NtUnloadKey");
	NtUnloadKey2 = (pfNtUnloadKey2)::GetProcAddress(hModule, "NtUnloadKey2");
	NtUnloadKeyEx = (pfNtUnloadKeyEx)::GetProcAddress(hModule, "NtUnloadKeyEx");
	NtQueryOpenSubKeys = (pfNtQueryOpenSubKeys)::GetProcAddress(hModule, "NtQueryOpenSubKeys");
	NtQueryOpenSubKeysEx = (pfNtQueryOpenSubKeysEx)::GetProcAddress(hModule, "NtQueryOpenSubKeysEx");
	NtReplaceKey = (pfNtReplaceKey)::GetProcAddress(hModule, "NtReplaceKey");
	NtSetInformationKey = (pfNtSetInformationKey)::GetProcAddress(hModule, "NtSetInformationKey");
	NtRenameKey = (pfNtRenameKey)::GetProcAddress(hModule, "NtRenameKey");
	NtNotifyChangeKey = (pfNtNotifyChangeKey)::GetProcAddress(hModule, "NtNotifyChangeKey");
	NtNotifyChangeMultipleKeys = (pfNtNotifyChangeMultipleKeys)::GetProcAddress(hModule, "NtNotifyChangeMultipleKeys");
	NtInitializeRegistry = (pfNtInitializeRegistry)::GetProcAddress(hModule, "NtInitializeRegistry");
	NtLockRegistryKey = (pfNtLockRegistryKey)::GetProcAddress(hModule, "NtLockRegistryKey");

	/*
		Port API
	*/
	NtCreatePort = (pfNtCreatePort)::GetProcAddress(hModule, "NtCreatePort");
	NtCreateWaitablePort = (pfNtCreateWaitablePort)::GetProcAddress(hModule, "NtCreateWaitablePort");
	NtConnectPort = (pfNtConnectPort)::GetProcAddress(hModule, "NtConnectPort");
	NtSecureConnectPort = (pfNtSecureConnectPort)::GetProcAddress(hModule, "NtSecureConnectPort");
	NtAlpcCreatePort = (pfNtAlpcCreatePort)::GetProcAddress(hModule, "NtAlpcCreatePort");
	NtAlpcConnectPort = (pfNtAlpcConnectPort)::GetProcAddress(hModule, "NtAlpcConnectPort");
	NtAlpcConnectPortEx = (pfNtAlpcConnectPortEx)::GetProcAddress(hModule, "NtAlpcConnectPortEx");

	/*
		ATOM API
	*/
	NtAddAtom = (pfNtAddAtom)::GetProcAddress(hModule, "NtAddAtom");
	NtAddAtomEx = (pfNtAddAtomEx)::GetProcAddress(hModule, "NtAddAtomEx");
	NtFindAtom = (pfNtFindAtom)::GetProcAddress(hModule, "NtFindAtom");

	/*
		Driver API
	*/
	NtLoadDriver = (pfNtLoadDriver)::GetProcAddress(hModule, "NtLoadDriver");
	NtUnloadDriver = (pfNtUnloadDriver)::GetProcAddress(hModule, "NtUnloadDriver");

	/*
		Transaction API
	*/
	NtCreateTransaction  = (pfNtCreateTransaction)::GetProcAddress(hModule, "NtCreateTransaction");
	NtOpenTransaction  = (pfNtOpenTransaction)::GetProcAddress(hModule, "NtOpenTransaction");
	NtCommitTransaction = (pfNtCommitTransaction)::GetProcAddress(hModule, "NtCommitTransaction");
	NtRollbackTransaction = (pfNtRollbackTransaction)::GetProcAddress(hModule, "NtRollbackTransaction");

	/*
		Security API
	*/
	NtQuerySecurityObject = (pfNtQuerySecurityObject)::GetProcAddress(hModule, "NtQuerySecurityObject");
	NtSetSecurityObject = (pfNtSetSecurityObject)::GetProcAddress(hModule, "NtSetSecurityObject");
	RtlFlushSecureMemoryCache = (pfRtlFlushSecureMemoryCache)::GetProcAddress(hModule, "RtlFlushSecureMemoryCache");
}

ntdllapi::~ntdllapi(void)
{
}


ntdllapi* ntdllapi::GetInstance()
{
	static ntdllapi _ntdllAPI;
	return &_ntdllAPI;
}

}