#include <tchar.h>
#include <stdio.h>
#include <Windows.h>
#include <ntdlllib/all.h>

int main(int argc, _TCHAR* argv)
{
	// NtCreateFile must use kernel Path
	std::wstring strPath = L"\\??\\C:\\temp\\test.txt";
	
	UNICODE_STRING usz = { 0, };
	ntdllutil::StringToUnicodeString(strPath, &usz);
	
	OBJECT_ATTRIBUTES oa = { 0, };
	InitializeObjectAttributes(&oa, &usz, OBJ_CASE_INSENSITIVE, NULL, NULL);
	IO_STATUS_BLOCK iostatusblock = { 0, };
	HANDLE handle = NULL;
	NTSTATUS status = ntdllapi::GetInstance()->NtCreateFile(
		&handle,
		FILE_GENERIC_READ | FILE_GENERIC_WRITE,
		&oa,
		&iostatusblock,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN_IF,
		0,
		0,
		0);
	if (NT_SUCCESS(status))
		printf("%ws : handle - 0x%x information - 0x%x \n", strPath, (DWORD)handle, (DWORD) iostatusblock.Information);
	else
		printf("NtCreateFile failed with 0x%x\n", (DWORD)status);

	if (NULL != handle)
		ntdllapi::GetInstance()->NtClose(handle);

	if (FILE_CREATED & iostatusblock.Information)
		printf("success to create\n");
	else if (FILE_OPENED & iostatusblock.Information)
		printf("success to open\n");

	return 0;
}