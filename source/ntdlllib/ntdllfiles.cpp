#include <ntdlllib/all.h>

namespace ntdlllib
{
	HANDLE ntdllfiles::CreateFile_ntdll(std::wstring& strPath)
	{
		HANDLE handle = NULL;

		std::wstring strKernelPath = ntdllutil::ToKernelPath(strPath);

		UNICODE_STRING usz = { 0, };
		ntdllutil::StringToUnicodeString(strKernelPath, &usz);

		OBJECT_ATTRIBUTES oa = { 0, };
		InitializeObjectAttributes(&oa, &usz, OBJ_CASE_INSENSITIVE, NULL, NULL);
		IO_STATUS_BLOCK iostatusblock = { 0, };

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
		
		return handle;
	}
}