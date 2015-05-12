#include <ntdlllib/all.h>

namespace ntdlllib
{
	std::wstring ntdllfiles::ToKernelPath(const std::wstring& str)
	{
		std::wstring strKernelPath;

		if (!str.compare(0, 4, L"\\??\\"))
			strKernelPath = str;
		else
			strKernelPath = L"\\??\\" + str;

		return strKernelPath;
	}

	std::wstring ntdllfiles::FromKernelPath(const std::wstring& strKernelPath)
	{
		std::wstring strPath;

		if (!strKernelPath.compare(0, 4, L"\\??\\"))
			strPath = strKernelPath.substr(4);
		else
			strPath = strKernelPath;

		return strPath;
	}

	HANDLE ntdllfiles::CreateFile(const std::wstring& strPath)
	{
		IO_STATUS_BLOCK iostatusblock = { 0, };
		return CreateFile(strPath, &iostatusblock);
	}
	HANDLE ntdllfiles::CreateFile(const std::wstring& strPath, PIO_STATUS_BLOCK piostatusblock)
	{
		HANDLE handle = NULL;

		std::wstring strKernelPath = ToKernelPath(strPath);

		UNICODE_STRING usz = { 0, };
		ntdllutil::StringToUnicodeString(strKernelPath, &usz);

		OBJECT_ATTRIBUTES oa = { 0, };
		InitializeObjectAttributes(&oa, &usz, OBJ_CASE_INSENSITIVE, NULL, NULL);

		NTSTATUS status = ntdllapi::GetInstance()->NtCreateFile(
			&handle,
			FILE_GENERIC_READ | FILE_GENERIC_WRITE,
			&oa,
			piostatusblock,
			0,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN_IF,
			0,
			0,
			0);

		ntdllutil::FreeUnicodeString(&usz);
		return handle;
	}
	bool ntdllfiles::CopyFile(const std::wstring& strSourcePath, const std::wstring& strDestinationPath)
	{
		bool f = false;

		NTSTATUS status = STATUS_SUCCESS;
		UNICODE_STRING uszSourcePath = { 0 };
		UNICODE_STRING uszDestinationPath = { 0 };
		OBJECT_ATTRIBUTES oaSource = { 0 };
		OBJECT_ATTRIBUTES oaDestination = { 0 };
		HANDLE hSource = NULL;
		HANDLE hDestination = NULL;
		FILE_BASIC_INFORMATION FileInformation = { 0 };

		do
		{
			if (0 == strSourcePath.compare(strDestinationPath))
				break;

			std::wstring strSourceKernelPath = ToKernelPath(strSourcePath);
			std::wstring strDestinationKernelPath = ToKernelPath(strDestinationPath);

			if (0 == strSourceKernelPath.compare(strDestinationKernelPath))
				break;

			ntdllutil::StringToUnicodeString(strSourceKernelPath, &uszSourcePath);
			InitializeObjectAttributes(&oaSource, &uszSourcePath, NULL, NULL, NULL);
			ntdllutil::StringToUnicodeString(strDestinationKernelPath, &uszDestinationPath);
			InitializeObjectAttributes(&oaDestination, &uszDestinationPath, NULL, NULL, NULL);

			IO_STATUS_BLOCK iostatus;
			status = ntdllapi::GetInstance()->NtCreateFile(
				&hSource,
				FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
				&oaSource,
				&iostatus,
				0,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				FILE_OPEN,
				FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
				NULL,
				0
				);
			if (!NT_SUCCESS(status))
				break;


			status = ntdllapi::GetInstance()->NtCreateFile(
				&hDestination,
				FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | WRITE_DAC | SYNCHRONIZE,
				&oaDestination,
				&iostatus,
				0,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ,
				FILE_OVERWRITE_IF,
				FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
				NULL,
				0
				);
			if (!NT_SUCCESS(status))
				break;
			

			byte ab[65536];
			memset(ab, 0, 65536);
			unsigned int uBytesRead = 0;
			do
			{
				status = ntdllapi::GetInstance()->NtReadFile(
					hSource,
					NULL,
					NULL,
					NULL,
					&iostatus,
					(PVOID)ab,
					65536,
					NULL,
					NULL
					);
				if (!NT_SUCCESS(status))
					break;

				uBytesRead = iostatus.Information;
				ntdllapi::GetInstance()->NtWriteFile(
					hDestination,
					NULL,
					NULL,
					NULL,
					&iostatus,
					(PVOID)ab,
					uBytesRead,
					NULL,
					NULL
					);
				if (!NT_SUCCESS(status))
					break;

			} while (NT_SUCCESS(status));

			status = ntdllapi::GetInstance()->NtQueryInformationFile(
				hSource,
				&iostatus,
				&FileInformation,
				sizeof(FileInformation),
				FileBasicInformation
				);
			if (!NT_SUCCESS(status))
				break;

			status = ntdllapi::GetInstance()->NtSetInformationFile(
				hDestination,
				&iostatus,
				&FileInformation,
				sizeof(FileInformation),
				FileBasicInformation
				);
			if (!NT_SUCCESS(status))
				break;

			memset(ab, 0, 65536);
			ULONG ulReturnLength = 0;
			status = ntdllapi::GetInstance()->NtQuerySecurityObject(hSource, DACL_SECURITY_INFORMATION, ab, 65536, &ulReturnLength);
			if (NT_SUCCESS(status))
			{
				status = ntdllapi::GetInstance()->NtSetSecurityObject(hDestination, DACL_SECURITY_INFORMATION, ab);
			}

			f = true;
		}
		while (false);

		ntdllutil::FreeUnicodeString(&uszSourcePath);
		ntdllutil::FreeUnicodeString(&uszDestinationPath);
		ntdllutil::CloseHandle(hSource);
		ntdllutil::CloseHandle(hDestination);

		return f;
	}
}