#include <ntdlllib/all.h>

namespace ntdlllib
{
	bool ntdllobj::QueryDeviceName(HANDLE hGlobalDirectory, const std::wstring& strInDeviceName, std::wstring& strSymDeviceName)
	{
		bool fSuccess = false;

		HANDLE hSymbolicLink = OpenSymbolicLink(hGlobalDirectory, strInDeviceName);
		if (hSymbolicLink)
		{
			wchar_t* wc[256];
			UNICODE_STRING uszValue;
			uszValue.Length = 256 * (USHORT)sizeof(wchar_t);
			uszValue.MaximumLength = uszValue.Length + sizeof(wchar_t);
			uszValue.Buffer = (PWSTR)wc;

			NTSTATUS status = ntdllapi::GetInstance()->NtQuerySymbolicLinkObject(hSymbolicLink, &uszValue, NULL);
			if (NT_SUCCESS(status))
			{
				ntdllutil::UnicodeStringToString(&uszValue, strSymDeviceName);
				fSuccess = true;
			}

			ntdllutil::CloseHandle(hSymbolicLink);
		}

		return fSuccess;
	}

	HANDLE ntdllobj::OpenSymbolicLink(HANDLE hRootDirectory, const std::wstring& strName)
	{
		HANDLE hSymbolicLink = NULL;

		NTSTATUS status;
		OBJECT_ATTRIBUTES oa;
		UNICODE_STRING usz;
		PSECURITY_DESCRIPTOR pSD = NULL;
		ntdllutil::MoveStringToUnicodeString(strName, &usz);
		InitializeObjectAttributes(&oa, &usz, NULL, hRootDirectory, pSD);

		status = ntdllapi::GetInstance()->NtOpenSymbolicLinkObject(&hSymbolicLink, SYMBOLIC_LINK_QUERY, &oa);
		if (NULL != pSD)
			::LocalFree(pSD);

		return hSymbolicLink;
	}


	HANDLE ntdllobj::OpenDirectoryObject(const std::wstring& strDirectoryName)
	{
		HANDLE hDirectory = NULL;

		OBJECT_ATTRIBUTES oa;
		UNICODE_STRING usz;
		PSECURITY_DESCRIPTOR pSD = NULL;
		ntdllutil::MoveStringToUnicodeString(strDirectoryName, &usz);
		InitializeObjectAttributes(&oa, &usz, NULL, NULL, pSD);

		NTSTATUS status = ntdllapi::GetInstance()->NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &oa);
		if (NULL != pSD)
			::LocalFree(pSD);
		if (!NT_SUCCESS(status))
			throw;

		return hDirectory;
	}

	HANDLE ntdllobj::OpenGlobalDirectoryObject()
	{
		return OpenDirectoryObject(L"\\GLOBAL??");
	}

}