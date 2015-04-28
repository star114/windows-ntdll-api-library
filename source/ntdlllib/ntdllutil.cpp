#include <ntdlllib/all.h>

namespace ntdlllib
{

BOOL ntdllutil::UnicodeStringToString(PUNICODE_STRING pusz, std::wstring& str)
{
	if (NULL == pusz)
		return FALSE;
	if (0 == pusz->Length)
	{
		str = std::wstring(L"");
		return TRUE;
	}

	str = std::wstring(pusz->Buffer, 0, pusz->Length / sizeof(wchar_t));

	return TRUE;
}

BOOL ntdllutil::MoveStringToUnicodeString(std::wstring const& str, PUNICODE_STRING pusz)
{
	if (NULL == pusz)
		return FALSE;

	pusz->Length = str.size() * (USHORT)sizeof(wchar_t);
	pusz->MaximumLength = (str.size() + 1) * (USHORT)sizeof(wchar_t);
	pusz->Buffer = (wchar_t*)str.c_str();

	return TRUE;
}

BOOL ntdllutil::StringToUnicodeString(std::wstring const& str, PUNICODE_STRING pusz)
{
	if (NULL == pusz)
		return FALSE;

	pusz->Length = str.size() * (USHORT)sizeof(wchar_t);
	pusz->MaximumLength = (str.size() + 1) * (USHORT)sizeof(wchar_t);
	pusz->Buffer = (wchar_t*)malloc(pusz->MaximumLength);
	memcpy(pusz->Buffer, (const wchar_t*)str.c_str(), pusz->MaximumLength);

	return TRUE;
}

void ntdllutil::FreeUnicodeString(PUNICODE_STRING pusz)
{
	if (NULL != pusz && NULL != pusz->Buffer)
	{
		free(pusz->Buffer);
		pusz->Buffer = NULL;
	}
}

bool ntdllutil::QueryDeviceName(HANDLE hGlobalDirectory, const std::wstring& strInDeviceName, std::wstring& strSymDeviceName)
{
	bool fSuccess = false;

	HANDLE hSymbolicLink = OpenSymbolicLink(hGlobalDirectory, strInDeviceName);
	if (hSymbolicLink)
	{
		wchar_t* wc[256];
		UNICODE_STRING uszValue;
		uszValue.Length = 256 * (USHORT)sizeof(wchar_t);
		uszValue.MaximumLength = uszValue.Length + sizeof(wchar_t);
		uszValue.Buffer = (PWSTR) wc;

		NTSTATUS status = ntdllapi::GetInstance()->NtQuerySymbolicLinkObject(hSymbolicLink, &uszValue, NULL);
		if (NT_SUCCESS(status))
		{
			ntdllutil::UnicodeStringToString(&uszValue, strSymDeviceName);
			fSuccess = true;
		}

		ntdllapi::GetInstance()->NtClose(hSymbolicLink);
	}

	return fSuccess;
}

HANDLE ntdllutil::OpenSymbolicLink(HANDLE hRootDirectory, const std::wstring& strName)
{
	HANDLE hSymbolicLink = NULL;

	NTSTATUS status;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING usz;
	PSECURITY_DESCRIPTOR pSD = NULL;
	ntdllutil::MoveStringToUnicodeString(strName, &usz);
	InitializeObjectAttributes(&oa, &usz, NULL, hRootDirectory, pSD);

	status = ntdllapi::GetInstance()->NtOpenSymbolicLinkObject(&hSymbolicLink, SYMBOLIC_LINK_QUERY, &oa);
	if(NULL != pSD)
		::LocalFree(pSD);

	return hSymbolicLink;
}


HANDLE ntdllutil::OpenDirectoryObject( const std::wstring& strDirectoryName)
{
	HANDLE hDirectory = NULL;

	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING usz;
	PSECURITY_DESCRIPTOR pSD = NULL;
	ntdllutil::MoveStringToUnicodeString(strDirectoryName, &usz);
	InitializeObjectAttributes(&oa, &usz, NULL, NULL, pSD);

	NTSTATUS status = ntdllapi::GetInstance()->NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &oa);
	if(NULL != pSD)
		::LocalFree(pSD);
	if (!NT_SUCCESS(status))
		throw;

	return hDirectory;
}

HANDLE ntdllutil::OpenGlobalDirectoryObject()
{
	return OpenDirectoryObject(L"\\GLOBAL??");
}

}