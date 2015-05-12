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

	void ntdllutil::CloseHandle(HANDLE handle)
	{
		if (NULL != handle)
			ntdllapi::GetInstance()->NtClose(handle);
	}
}