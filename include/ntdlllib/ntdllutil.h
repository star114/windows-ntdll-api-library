#pragma once
#include <ntdlllib/ntdll.h>
#include <string>

namespace ntdlllib
{

class ntdllutil
{ 
public:
	static BOOL UnicodeStringToString(PUNICODE_STRING pusz, std::wstring& str);
	static BOOL MoveStringToUnicodeString(std::wstring const& str, PUNICODE_STRING pusz);
	static BOOL StringToUnicodeString(std::wstring const& str, PUNICODE_STRING pusz);
	static void FreeUnicodeString(PUNICODE_STRING pusz);

	static bool QueryDeviceName(HANDLE hGlobalDirectory, const std::wstring& strInDeviceName, std::wstring& strSymDeviceName);
	static HANDLE OpenSymbolicLink(HANDLE hRootDirectory, const std::wstring& strName);
	static HANDLE OpenGlobalDirectoryObject();
	static HANDLE OpenDirectoryObject( const std::wstring& strDirectoryName);
private:
};
}