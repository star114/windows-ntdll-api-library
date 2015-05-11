#pragma once
#include <ntdlllib/ntdll.h>
#include <string>

namespace ntdlllib
{
	class ntdllobj
	{
	public:
		static bool QueryDeviceName(HANDLE hGlobalDirectory, const std::wstring& strInDeviceName, std::wstring& strSymDeviceName);
		static HANDLE OpenSymbolicLink(HANDLE hRootDirectory, const std::wstring& strName);
		static HANDLE OpenGlobalDirectoryObject();
		static HANDLE OpenDirectoryObject(const std::wstring& strDirectoryName);
	private:
	};
}