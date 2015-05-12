#pragma once
#include <string>

namespace ntdlllib
{
	class ntdllfiles
	{
	public:
		/*
			ToKernelPath
				return path starts with \??\.
			FromKernelPath
				return path removed \??\
		*/
		static std::wstring ToKernelPath(const std::wstring& str);
		static std::wstring FromKernelPath(const std::wstring& strKernelPath);
		/*
			CreateFile
			Input : 
				strPath - path that you want to create or open.
				piostatusblock - iostatusblock pointer
			Output :
				Handle - handle of input path file if it succeeds to create or open.
						if it fails, returns NULL
			After using handle, handle must be closed via ntclose function.
		*/
		static HANDLE CreateFile(const std::wstring& strPath);
		static HANDLE CreateFile(const std::wstring& strPath, PIO_STATUS_BLOCK piostatusblock);

		/*
			CopyFile
			Input :
				strSourcePath - source path to copy
				strDestinationPath - destination path to copy
			Output :
				bool - return true when succeed to copy, or return  false.
		*/
		static bool CopyFile(const std::wstring& strSourcePath, const std::wstring& strDestinationPath);
	private:
	};
}