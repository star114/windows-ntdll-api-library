#pragma once
#include <string>

namespace ntdlllib
{
	class ntdllfiles
	{
	public:
		/*
			CreateFile_ntdll
			Input : 
				Path - path that you want to create or open.
			Output :
				Handle - handle of input path file if it succeeds to create or open.
						if it fails, returns NULL
			After using handle, handle must be closed via ntclose function.
		*/
		static HANDLE CreateFile_ntdll(std::wstring& strPath);
	private:
	};
}