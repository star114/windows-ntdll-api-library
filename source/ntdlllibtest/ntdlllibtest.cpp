#include <tchar.h>
#include <stdio.h>
#include <Windows.h>
#include <ntdlllib/all.h>

int main(int argc, _TCHAR* argv)
{
	std::wstring strPath = L"C:\\temp\\test.txt";
	IO_STATUS_BLOCK iostatusblock = { 0, };
	HANDLE handle = ntdllfiles::CreateFile(strPath, &iostatusblock);

	printf("strPath:%ws - handle:%x\n", strPath.c_str(), (DWORD)handle);

	if (FILE_CREATED & iostatusblock.Information)
		printf("created file.\n");
	else if (FILE_OPENED & iostatusblock.Information)
		printf("opened file.\n");

	ntdllutil::CloseHandle(handle);

	std::wstring strDestinationPath = L"C:\\temp\\test2.txt";
	bool f = ntdllfiles::CopyFile(strPath, strDestinationPath);
	if (f)
		printf("copy file %ws to %ws success\n", strPath.c_str(), strDestinationPath.c_str());
	else
		printf("copy file failed.\n");

	return 0;
}