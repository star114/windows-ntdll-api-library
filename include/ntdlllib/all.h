#pragma once

#if _MT
#if _DLL
#define _crt_opt_str       "_md"
#else   // #if _DLL
#define _crt_opt_str       "_mt"
#endif  // #if _DLL
#else   // #if _MT
#define _crt_opt_str       ""
#endif  // #if _MT

#ifdef _DEBUG
#define _configuration_str "d"
#else
#define _configuration_str ""
#endif

#define _lib_filename      "ntdlllib"         \
                           _crt_opt_str       \
                           _configuration_str \
                           ".lib"

#pragma comment(lib, _lib_filename)

#include <ntdlllib/ntdll.h>
#include <ntdlllib/ntstatus.h>
#include <ntdlllib/ntdllapi.h>
//#include <ntdlllib/ntdllutil.h>

using namespace ntdlllib;