# windows-ntdll-api-library

we can use ntdll apis (including exported apis and not exported apids) easily.   
just link library to your project.

it will be updated steadily.

## How to Use   
1. include all.h file.   
  * *include*   
    * /ntdlllib   
      * all.h   

2. add library path (lib/win32 or lib/x64) to additional library dicectory.   

3. automatically link static linking library correctly.   
  * *lib*   
    * /Win32   
      * ntdlllib_md.lib   
      * ntdlllib_mdd.lib   
      * ntdlllib_mt.lib   
      * ntdlllib_mtd.lib   
    * /x64   
      * ntdlllib_md.lib   
      * ntdlllib_mdd.lib   
      * ntdlllib_mt.lib   
      * ntdlllib_mtd.lib   

## Build
* Configure     
  * Debug   
  * Debug DLL   
  * Release   
  * Release DLL   
* Platform   
  * Win32   
  * x64   
* Output File Naming   
  * md - multi thread dll   
  * mt - multi thread   
  * d - debug   

### Tools
visual studio 2013

### License
MIT
