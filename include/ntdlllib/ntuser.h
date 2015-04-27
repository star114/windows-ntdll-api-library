#pragma once

namespace ntdlllib
{

typedef struct _LARGE_STRING
{
	ULONG Length;
	ULONG MaximumLength:31;
	ULONG bAnsi:1;
	PVOID Buffer;
} LARGE_STRING, *PLARGE_STRING;


#define DWORD_ALIGN(pAddr)	((LPWORD)(((DWORD_PTR)pAddr + 3) & ~3))

#pragma pack(push, 1)

typedef struct {
	WORD dlgVer;
	WORD signature;
	DWORD helpID;
	DWORD exStyle;
	DWORD style;
	WORD cDlgItems;
	short x;
	short y;
	short cx;
	short cy;
	// 	sz_Or_Ord menu;
	// 	sz_Or_Ord windowClass;
	// 	WCHAR title[titleLen];
	// 	WORD pointsize;
	// 	WORD weight;
	// 	BYTE italic;
	// 	BYTE charset;
	// 	WCHAR typeface[stringLen];
} DLGTEMPLATEEX;
typedef DLGTEMPLATEEX* LPDLGTEMPLATEEX;

typedef struct {
	DWORD helpID;
	DWORD exStyle;
	DWORD style;
	short x;
	short y;
	short cx;
	short cy;
	DWORD id;
	// 	sz_Or_Ord windowClass;
	// 	sz_Or_Ord title;
	// 	WORD extraCount;
} DLGITEMTEMPLATEEX;
typedef DLGITEMTEMPLATEEX* LPDLGITEMTEMPLATEEX;

#pragma pack(pop)

}