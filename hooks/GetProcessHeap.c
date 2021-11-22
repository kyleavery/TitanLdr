#include "Common.h"

D_SEC( D ) HANDLE WINAPI GetProcessHeap_Hook() 
{
	return ((PDATA) G_SYM(Hooks))->hHeap;
};
