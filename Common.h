/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#pragma once

/* Include core defs */
#include <windows.h>
#include <wininet.h>
#include <windns.h>
#include <ntstatus.h>
#include "Native.h"
#include "Macros.h"

typedef struct __attribute__((packed))
{
    HANDLE hHeap;
} DATA, *PDATA ;

/* Include Library */
#include "Labels.h"
#include "Hash.h"
#include "Peb.h"
#include "Ldr.h"
#include "Pe.h"

/* Include Hooks! */
#include "hooks/GetProcessHeap.h"
#include "hooks/Sleep.h"
