#ifndef _PH_PHBASE_H
#define _PH_PHBASE_H

#pragma once

#ifndef PHLIB_NO_DEFAULT_LIB
#pragma comment(lib, "ntdll.lib")

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "version.lib")
#endif

// nonstandard extension used : nameless struct/union
#pragma warning(disable: 4201)
// nonstandard extension used : bit field types other than int
#pragma warning(disable: 4214)
// 'function': attributes not present on previous declaration
#pragma warning(disable: 4985)

#ifndef UNICODE
#define UNICODE
#endif

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#if !defined(_PHLIB_)
#define PHLIBAPI __declspec(dllimport)
#else
#define PHLIBAPI
#endif

#include <phnt_windows.h>
#include <phnt.h>
#include <phsup.h>
#include <ref.h>
#include <queuedlock.h>
#include <stdlib.h>

#include <phconfig.h>
#include <phbasesup.h>
#include <phdata.h>

#endif