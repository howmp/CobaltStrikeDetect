#ifndef _PH_PHUTIL_H
#define _PH_PHUTIL_H

#ifdef __cplusplus
extern "C" {
#endif

extern WCHAR *PhSizeUnitNames[7];
extern ULONG PhMaxSizeUnit;

typedef struct _PH_INTEGER_PAIR
{
    LONG X;
    LONG Y;
} PH_INTEGER_PAIR, *PPH_INTEGER_PAIR;

typedef struct _PH_SCALABLE_INTEGER_PAIR
{
    union
    {
        PH_INTEGER_PAIR Pair;
        struct
        {
            LONG X;
            LONG Y;
        };
    };
    ULONG Scale;
} PH_SCALABLE_INTEGER_PAIR, *PPH_SCALABLE_INTEGER_PAIR;

typedef struct _PH_RECTANGLE
{
    union
    {
        PH_INTEGER_PAIR Position;
        struct
        {
            LONG Left;
            LONG Top;
        };
    };
    union
    {
        PH_INTEGER_PAIR Size;
        struct
        {
            LONG Width;
            LONG Height;
        };
    };
} PH_RECTANGLE, *PPH_RECTANGLE;

FORCEINLINE
PH_RECTANGLE
PhRectToRectangle(
    _In_ RECT Rect
    )
{
    PH_RECTANGLE rectangle;

    rectangle.Left = Rect.left;
    rectangle.Top = Rect.top;
    rectangle.Width = Rect.right - Rect.left;
    rectangle.Height = Rect.bottom - Rect.top;

    return rectangle;
}

FORCEINLINE
RECT
PhRectangleToRect(
    _In_ PH_RECTANGLE Rectangle
    )
{
    RECT rect;

    rect.left = Rectangle.Left;
    rect.top = Rectangle.Top;
    rect.right = Rectangle.Left + Rectangle.Width;
    rect.bottom = Rectangle.Top + Rectangle.Height;

    return rect;
}

FORCEINLINE
VOID
PhConvertRect(
    _Inout_ PRECT Rect,
    _In_ PRECT ParentRect
    )
{
    Rect->right = ParentRect->right - ParentRect->left - Rect->right;
    Rect->bottom = ParentRect->bottom - ParentRect->top - Rect->bottom;
}

FORCEINLINE
RECT
PhMapRect(
    _In_ RECT InnerRect,
    _In_ RECT OuterRect
    )
{
    RECT rect;

    rect.left = InnerRect.left - OuterRect.left;
    rect.top = InnerRect.top - OuterRect.top;
    rect.right = InnerRect.right - OuterRect.left;
    rect.bottom = InnerRect.bottom - OuterRect.top;

    return rect;
}

PHLIBAPI
VOID
NTAPI
PhAdjustRectangleToBounds(
    _Inout_ PPH_RECTANGLE Rectangle,
    _In_ PPH_RECTANGLE Bounds
    );

PHLIBAPI
VOID
NTAPI
PhCenterRectangle(
    _Inout_ PPH_RECTANGLE Rectangle,
    _In_ PPH_RECTANGLE Bounds
    );

PHLIBAPI
VOID
NTAPI
PhAdjustRectangleToWorkingArea(
    _In_opt_ HWND hWnd,
    _Inout_ PPH_RECTANGLE Rectangle
    );

PHLIBAPI
VOID
NTAPI
PhCenterWindow(
    _In_ HWND WindowHandle,
    _In_opt_ HWND ParentWindowHandle
    );

FORCEINLINE
VOID
PhLargeIntegerToSystemTime(
    _Out_ PSYSTEMTIME SystemTime,
    _In_ PLARGE_INTEGER LargeInteger
    )
{
    FILETIME fileTime;

    fileTime.dwLowDateTime = LargeInteger->LowPart;
    fileTime.dwHighDateTime = LargeInteger->HighPart;
    FileTimeToSystemTime(&fileTime, SystemTime);
}

FORCEINLINE
VOID
PhLargeIntegerToLocalSystemTime(
    _Out_ PSYSTEMTIME SystemTime,
    _In_ PLARGE_INTEGER LargeInteger
    )
{
    FILETIME fileTime;
    FILETIME newFileTime;

    fileTime.dwLowDateTime = LargeInteger->LowPart;
    fileTime.dwHighDateTime = LargeInteger->HighPart;
    FileTimeToLocalFileTime(&fileTime, &newFileTime);
    FileTimeToSystemTime(&newFileTime, SystemTime);
}

PHLIBAPI
VOID
NTAPI
PhReferenceObjects(
    _In_reads_(NumberOfObjects) PVOID *Objects,
    _In_ ULONG NumberOfObjects
    );

PHLIBAPI
VOID
NTAPI
PhDereferenceObjects(
    _In_reads_(NumberOfObjects) PVOID *Objects,
    _In_ ULONG NumberOfObjects
    );

PHLIBAPI
PPH_STRING
NTAPI
PhGetMessage(
    _In_ PVOID DllHandle,
    _In_ ULONG MessageTableId,
    _In_ ULONG MessageLanguageId,
    _In_ ULONG MessageId
    );

PHLIBAPI
PPH_STRING
NTAPI
PhGetNtMessage(
    _In_ NTSTATUS Status
    );

PHLIBAPI
PPH_STRING
NTAPI
PhGetWin32Message(
    _In_ ULONG Result
    );

PHLIBAPI
INT
NTAPI
PhShowMessage(
    _In_ HWND hWnd,
    _In_ ULONG Type,
    _In_ PWSTR Format,
    ...
    );

PHLIBAPI
INT
NTAPI
PhShowMessage_V(
    _In_ HWND hWnd,
    _In_ ULONG Type,
    _In_ PWSTR Format,
    _In_ va_list ArgPtr
    );

#define PhShowError(hWnd, Format, ...) PhShowMessage(hWnd, MB_OK | MB_ICONERROR, Format, __VA_ARGS__)
#define PhShowWarning(hWnd, Format, ...) PhShowMessage(hWnd, MB_OK | MB_ICONWARNING, Format, __VA_ARGS__)
#define PhShowInformation(hWnd, Format, ...) PhShowMessage(hWnd, MB_OK | MB_ICONINFORMATION, Format, __VA_ARGS__)

PHLIBAPI
PPH_STRING
NTAPI
PhGetStatusMessage(
    _In_ NTSTATUS Status,
    _In_opt_ ULONG Win32Result
    );

PHLIBAPI
VOID
NTAPI
PhShowStatus(
    _In_ HWND hWnd,
    _In_opt_ PWSTR Message,
    _In_ NTSTATUS Status,
    _In_opt_ ULONG Win32Result
    );

PHLIBAPI
BOOLEAN
NTAPI
PhShowContinueStatus(
    _In_ HWND hWnd,
    _In_opt_ PWSTR Message,
    _In_ NTSTATUS Status,
    _In_opt_ ULONG Win32Result
    );

PHLIBAPI
BOOLEAN
NTAPI
PhShowConfirmMessage(
    _In_ HWND hWnd,
    _In_ PWSTR Verb,
    _In_ PWSTR Object,
    _In_opt_ PWSTR Message,
    _In_ BOOLEAN Warning
    );

PHLIBAPI
BOOLEAN
NTAPI
PhFindIntegerSiKeyValuePairs(
    _In_ PPH_KEY_VALUE_PAIR KeyValuePairs,
    _In_ ULONG SizeOfKeyValuePairs,
    _In_ PWSTR String,
    _Out_ PULONG Integer
    );

PHLIBAPI
BOOLEAN
NTAPI
PhFindStringSiKeyValuePairs(
    _In_ PPH_KEY_VALUE_PAIR KeyValuePairs,
    _In_ ULONG SizeOfKeyValuePairs,
    _In_ ULONG Integer,
    _Out_ PWSTR *String
    );

#define GUID_VERSION_MAC 1
#define GUID_VERSION_DCE 2
#define GUID_VERSION_MD5 3
#define GUID_VERSION_RANDOM 4
#define GUID_VERSION_SHA1 5

#define GUID_VARIANT_NCS_MASK 0x80
#define GUID_VARIANT_NCS 0x00
#define GUID_VARIANT_STANDARD_MASK 0xc0
#define GUID_VARIANT_STANDARD 0x80
#define GUID_VARIANT_MICROSOFT_MASK 0xe0
#define GUID_VARIANT_MICROSOFT 0xc0
#define GUID_VARIANT_RESERVED_MASK 0xe0
#define GUID_VARIANT_RESERVED 0xe0

typedef union _GUID_EX
{
    GUID Guid;
    UCHAR Data[16];
    struct
    {
        ULONG TimeLowPart;
        USHORT TimeMidPart;
        USHORT TimeHighPart;
        UCHAR ClockSequenceHigh;
        UCHAR ClockSequenceLow;
        UCHAR Node[6];
    } s;
    struct
    {
        ULONG Part0;
        USHORT Part32;
        UCHAR Part48;
        UCHAR Part56 : 4;
        UCHAR Version : 4;
        UCHAR Variant;
        UCHAR Part72;
        USHORT Part80;
        ULONG Part96;
    } s2;
} GUID_EX, *PGUID_EX;

PHLIBAPI
VOID
NTAPI
PhGenerateGuid(
    _Out_ PGUID Guid
    );

PHLIBAPI
VOID
NTAPI
PhGenerateGuidFromName(
    _Out_ PGUID Guid,
    _In_ PGUID Namespace,
    _In_ PCHAR Name,
    _In_ ULONG NameLength,
    _In_ UCHAR Version
    );

PHLIBAPI
VOID
NTAPI
PhGenerateRandomAlphaString(
    _Out_writes_z_(Count) PWSTR Buffer,
    _In_ ULONG Count
    );

PHLIBAPI
PPH_STRING
NTAPI
PhEllipsisString(
    _In_ PPH_STRING String,
    _In_ ULONG DesiredCount
    );

PHLIBAPI
PPH_STRING
NTAPI
PhEllipsisStringPath(
    _In_ PPH_STRING String,
    _In_ ULONG DesiredCount
    );

PHLIBAPI
BOOLEAN
NTAPI
PhMatchWildcards(
    _In_ PWSTR Pattern,
    _In_ PWSTR String,
    _In_ BOOLEAN IgnoreCase
    );

PHLIBAPI
PPH_STRING
NTAPI
PhEscapeStringForMenuPrefix(
    _In_ PPH_STRINGREF String
    );

PHLIBAPI
LONG
NTAPI
PhCompareUnicodeStringZIgnoreMenuPrefix(
    _In_ PWSTR A,
    _In_ PWSTR B,
    _In_ BOOLEAN IgnoreCase,
    _In_ BOOLEAN MatchIfPrefix
    );

PHLIBAPI
PPH_STRING
NTAPI
PhFormatDate(
    _In_opt_ PSYSTEMTIME Date,
    _In_opt_ PWSTR Format
    );

PHLIBAPI
PPH_STRING
NTAPI
PhFormatTime(
    _In_opt_ PSYSTEMTIME Time,
    _In_opt_ PWSTR Format
    );

PHLIBAPI
PPH_STRING
NTAPI
PhFormatDateTime(
    _In_opt_ PSYSTEMTIME DateTime
    );

#define PhaFormatDateTime(DateTime) PH_AUTO_T(PH_STRING, PhFormatDateTime(DateTime))

PHLIBAPI
PPH_STRING
NTAPI
PhFormatTimeSpan(
    _In_ ULONG64 Ticks,
    _In_opt_ ULONG Mode
    );

PHLIBAPI
PPH_STRING
NTAPI
PhFormatTimeSpanRelative(
    _In_ ULONG64 TimeSpan
    );

PHLIBAPI
PPH_STRING
NTAPI
PhFormatUInt64(
    _In_ ULONG64 Value,
    _In_ BOOLEAN GroupDigits
    );

#define PhaFormatUInt64(Value, GroupDigits) PH_AUTO_T(PH_STRING, PhFormatUInt64((Value), (GroupDigits)))

PHLIBAPI
PPH_STRING
NTAPI
PhFormatDecimal(
    _In_ PWSTR Value,
    _In_ ULONG FractionalDigits,
    _In_ BOOLEAN GroupDigits
    );

#define PhaFormatDecimal(Value, FractionalDigits, GroupDigits) \
    PH_AUTO_T(PH_STRING, PhFormatDecimal((Value), (FractionalDigits), (GroupDigits)))

PHLIBAPI
PPH_STRING
NTAPI
PhFormatSize(
    _In_ ULONG64 Size,
    _In_ ULONG MaxSizeUnit
    );

#define PhaFormatSize(Size, MaxSizeUnit) PH_AUTO_T(PH_STRING, PhFormatSize((Size), (MaxSizeUnit)))

PHLIBAPI
PPH_STRING
NTAPI
PhFormatGuid(
    _In_ PGUID Guid
    );

PHLIBAPI
PVOID
NTAPI
PhGetFileVersionInfo(
    _In_ PWSTR FileName
    );

PHLIBAPI
ULONG
NTAPI
PhGetFileVersionInfoLangCodePage(
    _In_ PVOID VersionInfo
    );

PHLIBAPI
PPH_STRING
NTAPI
PhGetFileVersionInfoString(
    _In_ PVOID VersionInfo,
    _In_ PWSTR SubBlock
    );

PHLIBAPI
PPH_STRING
NTAPI
PhGetFileVersionInfoString2(
    _In_ PVOID VersionInfo,
    _In_ ULONG LangCodePage,
    _In_ PWSTR StringName
    );

typedef struct _PH_IMAGE_VERSION_INFO
{
    PPH_STRING CompanyName;
    PPH_STRING FileDescription;
    PPH_STRING FileVersion;
    PPH_STRING ProductName;
} PH_IMAGE_VERSION_INFO, *PPH_IMAGE_VERSION_INFO;

PHLIBAPI
BOOLEAN
NTAPI
PhInitializeImageVersionInfo(
    _Out_ PPH_IMAGE_VERSION_INFO ImageVersionInfo,
    _In_ PWSTR FileName
    );

PHLIBAPI
VOID
NTAPI
PhDeleteImageVersionInfo(
    _Inout_ PPH_IMAGE_VERSION_INFO ImageVersionInfo
    );

PHLIBAPI
PPH_STRING
NTAPI
PhFormatImageVersionInfo(
    _In_opt_ PPH_STRING FileName,
    _In_ PPH_IMAGE_VERSION_INFO ImageVersionInfo,
    _In_opt_ PPH_STRINGREF Indent,
    _In_opt_ ULONG LineLimit
    );

PHLIBAPI
PPH_STRING
NTAPI
PhGetFullPath(
    _In_ PWSTR FileName,
    _Out_opt_ PULONG IndexOfFileName
    );

PHLIBAPI
PPH_STRING
NTAPI
PhExpandEnvironmentStrings(
    _In_ PPH_STRINGREF String
    );

PHLIBAPI
PPH_STRING
NTAPI
PhGetBaseName(
    _In_ PPH_STRING FileName
    );

PHLIBAPI
PPH_STRING
NTAPI
PhGetSystemDirectory(
    VOID
    );

PHLIBAPI
VOID
NTAPI
PhGetSystemRoot(
    _Out_ PPH_STRINGREF SystemRoot
    );

PHLIBAPI
PLDR_DATA_TABLE_ENTRY
NTAPI
PhFindLoaderEntry(
    _In_opt_ PVOID DllBase,
    _In_opt_ PPH_STRINGREF FullDllName,
    _In_opt_ PPH_STRINGREF BaseDllName
    );

PHLIBAPI
PPH_STRING
NTAPI
PhGetDllFileName(
    _In_ PVOID DllHandle,
    _Out_opt_ PULONG IndexOfFileName
    );

PHLIBAPI
PPH_STRING
NTAPI
PhGetApplicationFileName(
    VOID
    );

PHLIBAPI
PPH_STRING
NTAPI
PhGetApplicationDirectory(
    VOID
    );

PHLIBAPI
PPH_STRING
NTAPI
PhGetKnownLocation(
    _In_ ULONG Folder,
    _In_opt_ PWSTR AppendPath
    );

PHLIBAPI
NTSTATUS
NTAPI
PhWaitForMultipleObjectsAndPump(
    _In_opt_ HWND hWnd,
    _In_ ULONG NumberOfHandles,
    _In_ PHANDLE Handles,
    _In_ ULONG Timeout
    );

typedef struct _PH_CREATE_PROCESS_INFO
{
    PUNICODE_STRING DllPath;
    PUNICODE_STRING WindowTitle;
    PUNICODE_STRING DesktopInfo;
    PUNICODE_STRING ShellInfo;
    PUNICODE_STRING RuntimeData;
} PH_CREATE_PROCESS_INFO, *PPH_CREATE_PROCESS_INFO;

#define PH_CREATE_PROCESS_INHERIT_HANDLES 0x1
#define PH_CREATE_PROCESS_UNICODE_ENVIRONMENT 0x2
#define PH_CREATE_PROCESS_SUSPENDED 0x4
#define PH_CREATE_PROCESS_BREAKAWAY_FROM_JOB 0x8
#define PH_CREATE_PROCESS_NEW_CONSOLE 0x10

PHLIBAPI
NTSTATUS
NTAPI
PhCreateProcess(
    _In_ PWSTR FileName,
    _In_opt_ PPH_STRINGREF CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PPH_STRINGREF CurrentDirectory,
    _In_opt_ PPH_CREATE_PROCESS_INFO Information,
    _In_ ULONG Flags,
    _In_opt_ HANDLE ParentProcessHandle,
    _Out_opt_ PCLIENT_ID ClientId,
    _Out_opt_ PHANDLE ProcessHandle,
    _Out_opt_ PHANDLE ThreadHandle
    );

PHLIBAPI
NTSTATUS
NTAPI
PhCreateProcessWin32(
    _In_opt_ PWSTR FileName,
    _In_opt_ PWSTR CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PWSTR CurrentDirectory,
    _In_ ULONG Flags,
    _In_opt_ HANDLE TokenHandle,
    _Out_opt_ PHANDLE ProcessHandle,
    _Out_opt_ PHANDLE ThreadHandle
    );

PHLIBAPI
NTSTATUS
NTAPI
PhCreateProcessWin32Ex(
    _In_opt_ PWSTR FileName,
    _In_opt_ PWSTR CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PWSTR CurrentDirectory,
    _In_opt_ STARTUPINFO *StartupInfo,
    _In_ ULONG Flags,
    _In_opt_ HANDLE TokenHandle,
    _Out_opt_ PCLIENT_ID ClientId,
    _Out_opt_ PHANDLE ProcessHandle,
    _Out_opt_ PHANDLE ThreadHandle
    );

typedef struct _PH_CREATE_PROCESS_AS_USER_INFO
{
    _In_opt_ PWSTR ApplicationName;
    _In_opt_ PWSTR CommandLine;
    _In_opt_ PWSTR CurrentDirectory;
    _In_opt_ PVOID Environment;
    _In_opt_ PWSTR DesktopName;
    _In_opt_ ULONG SessionId; // use PH_CREATE_PROCESS_SET_SESSION_ID
    union
    {
        struct
        {
            _In_ PWSTR DomainName;
            _In_ PWSTR UserName;
            _In_ PWSTR Password;
            _In_opt_ ULONG LogonType;
        };
        _In_ HANDLE ProcessIdWithToken; // use PH_CREATE_PROCESS_USE_PROCESS_TOKEN
        _In_ ULONG SessionIdWithToken; // use PH_CREATE_PROCESS_USE_SESSION_TOKEN
    };
} PH_CREATE_PROCESS_AS_USER_INFO, *PPH_CREATE_PROCESS_AS_USER_INFO;

#define PH_CREATE_PROCESS_USE_PROCESS_TOKEN 0x1000
#define PH_CREATE_PROCESS_USE_SESSION_TOKEN 0x2000
#define PH_CREATE_PROCESS_USE_LINKED_TOKEN 0x10000
#define PH_CREATE_PROCESS_SET_SESSION_ID 0x20000
#define PH_CREATE_PROCESS_WITH_PROFILE 0x40000

PHLIBAPI
NTSTATUS
NTAPI
PhCreateProcessAsUser(
    _In_ PPH_CREATE_PROCESS_AS_USER_INFO Information,
    _In_ ULONG Flags,
    _Out_opt_ PCLIENT_ID ClientId,
    _Out_opt_ PHANDLE ProcessHandle,
    _Out_opt_ PHANDLE ThreadHandle
    );

PHLIBAPI
NTSTATUS
NTAPI
PhFilterTokenForLimitedUser(
    _In_ HANDLE TokenHandle,
    _Out_ PHANDLE NewTokenHandle
    );

PHLIBAPI
VOID
NTAPI
PhShellExecute(
    _In_ HWND hWnd,
    _In_ PWSTR FileName,
    _In_opt_ PWSTR Parameters
    );

#define PH_SHELL_EXECUTE_ADMIN 0x1
#define PH_SHELL_EXECUTE_PUMP_MESSAGES 0x2

PHLIBAPI
BOOLEAN
NTAPI
PhShellExecuteEx(
    _In_opt_ HWND hWnd,
    _In_ PWSTR FileName,
    _In_opt_ PWSTR Parameters,
    _In_ ULONG ShowWindowType,
    _In_ ULONG Flags,
    _In_opt_ ULONG Timeout,
    _Out_opt_ PHANDLE ProcessHandle
    );

PHLIBAPI
VOID
NTAPI
PhShellExploreFile(
    _In_ HWND hWnd,
    _In_ PWSTR FileName
    );

PHLIBAPI
VOID
NTAPI
PhShellProperties(
    _In_ HWND hWnd,
    _In_ PWSTR FileName
    );

PHLIBAPI
PPH_STRING
NTAPI
PhExpandKeyName(
    _In_ PPH_STRING KeyName,
    _In_ BOOLEAN Computer
    );

PHLIBAPI
VOID
NTAPI
PhShellOpenKey(
    _In_ HWND hWnd,
    _In_ PPH_STRING KeyName
    );

PHLIBAPI
PPH_STRING
NTAPI
PhQueryRegistryString(
    _In_ HANDLE KeyHandle,
    _In_opt_ PWSTR ValueName
    );

typedef struct _PH_FLAG_MAPPING
{
    ULONG Flag1;
    ULONG Flag2;
} PH_FLAG_MAPPING, *PPH_FLAG_MAPPING;

PHLIBAPI
VOID
NTAPI
PhMapFlags1(
    _Inout_ PULONG Value2,
    _In_ ULONG Value1,
    _In_ const PH_FLAG_MAPPING *Mappings,
    _In_ ULONG NumberOfMappings
    );

PHLIBAPI
VOID
NTAPI
PhMapFlags2(
    _Inout_ PULONG Value1,
    _In_ ULONG Value2,
    _In_ const PH_FLAG_MAPPING *Mappings,
    _In_ ULONG NumberOfMappings
    );

PHLIBAPI
PVOID
NTAPI
PhCreateOpenFileDialog(
    VOID
    );

PHLIBAPI
PVOID
NTAPI
PhCreateSaveFileDialog(
    VOID
    );

PHLIBAPI
VOID
NTAPI
PhFreeFileDialog(
    _In_ PVOID FileDialog
    );

PHLIBAPI
BOOLEAN
NTAPI
PhShowFileDialog(
    _In_ HWND hWnd,
    _In_ PVOID FileDialog
    );

#define PH_FILEDIALOG_CREATEPROMPT 0x1
#define PH_FILEDIALOG_PATHMUSTEXIST 0x2 // default both
#define PH_FILEDIALOG_FILEMUSTEXIST 0x4 // default open
#define PH_FILEDIALOG_SHOWHIDDEN 0x8
#define PH_FILEDIALOG_NODEREFERENCELINKS 0x10
#define PH_FILEDIALOG_OVERWRITEPROMPT 0x20 // default save
#define PH_FILEDIALOG_DEFAULTEXPANDED 0x40
#define PH_FILEDIALOG_STRICTFILETYPES 0x80
#define PH_FILEDIALOG_PICKFOLDERS 0x100

PHLIBAPI
ULONG
NTAPI
PhGetFileDialogOptions(
    _In_ PVOID FileDialog
    );

PHLIBAPI
VOID
NTAPI
PhSetFileDialogOptions(
    _In_ PVOID FileDialog,
    _In_ ULONG Options
    );

PHLIBAPI
ULONG
NTAPI
PhGetFileDialogFilterIndex(
    _In_ PVOID FileDialog
    );

typedef struct _PH_FILETYPE_FILTER
{
    PWSTR Name;
    PWSTR Filter;
} PH_FILETYPE_FILTER, *PPH_FILETYPE_FILTER;

PHLIBAPI
VOID
NTAPI
PhSetFileDialogFilter(
    _In_ PVOID FileDialog,
    _In_ PPH_FILETYPE_FILTER Filters,
    _In_ ULONG NumberOfFilters
    );

PHLIBAPI
PPH_STRING
NTAPI
PhGetFileDialogFileName(
    _In_ PVOID FileDialog
    );

PHLIBAPI
VOID
NTAPI
PhSetFileDialogFileName(
    _In_ PVOID FileDialog,
    _In_ PWSTR FileName
    );

PHLIBAPI
NTSTATUS
NTAPI
PhIsExecutablePacked(
    _In_ PWSTR FileName,
    _Out_ PBOOLEAN IsPacked,
    _Out_opt_ PULONG NumberOfModules,
    _Out_opt_ PULONG NumberOfFunctions
    );

PHLIBAPI
ULONG
NTAPI
PhCrc32(
    _In_ ULONG Crc,
    _In_reads_(Length) PCHAR Buffer,
    _In_ SIZE_T Length
    );

typedef enum _PH_HASH_ALGORITHM
{
    Md5HashAlgorithm,
    Sha1HashAlgorithm,
    Crc32HashAlgorithm
} PH_HASH_ALGORITHM;

typedef struct _PH_HASH_CONTEXT
{
    PH_HASH_ALGORITHM Algorithm;
    ULONG Context[64];
} PH_HASH_CONTEXT, *PPH_HASH_CONTEXT;

PHLIBAPI
VOID
NTAPI
PhInitializeHash(
    _Out_ PPH_HASH_CONTEXT Context,
    _In_ PH_HASH_ALGORITHM Algorithm
    );

PHLIBAPI
VOID
NTAPI
PhUpdateHash(
    _Inout_ PPH_HASH_CONTEXT Context,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length
    );

PHLIBAPI
BOOLEAN
NTAPI
PhFinalHash(
    _Inout_ PPH_HASH_CONTEXT Context,
    _Out_writes_bytes_(HashLength) PVOID Hash,
    _In_ ULONG HashLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef enum _PH_COMMAND_LINE_OPTION_TYPE
{
    NoArgumentType,
    MandatoryArgumentType,
    OptionalArgumentType
} PH_COMMAND_LINE_OPTION_TYPE, *PPH_COMMAND_LINE_OPTION_TYPE;

typedef struct _PH_COMMAND_LINE_OPTION
{
    ULONG Id;
    PWSTR Name;
    PH_COMMAND_LINE_OPTION_TYPE Type;
} PH_COMMAND_LINE_OPTION, *PPH_COMMAND_LINE_OPTION;

typedef BOOLEAN (NTAPI *PPH_COMMAND_LINE_CALLBACK)(
    _In_opt_ PPH_COMMAND_LINE_OPTION Option,
    _In_opt_ PPH_STRING Value,
    _In_opt_ PVOID Context
    );

#define PH_COMMAND_LINE_IGNORE_UNKNOWN_OPTIONS 0x1
#define PH_COMMAND_LINE_IGNORE_FIRST_PART 0x2

PHLIBAPI
PPH_STRING
NTAPI
PhParseCommandLinePart(
    _In_ PPH_STRINGREF CommandLine,
    _Inout_ PULONG_PTR Index
    );

PHLIBAPI
BOOLEAN
NTAPI
PhParseCommandLine(
    _In_ PPH_STRINGREF CommandLine,
    _In_opt_ PPH_COMMAND_LINE_OPTION Options,
    _In_ ULONG NumberOfOptions,
    _In_ ULONG Flags,
    _In_ PPH_COMMAND_LINE_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

PHLIBAPI
PPH_STRING
NTAPI
PhEscapeCommandLinePart(
    _In_ PPH_STRINGREF String
    );

PHLIBAPI
BOOLEAN
NTAPI
PhParseCommandLineFuzzy(
    _In_ PPH_STRINGREF CommandLine,
    _Out_ PPH_STRINGREF FileName,
    _Out_ PPH_STRINGREF Arguments,
    _Out_opt_ PPH_STRING *FullFileName
    );

#ifdef __cplusplus
}
#endif

#endif
