#ifndef _NTPFAPI_H
#define _NTPFAPI_H

// begin_private

// Prefetch

typedef enum _PF_BOOT_PHASE_ID
{
    PfKernelInitPhase = 0,
    PfBootDriverInitPhase = 90,
    PfSystemDriverInitPhase = 120,
    PfSessionManagerInitPhase = 150,
    PfSMRegistryInitPhase = 180,
    PfVideoInitPhase = 210,
    PfPostVideoInitPhase = 240,
    PfBootAcceptedRegistryInitPhase = 270,
    PfUserShellReadyPhase = 300,
    PfMaxBootPhaseId = 900
} PF_BOOT_PHASE_ID;

typedef enum _PF_ENABLE_STATUS
{
    PfSvNotSpecified,
    PfSvEnabled,
    PfSvDisabled,
    PfSvMaxEnableStatus
} PF_ENABLE_STATUS;

typedef struct _PF_TRACE_LIMITS
{
    ULONG MaxNumPages;
    ULONG MaxNumSections;
    LONGLONG TimerPeriod;
} PF_TRACE_LIMITS, *PPF_TRACE_LIMITS;

typedef struct _PF_SYSTEM_PREFETCH_PARAMETERS
{
    PF_ENABLE_STATUS EnableStatus[2];
    PF_TRACE_LIMITS TraceLimits[2];
    ULONG MaxNumActiveTraces;
    ULONG MaxNumSavedTraces;
    WCHAR RootDirPath[32];
    WCHAR HostingApplicationList[128];
} PF_SYSTEM_PREFETCH_PARAMETERS, *PPF_SYSTEM_PREFETCH_PARAMETERS;

#define PF_BOOT_CONTROL_VERSION 1

typedef struct _PF_BOOT_CONTROL
{
    ULONG Version;
    ULONG DisableBootPrefetching;
} PF_BOOT_CONTROL, *PPF_BOOT_CONTROL;

typedef enum _PREFETCHER_INFORMATION_CLASS
{
    PrefetcherRetrieveTrace = 1, // q: CHAR[]
    PrefetcherSystemParameters, // q: PF_SYSTEM_PREFETCH_PARAMETERS
    PrefetcherBootPhase, // s: PF_BOOT_PHASE_ID
    PrefetcherRetrieveBootLoaderTrace, // q: CHAR[]
    PrefetcherBootControl // s: PF_BOOT_CONTROL
} PREFETCHER_INFORMATION_CLASS;

#define PREFETCHER_INFORMATION_VERSION 23 // rev
#define PREFETCHER_INFORMATION_MAGIC ('kuhC') // rev

typedef struct _PREFETCHER_INFORMATION
{
    ULONG Version;
    ULONG Magic;
    PREFETCHER_INFORMATION_CLASS PrefetcherInformationClass;
    PVOID PrefetcherInformation;
    ULONG PrefetcherInformationLength;
} PREFETCHER_INFORMATION, *PPREFETCHER_INFORMATION;

// Superfetch

typedef struct _PF_SYSTEM_SUPERFETCH_PARAMETERS
{
    ULONG EnabledComponents;
    ULONG BootID;
    ULONG SavedSectInfoTracesMax;
    ULONG SavedPageAccessTracesMax;
    ULONG ScenarioPrefetchTimeoutStandby;
    ULONG ScenarioPrefetchTimeoutHibernate;
} PF_SYSTEM_SUPERFETCH_PARAMETERS, *PPF_SYSTEM_SUPERFETCH_PARAMETERS;

#define PF_PFN_PRIO_REQUEST_VERSION 1
#define PF_PFN_PRIO_REQUEST_QUERY_MEMORY_LIST 0x1
#define PF_PFN_PRIO_REQUEST_VALID_FLAGS 0x1

typedef struct _PF_PFN_PRIO_REQUEST
{
    ULONG Version;
    ULONG RequestFlags;
    ULONG PfnCount;
    SYSTEM_MEMORY_LIST_INFORMATION MemInfo;
    MMPFN_IDENTITY PageData[256];
} PF_PFN_PRIO_REQUEST, *PPF_PFN_PRIO_REQUEST;

typedef enum _PFS_PRIVATE_PAGE_SOURCE_TYPE
{
    PfsPrivateSourceKernel,
    PfsPrivateSourceSession,
    PfsPrivateSourceProcess,
    PfsPrivateSourceMax
} PFS_PRIVATE_PAGE_SOURCE_TYPE;

typedef struct _PFS_PRIVATE_PAGE_SOURCE
{
    PFS_PRIVATE_PAGE_SOURCE_TYPE Type;
    union
    {
        ULONG_PTR SessionId;
        ULONG_PTR ProcessId;
    };
    ULONG ImagePathHash;
    ULONG UniqueProcessHash;
} PFS_PRIVATE_PAGE_SOURCE, *PPFS_PRIVATE_PAGE_SOURCE;

typedef struct _PF_PRIVSOURCE_INFO
{
    PFS_PRIVATE_PAGE_SOURCE DbInfo;
    union
    {
        ULONG_PTR EProcess;
        ULONG_PTR GlobalVA;
    };
    ULONG WsPrivatePages;
    ULONG TotalPrivatePages;
    ULONG SessionID;
    CHAR ImageName[16];
} PF_PRIVSOURCE_INFO, *PPF_PRIVSOURCE_INFO;

#define PF_PRIVSOURCE_QUERY_REQUEST_VERSION 3

typedef struct _PF_PRIVSOURCE_QUERY_REQUEST
{
    ULONG Version;
    ULONG InfoCount;
    PF_PRIVSOURCE_INFO InfoArray[1];
} PF_PRIVSOURCE_QUERY_REQUEST, *PPF_PRIVSOURCE_QUERY_REQUEST;

typedef enum _PF_PHASED_SCENARIO_TYPE
{
    PfScenarioTypeNone,
    PfScenarioTypeStandby,
    PfScenarioTypeHibernate,
    PfScenarioTypeFUS,
    PfScenarioTypeMax
} PF_PHASED_SCENARIO_TYPE;

#define PF_SCENARIO_PHASE_INFO_VERSION 4

typedef struct _PF_SCENARIO_PHASE_INFO
{
    ULONG Version;
    PF_PHASED_SCENARIO_TYPE ScenType;
    ULONG PhaseId;
    ULONG SequenceNumber;
    ULONG Flags;
    ULONG FUSUserId;
} PF_SCENARIO_PHASE_INFO, *PPF_SCENARIO_PHASE_INFO;

typedef struct _PF_MEMORY_LIST_NODE
{
    ULONGLONG Node : 8;
    ULONGLONG Spare : 56;
    ULONGLONG StandbyLowPageCount;
    ULONGLONG StandbyMediumPageCount;
    ULONGLONG StandbyHighPageCount;
    ULONGLONG FreePageCount;
    ULONGLONG ModifiedPageCount;
} PF_MEMORY_LIST_NODE, *PPF_MEMORY_LIST_NODE;

#define PF_MEMORY_LIST_INFO_VERSION 1

typedef struct _PF_MEMORY_LIST_INFO
{
    ULONG Version;
    ULONG Size;
    ULONG NodeCount;
    PF_MEMORY_LIST_NODE Nodes[1];
} PF_MEMORY_LIST_INFO, *PPF_MEMORY_LIST_INFO;

typedef struct _PF_PHYSICAL_MEMORY_RANGE
{
    ULONG BasePfn;
    ULONG PageCount;
} PF_PHYSICAL_MEMORY_RANGE, *PPF_PHYSICAL_MEMORY_RANGE;

#define PF_PHYSICAL_MEMORY_RANGE_INFO_VERSION 1

typedef struct _PF_PHYSICAL_MEMORY_RANGE_INFO
{
    ULONG Version;
    ULONG RangeCount;
    PF_PHYSICAL_MEMORY_RANGE Ranges[1];
} PF_PHYSICAL_MEMORY_RANGE_INFO, *PPF_PHYSICAL_MEMORY_RANGE_INFO;

// begin_rev

#define PF_REPURPOSED_BY_PREFETCH_INFO_VERSION 1

typedef struct _PF_REPURPOSED_BY_PREFETCH_INFO
{
    ULONG Version;
    ULONG RepurposedByPrefetch;
} PF_REPURPOSED_BY_PREFETCH_INFO, *PPF_REPURPOSED_BY_PREFETCH_INFO;

// end_rev

typedef enum _SUPERFETCH_INFORMATION_CLASS
{
    SuperfetchRetrieveTrace = 1, // q: CHAR[]
    SuperfetchSystemParameters, // q: PF_SYSTEM_SUPERFETCH_PARAMETERS
    SuperfetchLogEvent,
    SuperfetchGenerateTrace,
    SuperfetchPrefetch,
    SuperfetchPfnQuery, // q: PF_PFN_PRIO_REQUEST
    SuperfetchPfnSetPriority,
    SuperfetchPrivSourceQuery, // q: PF_PRIVSOURCE_QUERY_REQUEST
    SuperfetchSequenceNumberQuery, // q: ULONG
    SuperfetchScenarioPhase, // 10
    SuperfetchWorkerPriority,
    SuperfetchScenarioQuery, // q: PF_SCENARIO_PHASE_INFO
    SuperfetchScenarioPrefetch,
    SuperfetchRobustnessControl,
    SuperfetchTimeControl,
    SuperfetchMemoryListQuery, // q: PF_MEMORY_LIST_INFO
    SuperfetchMemoryRangesQuery, // q: PF_PHYSICAL_MEMORY_RANGE_INFO
    SuperfetchTracingControl,
    SuperfetchTrimWhileAgingControl,
    SuperfetchRepurposedByPrefetch, // q: PF_REPURPOSED_BY_PREFETCH_INFO // rev
    SuperfetchInformationMax
} SUPERFETCH_INFORMATION_CLASS;

#define SUPERFETCH_INFORMATION_VERSION 45 // rev
#define SUPERFETCH_INFORMATION_MAGIC ('kuhC') // rev

typedef struct _SUPERFETCH_INFORMATION
{
    ULONG Version;
    ULONG Magic;
    SUPERFETCH_INFORMATION_CLASS InfoClass;
    PVOID Data;
    ULONG Length;
} SUPERFETCH_INFORMATION, *PSUPERFETCH_INFORMATION;

// end_private

#endif
