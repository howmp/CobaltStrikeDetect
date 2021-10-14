// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

#pragma comment(lib, "ProcessHacker.lib")

#define ID_VIEW_HIDEPROCESSESFROMOTHERUSERS 40232
#define ID_PROCESS_CHECK 101
#define COLUMN_ID 101
typedef enum _CURRENT_THREAD_STAGE
{
	ThreadStageNone,
	ThreadStageSleep,
	ThreadStageWininet,
	ThreadStageSMB,
	ThreadStageTCP,
} CURRENT_THREAD_STAGE;


typedef struct _CS_ITEM
{
	union
	{
		struct
		{
			BOOL isCS : 1;
			BOOL IsAdvapi32 : 1;
			BOOL IsDnsapi : 1;
			BOOL IsIphlpapi : 1;
			BOOL IsSecur32 : 1;
			BOOL IsWininet : 1;
			BOOL IsWs2_32 : 1;
		};
	};
	HANDLE CurrentThreadId;
	PVOID BaseAddressOfCS;
	SIZE_T SizeOfCS;
	PPH_PROCESS_ITEM ProcessItem;
	PPH_SYMBOL_PROVIDER symbolProvider;
	CURRENT_THREAD_STAGE CurrentThreadStage;
	PPH_STRING Text;
} CS_ITEM, * PCS_ITEM;

PPH_PLUGIN PluginInstance;
HWND ProcessTreeNewHandle;
static PH_CALLBACK_REGISTRATION PluginMenuItemCallbackRegistration;
static PH_CALLBACK_REGISTRATION MainMenuInitializingCallbackRegistration;
static PH_CALLBACK_REGISTRATION ProcessTreeNewInitializingCallbackRegistration;
static PH_CALLBACK_REGISTRATION TreeNewMessageCallbackRegistration;

static PPH_TN_FILTER_ENTRY FilterEntry = NULL;
static VOID NTAPI MainMenuInitializingCallback(
	_In_opt_ PVOID Parameter,
	_In_opt_ PVOID Context
)
{
	PPH_PLUGIN_MENU_INFORMATION menuInfo = (PPH_PLUGIN_MENU_INFORMATION)Parameter;
	PPH_EMENU_ITEM menuItem;
	ULONG insertIndex;
	// Check this menu is the View menu
	if (!menuInfo || menuInfo->u.MainMenu.SubMenuIndex != PH_MENU_ITEM_LOCATION_VIEW)
		return;
	menuItem = PhFindEMenuItem(menuInfo->Menu, 0, NULL, ID_VIEW_HIDEPROCESSESFROMOTHERUSERS);

	if (!menuItem) {
		return;
	}
	insertIndex = PhIndexOfEMenuItem(menuInfo->Menu, menuItem);
	menuItem = PhPluginCreateEMenuItem(PluginInstance, 0, ID_PROCESS_CHECK, L"Show CobaltStrike processes", NULL);
	PhInsertEMenuItem(menuInfo->Menu, menuItem, insertIndex);
	if (FilterEntry)
		menuItem->Flags |= PH_EMENU_CHECKED;
}

static BOOLEAN NTAPI EnumGenericModulesCallback(
	_In_ PPH_MODULE_INFO Module,
	_In_opt_ PVOID Context
)
{
	PCS_ITEM cs = Context;
	if (
		PhEqualStringRef2(&Module->Name->sr, L"Wininet.dll", TRUE) ||
		PhStartsWithStringRef2(&Module->Name->sr, L"Kernel", TRUE) ||
		PhEqualStringRef2(&Module->Name->sr, L"Ntdll.dll", TRUE) || 
		PhEqualStringRef2(&Module->Name->sr, L"Ws2_32.dll", TRUE) 
		) {
		PhLoadModuleSymbolProvider(cs->symbolProvider, Module->FileName->Buffer,
			(ULONG64)Module->BaseAddress, Module->Size);
	}
	return TRUE;
}

static BOOLEAN NTAPI EnumGenericModulesCallbackDLL(
	_In_ PPH_MODULE_INFO Module,
	_In_opt_ PVOID Context
)
{
	PCS_ITEM cs = Context;
	if (PhEqualStringRef2(&Module->Name->sr, L"Advapi32.dll", TRUE)) {
		cs->IsAdvapi32 = 1;
	}
	else if (PhEqualStringRef2(&Module->Name->sr, L"Dnsapi.dll", TRUE)) {
		cs->IsDnsapi = 1;
	}
	else if (PhEqualStringRef2(&Module->Name->sr, L"Iphlpapi.dll", TRUE)) {
		cs->IsIphlpapi = 1;
	}
	else if (PhEqualStringRef2(&Module->Name->sr, L"Secur32.dll", TRUE)) {
		cs->IsSecur32 = 1;
	}
	else if (PhEqualStringRef2(&Module->Name->sr, L"Wininet.dll", TRUE)) {
		cs->IsWininet = 1;
	}
	else if (PhEqualStringRef2(&Module->Name->sr, L"Ws2_32.dll", TRUE)) {
		cs->IsWs2_32 = 1;
	}
	return TRUE;
}

static VOID DetectAddress(PCS_ITEM cs, PVOID addr) {
	//检查内存是否为MEM_PRIVATE、PAGE_READWRITE
	MEMORY_BASIC_INFORMATION basicInfo;
	if (NtQueryVirtualMemory(
		cs->symbolProvider->ProcessHandle,
		addr,
		MemoryBasicInformation,
		&basicInfo,
		sizeof(MEMORY_BASIC_INFORMATION),
		NULL
	) >= 0) {
		//判断原始属性可写，最终属性可执行
		if (
			(basicInfo.Type & MEM_PRIVATE) && 
			(basicInfo.Protect & (PAGE_EXECUTE_READWRITE| PAGE_EXECUTE_READ)) &&
			(basicInfo.AllocationProtect & (PAGE_EXECUTE_READWRITE| PAGE_READWRITE))
		) {
			cs->BaseAddressOfCS = basicInfo.AllocationBase;
			cs->SizeOfCS = basicInfo.RegionSize;
			cs->isCS = TRUE;
			PWCHAR type = L"";
			switch (cs->CurrentThreadStage)
			{
			case ThreadStageSleep:
				type = L"Sleep";
				break;
			case ThreadStageWininet:
				type = L"Wininet";
				break;
			case ThreadStageSMB:
				type = L"SMB";
				break;
			case ThreadStageTCP:
				type = L"TCP";
				break;
			}
			cs->Text = PhFormatString(
				L"Pid:%u Tid:%u Type:%s Mem:%p(%llx) Call:%p",
				HandleToUlong(cs->ProcessItem->ProcessId),
				HandleToUlong(cs->CurrentThreadId),
				type,
				cs->BaseAddressOfCS,
				cs->SizeOfCS,
				addr
				);
		}
	}
}


PH_STRINGREF FrameSleep1 = PH_STRINGREF_INIT(L"!Sleep+0x");
PH_STRINGREF FrameSleep2 = PH_STRINGREF_INIT(L"!SleepEx+0x");
PH_STRINGREF FrameWininet = PH_STRINGREF_INIT(L"Wininet.dll!");
PH_STRINGREF FrameSMB1 = PH_STRINGREF_INIT(L"ReadFile+0x");
PH_STRINGREF FrameSMB2 = PH_STRINGREF_INIT(L"FsControlFile+0x");
PH_STRINGREF FrameTCP1 = PH_STRINGREF_INIT(L"ws2_32.dll!accept+0x");
PH_STRINGREF FrameTCP2 = PH_STRINGREF_INIT(L"ws2_32.dll!recv+0x");
static BOOLEAN NTAPI PhpWalkThreadStackCallback(
	_In_ PPH_THREAD_STACK_FRAME StackFrame,
	_In_opt_ PVOID Context
)
{
	BOOLEAN ret = TRUE;
	PCS_ITEM cs = Context;
	PPH_STRING symbol = PhGetSymbolFromAddress(
		cs->symbolProvider,
		(ULONG64)StackFrame->PcAddress,
		NULL,
		NULL,
		NULL,
		NULL
	);
#ifdef DEBUG
	DbgPrint("%S p:%d t:%d %S\n", cs->ProcessItem->ProcessName->Buffer, cs->ProcessItem->ProcessId, cs->CurrentThreadId, symbol->Buffer);
#endif // DEBUG


	//之前栈包含sleep或wininet调用,检查当前栈是否可写
	switch (cs->CurrentThreadStage)
	{
	case ThreadStageNone: {
		if (
			(PhFindStringInStringRef(&symbol->sr, &FrameSleep1, TRUE) != -1) || 
			(PhFindStringInStringRef(&symbol->sr, &FrameSleep2, TRUE) != -1)) 
		{
			cs->CurrentThreadStage = ThreadStageSleep;
		}
		else if (PhFindStringInStringRef(&symbol->sr, &FrameWininet, TRUE) != -1) {
			cs->CurrentThreadStage = ThreadStageWininet;
		}
		else if (
			(PhFindStringInStringRef(&symbol->sr, &FrameSMB1, TRUE) != -1) ||
			(PhFindStringInStringRef(&symbol->sr, &FrameSMB2, TRUE) != -1))
		{
			cs->CurrentThreadStage = ThreadStageSMB;
		}
		else if (
			(PhFindStringInStringRef(&symbol->sr, &FrameTCP1, TRUE) != -1) ||
			(PhFindStringInStringRef(&symbol->sr, &FrameTCP2, TRUE) != -1))
		{
			cs->CurrentThreadStage = ThreadStageTCP;
		}
		break;
	}
	case ThreadStageSleep: {
		if (
			(PhFindStringInStringRef(&symbol->sr, &FrameSleep1, TRUE) == -1) && 
			(PhFindStringInStringRef(&symbol->sr, &FrameSleep2, TRUE) == -1)) 
		{
			ret = FALSE;
			//检查当前栈是否可写
			DetectAddress(cs, StackFrame->PcAddress);
		}
		break;
	}
	case ThreadStageWininet: {
		if (PhFindStringInStringRef(&symbol->sr, &FrameWininet, TRUE) == -1) {
			ret = FALSE;
			//检查当前栈是否可写
			DetectAddress(cs, StackFrame->PcAddress);
		}
		break;
	}
	case ThreadStageSMB: {
		if (
			(PhFindStringInStringRef(&symbol->sr, &FrameSMB1, TRUE) == -1) &&
			(PhFindStringInStringRef(&symbol->sr, &FrameSMB2, TRUE) == -1))
		{
			ret = FALSE;
			//检查当前栈是否可写
			DetectAddress(cs, StackFrame->PcAddress);
		}
		break;
	}
	case ThreadStageTCP: {
		if (
			(PhFindStringInStringRef(&symbol->sr, &FrameTCP1, TRUE) == -1) &&
			(PhFindStringInStringRef(&symbol->sr, &FrameTCP2, TRUE) == -1))
		{
			ret = FALSE;
			//检查当前栈是否可写
			DetectAddress(cs, StackFrame->PcAddress);
		}
		break;
	}
	}
	PhDereferenceObject(symbol);
	return ret;
}

BOOL GetSymbolProvider(PCS_ITEM cs) {
	if (cs->symbolProvider) {
		return TRUE;
	}
	cs->symbolProvider = PhCreateSymbolProvider(cs->ProcessItem->ProcessId);
	PhLoadSymbolProviderOptions(cs->symbolProvider);
	if (!cs->symbolProvider->IsRealHandle)
	{
		//进程无法打开
		goto CLEAN;
	}
	PhEnumGenericModules(
		cs->ProcessItem->ProcessId,
		cs->symbolProvider->ProcessHandle,
		0,
		EnumGenericModulesCallbackDLL,
		cs
	);
	//有CS必然加载的模块
	if (cs->IsAdvapi32 && cs->IsIphlpapi && cs->IsWs2_32) {
		//加载模块的符号
		PhEnumGenericModules(
			cs->ProcessItem->ProcessId,
			cs->symbolProvider->ProcessHandle,
			0,
			EnumGenericModulesCallback,
			cs
		);
		return TRUE;
	}
CLEAN:
	PhDereferenceObject(cs->symbolProvider);
	cs->symbolProvider = NULL;
	return FALSE;

}

VOID Detect(PCS_ITEM cs) {
	PVOID processes;
	cs->isCS = FALSE;
	if (cs->ProcessItem->IsSuspended) {
		return;
	}
	if (!NT_SUCCESS(PhEnumProcesses(&processes))) {
		return;
	}
	PSYSTEM_PROCESS_INFORMATION process = PhFindProcessInformation(processes, cs->ProcessItem->ProcessId);
	if (!process) {
		//没找到进程
		goto CLEAN;
	}
	if (!GetSymbolProvider(cs)) {
		goto CLEAN;
	}
	PSYSTEM_THREAD_INFORMATION threads = process->Threads;
	ULONG numberOfThreads = process->NumberOfThreads;
	NTSTATUS status;
	HANDLE threadHandle;
	CLIENT_ID clientId;
	for (ULONG i = 0; i < numberOfThreads; i++) {
		if (!NT_SUCCESS(status = PhOpenThread(
			&threadHandle,
			ThreadQueryAccess | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
			threads[i].ClientId.UniqueThread
		)))
		{
			//线程无法打开，继续下个循环
			continue;
		}
		clientId.UniqueProcess = cs->ProcessItem->ProcessId;
		clientId.UniqueThread = threads[i].ClientId.UniqueThread;
		//回溯堆栈
		cs->CurrentThreadId = clientId.UniqueThread;
		cs->CurrentThreadStage = ThreadStageNone;
		status = PhWalkThreadStack(
			threadHandle,
			cs->symbolProvider->ProcessHandle,
			&clientId,
			cs->symbolProvider,
			PH_WALK_I386_STACK | PH_WALK_AMD64_STACK,
			PhpWalkThreadStackCallback,
			cs
		);
		NtClose(threadHandle);
		if (cs->isCS) {
			break;
		}
	}


CLEAN:
	PhFree(processes);
}


static BOOLEAN ProcessTreeFilter(
	_In_ PPH_TREENEW_NODE Node,
	_In_opt_ PVOID Context
)
{
	PPH_PROCESS_NODE node = (PPH_PROCESS_NODE)Node;
	PCS_ITEM cs = PhPluginGetObjectExtension(PluginInstance, node->ProcessItem, EmProcessItemType);

	//PhEqualStringRef2(&cs->ProcessItem->ProcessName->sr,L"artifact.exe",TRUE)
	if (!cs->isCS) {
		Detect(cs);
	}
	return cs->isCS;
}


static VOID NTAPI MenuItemCallback(
	_In_opt_ PVOID Parameter,
	_In_opt_ PVOID Context
)
{
	PPH_PLUGIN_MENU_ITEM menuItem = (PPH_PLUGIN_MENU_ITEM)Parameter;
	if (!menuItem || menuItem->Id != ID_PROCESS_CHECK)
	{
		return;
	}
	if (!FilterEntry) {
		FilterEntry = PhAddTreeNewFilter(PhGetFilterSupportProcessTreeList(), ProcessTreeFilter, NULL);
	}
	else {
		PhRemoveTreeNewFilter(PhGetFilterSupportProcessTreeList(), FilterEntry);
		FilterEntry = NULL;
	}
	PhApplyTreeNewFilters(PhGetFilterSupportProcessTreeList());

}
static VOID NTAPI ItemCreateCallback(
	_In_ PVOID Object,
	_In_ PH_EM_OBJECT_TYPE ObjectType,
	_In_ PVOID Extension
)
{
	PCS_ITEM cs = Extension;
	memset(cs, 0, sizeof(CS_ITEM));
	cs->ProcessItem = Object;
}

VOID NTAPI ItemDeleteCallback(
	_In_ PVOID Object,
	_In_ PH_EM_OBJECT_TYPE ObjectType,
	_In_ PVOID Extension
)
{
	PCS_ITEM cs = Extension;
	if (cs->symbolProvider) {
		PhDereferenceObject(cs->symbolProvider);
	}
	if (cs->Text) {
		PhDereferenceObject(cs->Text);
	}
}

static LONG NTAPI ProcessSortFunction(
	_In_ PVOID Node1,
	_In_ PVOID Node2,
	_In_ ULONG SubId,
	_In_ PVOID Context
)
{
	PPH_PROCESS_NODE node1 = Node1;
	PPH_PROCESS_NODE node2 = Node2;
	PCS_ITEM cs1 = PhPluginGetObjectExtension(PluginInstance, node1->ProcessItem, EmProcessItemType);
	PCS_ITEM cs2 = PhPluginGetObjectExtension(PluginInstance, node2->ProcessItem, EmProcessItemType);
	return PhCompareStringWithNull(cs1->Text, cs2->Text, TRUE);
}

VOID ProcessTreeNewInitializingCallback(
	_In_opt_ PVOID Parameter,
	_In_opt_ PVOID Context
)
{
	PPH_PLUGIN_TREENEW_INFORMATION info = Parameter;
	PH_TREENEW_COLUMN column;

	ProcessTreeNewHandle = info->TreeNewHandle;

	memset(&column, 0, sizeof(PH_TREENEW_COLUMN));
	column.Text = L"CobaltStrike";
	column.Width = 120;
	column.Alignment = PH_ALIGN_LEFT;

	PhPluginAddTreeNewColumn(PluginInstance, info->CmData, &column, COLUMN_ID, NULL, ProcessSortFunction);
}

VOID TreeNewMessageCallback(
	_In_opt_ PVOID Parameter,
	_In_opt_ PVOID Context
)
{
	PPH_PLUGIN_TREENEW_MESSAGE message = Parameter;

	if (message->Message != TreeNewGetCellText || message->TreeNewHandle != ProcessTreeNewHandle) {
		return;
	}

	PPH_TREENEW_GET_CELL_TEXT getCellText = message->Parameter1;

	if (message->TreeNewHandle == ProcessTreeNewHandle)
	{
		PPH_PROCESS_NODE node;

		node = (PPH_PROCESS_NODE)getCellText->Node;

		switch (message->SubId)
		{
		case COLUMN_ID:
		{
			PCS_ITEM cs;
			cs = PhPluginGetObjectExtension(PluginInstance, node->ProcessItem, EmProcessItemType);
			getCellText->Text = PhGetStringRef(cs->Text);
		}
		break;
		}
	}


}

BOOL APIENTRY DllMain(HMODULE Instance,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	if (ul_reason_for_call != DLL_PROCESS_ATTACH) {
		return TRUE;
	}
	PPH_PLUGIN_INFORMATION info;

	// Register your plugin with a unique name, otherwise it will fail.
	PluginInstance = PhRegisterPlugin(L"ProcessHacker.CobaltStrikeDetect", Instance, &info);

	if (!PluginInstance)
		return FALSE;
	info->DisplayName = L"CobaltStrike Detect";
	info->Author = L"guage";
	info->Description = L"Plugin for checking CobaltStrike's process";
	info->Url = L"https://guage.cool/";
	info->HasOptions = FALSE;
	PhRegisterCallback(
		PhGetGeneralCallback(GeneralCallbackMainMenuInitializing),
		MainMenuInitializingCallback,
		NULL,
		&MainMenuInitializingCallbackRegistration
	);
	PhRegisterCallback(
		PhGetPluginCallback(PluginInstance, PluginCallbackMenuItem),
		MenuItemCallback,
		NULL,
		&PluginMenuItemCallbackRegistration
	);
	PhRegisterCallback(
		PhGetGeneralCallback(GeneralCallbackProcessTreeNewInitializing),
		ProcessTreeNewInitializingCallback,
		NULL,
		&ProcessTreeNewInitializingCallbackRegistration
	);
	PhRegisterCallback(
		PhGetPluginCallback(PluginInstance, PluginCallbackTreeNewMessage),
		TreeNewMessageCallback,
		NULL,
		&TreeNewMessageCallbackRegistration
	);
	PhPluginSetObjectExtension(
		PluginInstance,
		EmProcessItemType,
		sizeof(CS_ITEM),
		ItemCreateCallback,
		ItemDeleteCallback
	);

	return TRUE;
}

