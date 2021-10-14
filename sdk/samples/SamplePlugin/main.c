#include <phdk.h>

#define ID_SAMPLE_MENU_ITEM 1
#define ID_SHOW_ME_SOME_OBJECTS 2

VOID LoadCallback(
    __in_opt PVOID Parameter,
    __in_opt PVOID Context
    );

VOID ShowOptionsCallback(
    __in_opt PVOID Parameter,
    __in_opt PVOID Context
    );

VOID MenuItemCallback(
    __in_opt PVOID Parameter,
    __in_opt PVOID Context
    );

VOID MainWindowShowingCallback(
    __in_opt PVOID Parameter,
    __in_opt PVOID Context
    );

VOID GetProcessHighlightingColorCallback(
    __in_opt PVOID Parameter,
    __in_opt PVOID Context
    );

VOID GetProcessTooltipTextCallback(
    __in_opt PVOID Parameter,
    __in_opt PVOID Context
    );

PPH_PLUGIN PluginInstance;
PH_CALLBACK_REGISTRATION PluginLoadCallbackRegistration;
PH_CALLBACK_REGISTRATION PluginShowOptionsCallbackRegistration;
PH_CALLBACK_REGISTRATION PluginMenuItemCallbackRegistration;
PH_CALLBACK_REGISTRATION MainWindowShowingCallbackRegistration;
PH_CALLBACK_REGISTRATION GetProcessHighlightingColorCallbackRegistration;
PH_CALLBACK_REGISTRATION GetProcessTooltipTextCallbackRegistration;

LOGICAL DllMain(
    __in HINSTANCE Instance,
    __in ULONG Reason,
    __reserved PVOID Reserved
    )
{
    switch (Reason)
    {
    case DLL_PROCESS_ATTACH:
        {
            PPH_PLUGIN_INFORMATION info;

            // Register your plugin with a unique name, otherwise it will fail.
            PluginInstance = PhRegisterPlugin(L"YourName.SamplePlugin", Instance, &info);

            if (!PluginInstance)
                return FALSE;

            info->DisplayName = L"Sample Plugin";
            info->Author = L"Someone";
            info->Description = L"Description goes here";
            info->HasOptions = TRUE;

            PhRegisterCallback(
                PhGetPluginCallback(PluginInstance, PluginCallbackLoad),
                LoadCallback,
                NULL,
                &PluginLoadCallbackRegistration
                );
            PhRegisterCallback(
                PhGetPluginCallback(PluginInstance, PluginCallbackShowOptions),
                ShowOptionsCallback,
                NULL,
                &PluginShowOptionsCallbackRegistration
                );
            PhRegisterCallback(
                PhGetPluginCallback(PluginInstance, PluginCallbackMenuItem),
                MenuItemCallback,
                NULL,
                &PluginMenuItemCallbackRegistration
                );

            PhRegisterCallback(
                PhGetGeneralCallback(GeneralCallbackMainWindowShowing),
                MainWindowShowingCallback,
                NULL,
                &MainWindowShowingCallbackRegistration
                );
            PhRegisterCallback(
                PhGetGeneralCallback(GeneralCallbackGetProcessHighlightingColor),
                GetProcessHighlightingColorCallback,
                NULL,
                &GetProcessHighlightingColorCallbackRegistration
                );
            PhRegisterCallback(
                PhGetGeneralCallback(GeneralCallbackGetProcessTooltipText),
                GetProcessTooltipTextCallback,
                NULL,
                &GetProcessTooltipTextCallbackRegistration
                );

            // Add some settings. Note that we cannot access these settings
            // in DllMain. Settings must be added in DllMain.
            {
                static PH_SETTING_CREATE settings[] =
                {
                    // You must prepend your plugin name to the setting names.
                    { IntegerSettingType, L"ProcessHacker.SamplePlugin.SomeInteger", L"1234" },
                    { StringSettingType, L"ProcessHacker.SamplePlugin.SomeString", L"my string" }
                };

                PhAddSettings(settings, sizeof(settings) / sizeof(PH_SETTING_CREATE));
            }
        }
        break;
    }

    return TRUE;
}

VOID LoadCallback(
    __in_opt PVOID Parameter,
    __in_opt PVOID Context
    )
{
    ULONG myInteger;
    PPH_STRING myString;

    myInteger = PhGetIntegerSetting(L"ProcessHacker.SamplePlugin.SomeInteger");
    // Do stuff to the integer. Possibly modify the setting.
    PhSetIntegerSetting(L"ProcessHacker.SamplePlugin.SomeInteger", myInteger + 100);

    myString = PhGetStringSetting(L"ProcessHacker.SamplePlugin.SomeString");
    // Do stuff to the string.
    // Dereference the string when you're done, or memory will be leaked.
    PhDereferenceObject(myString);
}

VOID ShowOptionsCallback(
    __in_opt PVOID Parameter,
    __in_opt PVOID Context
    )
{
    PhShowError((HWND)Parameter, L"Show some options here.");
}

BOOLEAN NTAPI EnumDirectoryObjectsCallback(
    __in PPH_STRINGREF Name,
    __in PPH_STRINGREF TypeName,
    __in_opt PVOID Context
    )
{
    INT result;
    PPH_STRING name;
    PPH_STRING typeName;

    name = PhCreateString2(Name);
    typeName = PhCreateString2(TypeName);
    result = PhShowMessage(
        PhMainWndHandle,
        MB_ICONINFORMATION | MB_OKCANCEL,
        L"%s: %s",
        name->Buffer,
        typeName->Buffer
        );
    PhDereferenceObject(name);
    PhDereferenceObject(typeName);

    return result == IDOK;
}

VOID MenuItemCallback(
    __in_opt PVOID Parameter,
    __in_opt PVOID Context
    )
{
    PPH_PLUGIN_MENU_ITEM menuItem = Parameter;

    switch (menuItem->Id)
    {
    case ID_SAMPLE_MENU_ITEM:
        {
            PhShowInformation(PhMainWndHandle, L"You clicked the sample menu item!");
        }
        break;
    case ID_SHOW_ME_SOME_OBJECTS:
        {
            NTSTATUS status;
            HANDLE directoryHandle;
            OBJECT_ATTRIBUTES oa;
            UNICODE_STRING name;

            // Use the Native API seamlessly alongside Win32.
            RtlInitUnicodeString(&name, L"\\");
            InitializeObjectAttributes(&oa, &name, 0, NULL, NULL);

            if (NT_SUCCESS(status = NtOpenDirectoryObject(&directoryHandle, DIRECTORY_QUERY, &oa)))
            {
                PhEnumDirectoryObjects(directoryHandle, EnumDirectoryObjectsCallback, NULL);
                NtClose(directoryHandle);
            }
        }
        break;
    }
}

VOID MainWindowShowingCallback(
    __in_opt PVOID Parameter,
    __in_opt PVOID Context
    )
{
    // $ won't match anything, so the menu item will get added to the end.
    PhPluginAddMenuItem(PluginInstance, PH_MENU_ITEM_LOCATION_TOOLS, L"$",
        ID_SAMPLE_MENU_ITEM, L"Sample menu item", NULL);
    PhPluginAddMenuItem(PluginInstance, PH_MENU_ITEM_LOCATION_TOOLS, L"$",
        ID_SHOW_ME_SOME_OBJECTS, L"Show me some objects", NULL);
}

VOID GetProcessHighlightingColorCallback(
    __in_opt PVOID Parameter,
    __in_opt PVOID Context
    )
{
    PPH_PLUGIN_GET_HIGHLIGHTING_COLOR getHighlightingColor = Parameter;
    PPH_PROCESS_ITEM processItem;

    processItem = getHighlightingColor->Parameter;

    // Optional: if another plugin handled the highlighting, don't override it.
    if (getHighlightingColor->Handled)
        return;

    // Set the background color of svchost.exe processes to black.
    if (PhEqualString2(processItem->ProcessName, L"svchost.exe", TRUE))
    {
        getHighlightingColor->BackColor = RGB(0x00, 0x00, 0x00);
        getHighlightingColor->Cache = TRUE;
        getHighlightingColor->Handled = TRUE;
    }
}

VOID GetProcessTooltipTextCallback(
    __in_opt PVOID Parameter,
    __in_opt PVOID Context
    )
{
    PPH_PLUGIN_GET_TOOLTIP_TEXT getTooltipText = Parameter;
    PPH_PROCESS_ITEM processItem;

    processItem = getTooltipText->Parameter;

    // Put some text into the tooltip. This will go in just before the Notes section.
    PhAppendFormatStringBuilder(
        getTooltipText->StringBuilder,
        L"Sample plugin:\n    The process name is: %s\n",
        processItem->ProcessName->Buffer
        );
}
