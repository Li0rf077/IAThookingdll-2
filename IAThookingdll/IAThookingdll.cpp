#include "pch.h"
#include "framework.h"
#include "IAThookingdll.h"
#include <WinUser.h>
#include<stdio.h>

void msg()
{
    MessageBox(NULL, (LPCWSTR)L"yeah!", (LPCWSTR)L"Execution Succeeded", MB_OK | MB_DEFBUTTON1 | MB_ICONASTERISK);
}

PIMAGE_IMPORT_DESCRIPTOR mappe(HMODULE hprocess)
{
    PIMAGE_DOS_HEADER dos_h = (PIMAGE_DOS_HEADER)hprocess;
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(dos_h->e_lfanew + (DWORD64)hprocess);
    IMAGE_FILE_HEADER file_header = (IMAGE_FILE_HEADER)nt_header->FileHeader;
    IMAGE_OPTIONAL_HEADER optional_header = (IMAGE_OPTIONAL_HEADER)nt_header->OptionalHeader;
    PIMAGE_IMPORT_DESCRIPTOR import_directory = (PIMAGE_IMPORT_DESCRIPTOR)(optional_header.DataDirectory[1].VirtualAddress + (DWORD64)hprocess);

    return import_directory;
}

IATHOOKINGDLL_API int hook()
{
    PIMAGE_IMPORT_DESCRIPTOR import_directory;
    PIMAGE_THUNK_DATA iat_thunk, idt_thunk;

    HMODULE hprocess = GetModuleHandle(NULL);
    if (!hprocess) {printf_s("unable to get process hmodule"); return 0;}
    
    // Get import directory
    import_directory = mappe(hprocess);
    
    // Iterete through all imported dlls
    while (import_directory->Name != 0)
    {
        char* nana = (char*)(import_directory->Name + (DWORD64)hprocess);

        // Find our dll
        if (!strcmp(nana,"api-ms-win-core-errorhandling-l1-1-0.dll")) 
        {
            int i = 0;
            iat_thunk = (PIMAGE_THUNK_DATA)(import_directory->FirstThunk + (DWORD64)hprocess);
            idt_thunk = (PIMAGE_THUNK_DATA)(import_directory->OriginalFirstThunk + (DWORD64)hprocess);
            
            // Iterete through all functions in our dll - via INT table
            while (idt_thunk->u1.AddressOfData != 0)
            {
                PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)(idt_thunk->u1.AddressOfData + (DWORD64)hprocess);

                char* name = (char*)import_by_name->Name;

                // Find wanted function to hook
                if (strcmp(name, "GetLastError") == 0)
                {
                    // Check if function is not being called by ordinal 
                    if (!(iat_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
                    {
                        // Adress of function to change!
                        LPVOID wanted_address = (LPVOID)(iat_thunk->u1.Function);

                        // Save original page permissions of the process
                        DWORD64 sourceAddr = iat_thunk->u1.Function;

                        // Change permissions on pages
                        DWORD old;
                        VirtualProtect(iat_thunk, 4096, PAGE_EXECUTE_READWRITE, &old);

                        // Change the address of GetStartupinfoW to msg()
                        DWORD64 msg_address = (DWORD64)msg;
                        iat_thunk->u1.Function = msg_address;

                        // Return to previous permissions
                        DWORD junk;
                        VirtualProtect(wanted_address, 4096, old, &junk);

                        return 0;
                    }
                }
                idt_thunk++;
                iat_thunk++;
            }
        }
        import_directory++;
    } 
    return 1;
}
