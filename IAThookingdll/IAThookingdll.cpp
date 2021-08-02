#include "pch.h"
#include "framework.h"
#include "IAThookingdll.h"
#include <WinUser.h>
#include<stdio.h>

void msg()
{
    int msgboxID = MessageBox(
        NULL,
        (LPCWSTR)L"yeah!",
        (LPCWSTR)L"Execution Succeeded",
        MB_OK | MB_DEFBUTTON1 | MB_ICONASTERISK
    );
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
    
    import_directory = mappe(hprocess);

    while (import_directory->Name != 0)
    {
        int i = 0;
        iat_thunk = (PIMAGE_THUNK_DATA)(import_directory[i].FirstThunk + (DWORD64)import_directory);
        while (iat_thunk != 0)
        {
            idt_thunk = (PIMAGE_THUNK_DATA)(import_directory[1].OriginalFirstThunk + (DWORD64)import_directory);

            PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)(iat_thunk->u1.AddressOfData + (DWORD64)hprocess);

            DWORD64* name = (DWORD64*)(import_by_name + 2);
            iat_thunk++;
            i++;
        }
        import_directory++;
     }
    return 0;
}
