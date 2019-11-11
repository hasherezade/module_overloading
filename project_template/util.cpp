#include "util.h"
#include <peconv.h>

DWORD translate_protect(DWORD sec_charact)
{
	if ((sec_charact & IMAGE_SCN_MEM_EXECUTE)
		&& (sec_charact & IMAGE_SCN_MEM_READ)
		&& (sec_charact & IMAGE_SCN_MEM_WRITE))
	{
		return PAGE_EXECUTE_READWRITE;
	}
	if ((sec_charact & IMAGE_SCN_MEM_EXECUTE)
		&& (sec_charact & IMAGE_SCN_MEM_READ))
	{
		return PAGE_EXECUTE_READ;
	}
	if (sec_charact & IMAGE_SCN_MEM_EXECUTE)
	{
		return PAGE_EXECUTE_READ;
	}

	if ((sec_charact & IMAGE_SCN_MEM_READ)
		&& (sec_charact & IMAGE_SCN_MEM_WRITE))
	{
		return PAGE_READWRITE;
	}
	if (sec_charact &  IMAGE_SCN_MEM_READ) {
		return PAGE_READONLY;
	}

	return PAGE_READWRITE;
}

bool is_compatibile(BYTE *implant_dll)
{
	bool is_payload64 = peconv::is64bit(implant_dll);
#ifdef _WIN64
	if (!is_payload64) {
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

