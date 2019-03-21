#include <windows.h>
#include <stdio.h>
#include <winnt.h>

typedef HMODULE(*LoadLibraryFunction) (LPCSTR lpLibFileName);
typedef LPVOID(*VirtualAllocFunction) (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef FARPROC(*GetProcAddressFunction) (HMODULE hModule, LPCSTR lpProcName);

typedef struct _ShellcodeInformation 
{
	byte* raw_module_destination;
	LoadLibraryFunction fnLoadLibrary;
	VirtualAllocFunction fnVirtualAlloc;
	GetProcAddressFunction fnGetProcAddress;
} ShellcodeInformation;

void LoadLibShellcode(ShellcodeInformation* modinfo)
{		   
	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)modinfo->raw_module_destination;

	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return;
	}			
					
	IMAGE_NT_HEADERS* headers = ((IMAGE_NT_HEADERS*)modinfo->raw_module_destination) + idh->e_lfanew;
	   
	if (headers->Signature != IMAGE_NT_SIGNATURE) {
		return;
	}	
					
	// reserve memory for the complete module
	byte* module_destination = (byte*)modinfo->fnVirtualAlloc(modinfo->raw_module_destination, headers->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_READWRITE);


	//
	// Map headers into memory
	//	  
	modinfo->fnVirtualAlloc(modinfo->raw_module_destination, headers->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
	for (SIZE_T index = 0; index < headers->OptionalHeader.SizeOfHeaders; index++)
	{
		module_destination[index] = modinfo->raw_module_destination[index];
	}	   
	// Update pointer to headers
	IMAGE_NT_HEADERS* new_headers = (IMAGE_NT_HEADERS*)module_destination + idh->e_lfanew;

	//
	// Map sections into memory
	//						
	for (int section_counter = 0; section_counter < new_headers->FileHeader.NumberOfSections; section_counter++)
	{
		IMAGE_SECTION_HEADER* ish = (IMAGE_SECTION_HEADER *)((DWORD)&(new_headers->OptionalHeader) + (section_counter * sizeof(IMAGE_OPTIONAL_HEADER)));
		byte* section_destination = 0;
		if (ish->SizeOfRawData != 0)
		{
			// commit the memory for this section
			section_destination = (byte*)modinfo->fnVirtualAlloc(module_destination + ish->VirtualAddress, ish->SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
														 
			// copy section into final location
			for (SIZE_T index = 0; index < ish->SizeOfRawData; index++)
			{
				(module_destination + ish->VirtualAddress)[index] = (modinfo->raw_module_destination + ish->PointerToRawData)[index];
			}
		}
		else
		{
			// Zero the empty areas just in case
			if (ish->Characteristics == IMAGE_SCN_CNT_INITIALIZED_DATA)
			{
				section_destination = (byte*)modinfo->fnVirtualAlloc(module_destination + ish->VirtualAddress, new_headers->OptionalHeader.SizeOfInitializedData, MEM_COMMIT, PAGE_READWRITE);

				for (SIZE_T index = 0; index < new_headers->OptionalHeader.SizeOfInitializedData; index++)
				{
					(module_destination + ish->VirtualAddress)[index] = 0;
				}
				
			}
			else if (ish->Characteristics == IMAGE_SCN_CNT_UNINITIALIZED_DATA)
			{
				section_destination = (byte*)modinfo->fnVirtualAlloc(module_destination + ish->VirtualAddress, new_headers->OptionalHeader.SizeOfUninitializedData, MEM_COMMIT, PAGE_READWRITE);

				for (SIZE_T index = 0; index < new_headers->OptionalHeader.SizeOfUninitializedData; index++)
				{
					(module_destination + ish->VirtualAddress)[index] = 0;
				}	 					
			}	 			
		}

		// store the final destination of the section back in the header
		ish->Misc.PhysicalAddress = (DWORD)section_destination;				
	}


	//
	// Perform Relocations
	//

	DWORD delta = (DWORD)module_destination - headers->OptionalHeader.ImageBase;
	IMAGE_DATA_DIRECTORY* relocation_directory_entry = &new_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	IMAGE_BASE_RELOCATION* relocation_table = (IMAGE_BASE_RELOCATION*)(module_destination + relocation_directory_entry->VirtualAddress);

	int index = 0;
	while (relocation_table->VirtualAddress > 0)
	{
		for (int relocations = 0; relocations < ((relocation_table[index].SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); relocations++)
		{
			WORD reloc_info = *(WORD*)(relocation_table + sizeof(IMAGE_BASE_RELOCATION) + (relocations * sizeof(WORD)));
			int type, offset;

			type = reloc_info >> 12;
			offset = reloc_info & 0xfff;

			if (type == IMAGE_REL_BASED_HIGHLOW)
			{
				*(DWORD*)(module_destination + relocation_table->VirtualAddress + offset) += delta;
			}  
		}  	
		relocation_table += relocation_table->SizeOfBlock;
	}

	//
	// Imports
	//

	//
	// Set Section Memory flags
	//

	// Delete raw data

	return;
}	  	  	 
					   
void END_SHELLCODE(void) {}


int main(int argc, char *argv[])
{

 // will not work in debug
#ifdef _DEBUG
	return 1337;
#endif

	FILE *output_file;
	
#ifdef WIN_X86
	const char* fileName = "shellcode_x86.bin";
#endif

#ifdef WIN_X64
	const char* fileName = "shellcode_x64.bin";
#endif // WIN_X64
						
	fopen_s(&output_file, fileName, "w");
    fwrite(LoadLibShellcode, (long)END_SHELLCODE - (long)LoadLibShellcode, 1, output_file);
    fclose(output_file);

    return 0;
}