#include <stdio.h>
#include "PEFuncs.h"

//wchar_t szFilePath[MAX_PATH] = TEXT("C:\\Users\\Administrator\\Desktop\\pe_header\\LockTray.exe");
wchar_t szFilePath[MAX_PATH] = TEXT("C:\\Users\\Administrator\\Desktop\\pe_header\\Counter.dll");
MAP_FILE_STRUCT stMapFile = {0,0,0};

int main()
{
	//LPVOID ImageBase = 0;
	
	if(!LoadFileR(szFilePath, &stMapFile))
	{
		printf("load failed\n");
		return 1;
	}
	
	LPVOID ImageBase = stMapFile.ImageBase;
	if(!IsPEFile(ImageBase))
	{
		printf("not a PE file\n");
		return 1;
	}

	PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS  pNth = GetNtHeaders(ImageBase);
	PIMAGE_FILE_HEADER pfh = GetFileHeader(ImageBase);
	PIMAGE_OPTIONAL_HEADER poh = GetOptionalHeader(ImageBase);
	PIMAGE_SECTION_HEADER  psh = GetFirstSectionHeader(ImageBase);

	PIMAGE_EXPORT_DIRECTORY pExport = GetExportDirectory(ImageBase);
	PIMAGE_IMPORT_DESCRIPTOR pImport = GetFirstImportDesc(ImageBase);
	
	printf("OEP: %x\n", poh->AddressOfEntryPoint);
	printf("ImageBase: %x\n", poh->ImageBase);
	printf("Size of Image: %x\n", poh->SizeOfImage);
	printf("Base of Code: %x\n", poh->BaseOfCode);
	printf("Base of Data: %x\n", poh->BaseOfData);
	printf("Section Alignment: %x\n", poh->SectionAlignment);
	printf("File Alignment: %x\n", poh->FileAlignment);
	printf("Magic: %x\n", pdh->e_magic);
	//printf("Signature: %x\n", pNth->Signature);
	printf("Subsystem: %x\n", poh->Subsystem);
	printf("Number Of Sections: %x\n", pfh->NumberOfSections);
	printf("TimeDateStamp: %x\n", pfh->TimeDateStamp);
	printf("Size of Headers: %x\n", poh->SizeOfHeaders);
	printf("Chracteristics: %x\n", pfh->Characteristics);
	printf("CheckSum: %x\n", poh->CheckSum);
	printf("Addr of OpHeader: %x\n", poh);
	printf("Number of Directory: %x\n", poh->NumberOfRvaAndSizes); 

	GetInfoOfSections(ImageBase);
	GetInfoOfINT(ImageBase);
	GetInfoOfExport(ImageBase);

	UnLoadFile(&stMapFile);

	getchar();
	return 0;
}