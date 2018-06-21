#include "PEFuncs.h"
#include <imagehlp.h>
#include <stdio.h>

//RVA-->FOA+ImageBase, use NT_HEADERS to get Section Table
LPVOID RvaToPtr(PIMAGE_NT_HEADERS pNtH,LPVOID ImageBase,DWORD dwRVA)
{
	//return ImageRvaToVa(pNtH,ImageBase,dwRVA,NULL);
	DWORD dwVa;
    PIMAGE_SECTION_HEADER psh =IMAGE_FIRST_SECTION(pNtH);

	for(int i=0;i<pNtH->FileHeader.NumberOfSections;i++,psh++)
	{  
     if(dwRVA >= psh->VirtualAddress  && dwRVA < (psh->SizeOfRawData + psh->VirtualAddress ) )
	 {
        dwVa=(DWORD)ImageBase + (psh->PointerToRawData - psh->VirtualAddress + dwRVA);
        return (LPVOID)dwVa;
      }
    }
    return NULL;
}

BOOL  LoadFileR(LPTSTR lpFilename,PMAP_FILE_STRUCT pstMapFile)
{

	HANDLE hFile;
	HANDLE hMapping;
	LPVOID ImageBase;

	memset(pstMapFile,0,sizeof(MAP_FILE_STRUCT));

	hFile=CreateFile(lpFilename,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL,0);
	
	if (!hFile)				   
		return FALSE;

	hMapping=CreateFileMapping(hFile,NULL,PAGE_READONLY,0,0,NULL);
	if(!hMapping)
	{									
		CloseHandle(hFile);
		return FALSE;
	}
	ImageBase=MapViewOfFile(hMapping,FILE_MAP_READ,0,0,0);
    if(!ImageBase)
	{									
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return FALSE;
	}
	pstMapFile->hFile=hFile;
	pstMapFile->hMapping=hMapping;
	pstMapFile->ImageBase=ImageBase;
	return TRUE;
}

void UnLoadFile(PMAP_FILE_STRUCT pstMapFile)
{
	if(pstMapFile->ImageBase)
		UnmapViewOfFile(pstMapFile->ImageBase);
	
	if(pstMapFile->hMapping)
		CloseHandle(pstMapFile->hMapping);
	
	if(pstMapFile->hFile)
		CloseHandle(pstMapFile->hFile);
	
}

BOOL IsPEFile(LPVOID ImageBase)
{
	PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)ImageBase;
	if(!pdh)
	{
		return FALSE;
	}
	if(IMAGE_DOS_SIGNATURE != pdh->e_magic)
	{
		return FALSE;
	}
	PIMAGE_NT_HEADERS pNtH = (PIMAGE_NT_HEADERS)((DWORD)pdh + pdh->e_lfanew);
	if(IMAGE_NT_SIGNATURE != pNtH->Signature)
	{
		return FALSE;
	}
	return TRUE;
}

PIMAGE_NT_HEADERS      GetNtHeaders(LPVOID ImageBase)
{
	PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS pNtH = (PIMAGE_NT_HEADERS)((DWORD)pdh + pdh->e_lfanew);
	return pNtH;
}

PIMAGE_FILE_HEADER     GetFileHeader(LPVOID ImageBase)
{
	PIMAGE_NT_HEADERS pNtH = GetNtHeaders(ImageBase);
	PIMAGE_FILE_HEADER pfh = &pNtH->FileHeader;
	return pfh;
}

PIMAGE_OPTIONAL_HEADER GetOptionalHeader(LPVOID ImageBase)
{
	PIMAGE_NT_HEADERS pNtH = GetNtHeaders(ImageBase);
	PIMAGE_OPTIONAL_HEADER poh = &pNtH->OptionalHeader;
	return poh;
}



//DataDirectory[DirectoryEntry].VirtualAddress --> FOA+ImageBase
LPVOID GetDirectoryEntryToData(LPVOID ImageBase,USHORT DirectoryEntry)
{
	PIMAGE_NT_HEADERS pNtH = GetNtHeaders(ImageBase);
	PIMAGE_OPTIONAL_HEADER poh = GetOptionalHeader(ImageBase);
	DWORD dwRVA = poh->DataDirectory[DirectoryEntry].VirtualAddress;
	return RvaToPtr(pNtH, ImageBase, dwRVA);
}

PIMAGE_EXPORT_DIRECTORY GetExportDirectory(LPVOID ImageBase)
{
	return (PIMAGE_EXPORT_DIRECTORY)GetDirectoryEntryToData(ImageBase, IMAGE_DIRECTORY_ENTRY_EXPORT);
}

PIMAGE_IMPORT_DESCRIPTOR  GetFirstImportDesc(LPVOID ImageBase)
{
	return (PIMAGE_IMPORT_DESCRIPTOR)GetDirectoryEntryToData(ImageBase, IMAGE_DIRECTORY_ENTRY_IMPORT);
}

DWORD   GetNumOfExportFuncs(LPVOID ImageBase,PIMAGE_EXPORT_DIRECTORY pExportDir)
{
	//return pExportDir->NumberOfFunctions;
	PIMAGE_NT_HEADERS pNtH = GetNtHeaders(ImageBase);
	PDWORD pFunc = (PDWORD)RvaToPtr(pNtH, ImageBase, pExportDir->AddressOfFunctions);
	int number = 0;
	for(DWORD i = 0; i < pExportDir->NumberOfFunctions; i++, pFunc++)
	{
		if(*pFunc)
		{
			number++;
		}
	}
	return number;
}

PIMAGE_SECTION_HEADER  GetFirstSectionHeader(LPVOID ImageBase)
{
	PIMAGE_NT_HEADERS pNtH = GetNtHeaders(ImageBase);
	return IMAGE_FIRST_SECTION(pNtH);
}
/*
DWORD   GetNumberOfSections(LPVOID ImageBase)
{
	//PIMAGE_SECTION_HEADER psh = GetFirstSectionHeader(ImageBase);
	return 0;
}
*/

LPVOID   GetInfoOfSections(LPVOID ImageBase)
{
	//PIMAGE_SECTION_HEADER psh = GetFirstSectionHeader(ImageBase);
	PIMAGE_NT_HEADERS pNtH = GetNtHeaders(ImageBase);
	PIMAGE_SECTION_HEADER psh = GetFirstSectionHeader(ImageBase);
	PIMAGE_OPTIONAL_HEADER poh = GetOptionalHeader(ImageBase);
	PIMAGE_FILE_HEADER pfh = GetFileHeader(ImageBase);

	IMAGE_SECTION_HEADER null_section;
	memset(&null_section, 0, sizeof(IMAGE_SECTION_HEADER));
	for(int i = 0; i < pfh->NumberOfSections; i++, psh++)
	{
		if(!memcmp(psh, &null_section, sizeof(IMAGE_SECTION_HEADER)))
		{
			break;
		}
		printf("------Section %d------\n", i);
		printf("Name: %s\n", psh->Name);
		printf("VAddress: %x\n", psh->VirtualAddress);
		printf("VSize: %x\n", psh->Misc);  //VirtualSize
		printf("ROffset: %x\n", psh->PointerToRawData);
		printf("RSize: %x\n", psh->SizeOfRawData);
		printf("Flags: %x\n", psh->Characteristics);
	}

	return 0;
}

LPVOID   GetInfoOfINT(LPVOID ImageBase)
{
	PIMAGE_NT_HEADERS pNtH = GetNtHeaders(ImageBase);
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = GetFirstImportDesc(ImageBase);
	
	IMAGE_IMPORT_DESCRIPTOR null_iid;
	memset(&null_iid, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	
	PIMAGE_THUNK_DATA32 null_thunk;
	memset(&null_thunk, 0, sizeof(PIMAGE_THUNK_DATA32));

	for(PIMAGE_IMPORT_DESCRIPTOR iid = pImportTable; 
		memcmp(iid, &null_iid, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		iid++)
	{
		printf("-------INT---------\n");
		LPCSTR szDllName = (LPCSTR)RvaToPtr(pNtH, ImageBase, iid->Name);
		printf("Dll Name: %s\n", szDllName);
		printf("OriginalFirstThunk: %x\n", iid->OriginalFirstThunk);
		printf("FirstThunk: %x\n", iid->FirstThunk);
		PIMAGE_THUNK_DATA32 thunk = (PIMAGE_THUNK_DATA32)RvaToPtr(pNtH, ImageBase, iid->OriginalFirstThunk);
		//PIMAGE_THUNK_DATA32 thunk = (PIMAGE_THUNK_DATA32)RvaToPtr(pNtH, ImageBase, iid->FirstThunk);
		for(int i = 0;
			memcmp(thunk, &null_thunk, sizeof(PIMAGE_THUNK_DATA32));
			i++, thunk++)
		{
			//if(thunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG32)
			if(IMAGE_SNAP_BY_ORDINAL32(thunk->u1.AddressOfData))
			{
				printf("Import by Ordinal: %d	%x\n", i, thunk->u1.AddressOfData & 0xffff);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pFunc = (PIMAGE_IMPORT_BY_NAME)RvaToPtr(pNtH, ImageBase, thunk->u1.AddressOfData);
				printf("Ordinal: %x		Name:%s\n", pFunc->Hint, pFunc->Name);
			}
		}
	}

	return 0;
}

LPVOID   GetInfoOfIAT(LPVOID ImageBase)
{
	return 0;
}

DWORD  GetInfoOfExport(LPVOID ImageBase)
{
	PIMAGE_NT_HEADERS pNtH = GetNtHeaders(ImageBase);
	PIMAGE_EXPORT_DIRECTORY pExportDir = GetExportDirectory(ImageBase);

	LPCSTR szName = (LPSTR)RvaToPtr(pNtH, ImageBase, pExportDir->Name);
	printf("-------EXPORT---------\n");
	printf("%s\n", szName);
	PDWORD pFunctions = (PDWORD)RvaToPtr(pNtH, ImageBase, pExportDir->AddressOfFunctions);
	PDWORD pNames = (PDWORD)RvaToPtr(pNtH, ImageBase, pExportDir->AddressOfNames);
	//Ordinal Type: WORD
	PWORD pNameOrdinals = (PWORD)RvaToPtr(pNtH, ImageBase, pExportDir->AddressOfNameOrdinals);		
	DWORD number = 0;
	for(DWORD i = 0; i < pExportDir->NumberOfFunctions; i++)
	{
		LPCSTR name = (LPSTR)RvaToPtr(pNtH, ImageBase, *(pNames + i));
		//Ordinal Type: WORD
		WORD ordinal = *(pNameOrdinals + i);
		DWORD func = *(pFunctions + ordinal);
		if(func)
		{
			printf("%s %x %x\n", name, ordinal, func);
			number++;
		}
	}
	return number;
}

LPVOID   GetInfoOfRebase(LPVOID ImageBase)
{
	
	return 0;
}