#define FIELD_OFFSET(type, field)    ((LONG)(LONG_PTR)&(((type *)0)->field))

//
// DOS MZ Header(IMAGE_DOS_HEADER)
// DOS Header(not fixed length) = DOS MZ Header(44h) + DOS sub(not fixed length)
// address:  ImageBase(装载地址)
// size:   44h
//
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number			CHECK	#define IMAGE_DOS_SIGNATURE 0x5A4D  ("MZ")	;0000h
    WORD   e_cblp;                      // Bytes on last page of file			;0002h
    WORD   e_cp;                        // Pages in file						;0004h
    WORD   e_crlc;                      // Relocations							;0006h
    WORD   e_cparhdr;                   // Size of header in paragraphs			;0008h
    WORD   e_minalloc;                  // Minimum extra paragraphs needed		;000ah
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed		;000ch
    WORD   e_ss;                        // Initial (relative) SS value			;000eh
    WORD   e_sp;                        // Initial SP value						;0010h
    WORD   e_csum;                      // Checksum								;0012h
    WORD   e_ip;                        // Initial IP value						;0014h
    WORD   e_cs;                        // Initial (relative) CS value			;0016h
    WORD   e_lfarlc;                    // File address of relocation table		;0018h
    WORD   e_ovno;                      // Overlay number						;001ah
    WORD   e_res[4];                    // Reserved words						;001ch
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)		;0024h
    WORD   e_oeminfo;                   // OEM information; e_oemid specific	;0026h
    WORD   e_res2[10];                  // Reserved words						;0028h
    LONG   e_lfanew;                    // File address of new exe header       sizeof(LONG) + sizeof(DOS sub)   ;003ch
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;


//
// PE header(IMAGE_NT_HEADERS)            
// address: ImageBase + IMAGE_DOS_HEADER.e_lfanew  
// size:    f8h  
//
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;			// CHECK   #define IMAGE_NT_SIGNATURE   0x00004550 (标志字"PE00")  ;IMAGE_NT_HEADERS+00h / ImageBase + *(ImageBase+003ch)
    IMAGE_FILE_HEADER FileHeader;					//   						;IMAGE_NT_HEADERS+04h
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;			//   						;IMAGE_NT_HEADERS+18h
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
  
  
//
// File header(IMAGE_FILE_HEADER)
// address:   &(IMAGE_NT_HEADERS->FileHeader) or IMAGE_NT_HEADERS+04h
// size:      14h

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;								//   						 ;IMAGE_NT_HEADERS+04h+00h
    WORD    NumberOfSections;	// 与实际节表数一致(加载器搜到全0结构提前结束)	 ;IMAGE_NT_HEADERS+04h+02h	    ;IMAGE_NT_HEADERS+06h
    DWORD   TimeDateStamp;		//  时间戳,编译器创建此文件的时间,可随意修改 	 ;IMAGE_NT_HEADERS+04h+04h      ;IMAGE_NT_HEADERS+08h
    DWORD   PointerToSymbolTable;					//   						 ;IMAGE_NT_HEADERS+04h+08h
    DWORD   NumberOfSymbols;						//   						 ;IMAGE_NT_HEADERS+04h+0ch
    WORD    SizeOfOptionalHeader;					//  OptionalHeader的大小 	 ;IMAGE_NT_HEADERS+04h+10h		;IMAGE_NT_HEADERS+14h
    WORD    Characteristics;						//  文件特征值,决定装载方式  ;IMAGE_NT_HEADERS+04h+12h      ;IMAGE_NT_HEADERS+16h
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;			



//
// Optional header(IMAGE_OPTIONAL_HEADER32)
// address:	IMAGE_NT_HEADERS->OptionalHeader or IMAGE_NT_HEADERS+18h
// size:    应与IMAGE_FILE_HEADER->SizeOfOptionalHeader一致。00e0h(32bit)/00fbh(64bit)，可以自行修改，但要保持一致和对齐
//

typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;									//    						 1;IMAGE_NT_HEADERS+18h+00h
    BYTE    MajorLinkerVersion;						//    						 2;IMAGE_NT_HEADERS+18h+02h
    BYTE    MinorLinkerVersion;						//    						 3;IMAGE_NT_HEADERS+18h+03h
    DWORD   SizeOfCode;								//    						 4;IMAGE_NT_HEADERS+18h+04h
    DWORD   SizeOfInitializedData;					//    						 5;IMAGE_NT_HEADERS+18h+08h   
    DWORD   SizeOfUninitializedData;				//    						 6;IMAGE_NT_HEADERS+18h+0ch	
    DWORD   AddressOfEntryPoint;					//    	OEP(RVA)			 7;IMAGE_NT_HEADERS+18h+10h	;IMAGE_NT_HEADERS+0028h
    DWORD   BaseOfCode;				//   代码基址(RVA)，节名一般为.text			 8;IMAGE_NT_HEADERS+18h+14h ;IMAGE_NT_HEADERS+002ch
    DWORD   BaseOfData;				//   数据基址(RVA)，节名一般为.data 		 9;IMAGE_NT_HEADERS+18h+18h ;IMAGE_NT_HEADERS+0030h

    //
    // NT additional fields.
    //

    DWORD   ImageBase;								//    默认ImageBase			10;IMAGE_NT_HEADERS+18h+1ch	;IMAGE_NT_HEADERS+0034h
    DWORD   SectionAlignment; // >=FileAlignment,内存中节(页)的对齐大小,(页4KB) 11;IMAGE_NT_HEADERS+18h+20h	;IMAGE_NT_HEADERS+0038h
    DWORD   FileAlignment;	  // 文件中节的对齐大小，(扇区512B~4KB)				12;IMAGE_NT_HEADERS+18h+24h	;IMAGE_NT_HEADERS+003ch
    WORD    MajorOperatingSystemVersion;			//							13;IMAGE_NT_HEADERS+18h+28h
    WORD    MinorOperatingSystemVersion;			//							14;IMAGE_NT_HEADERS+18h+2ah
    WORD    MajorImageVersion;						//							15;IMAGE_NT_HEADERS+18h+2ch
    WORD    MinorImageVersion;						//							16;IMAGE_NT_HEADERS+18h+2eh
    WORD    MajorSubsystemVersion;					//							17;IMAGE_NT_HEADERS+18h+30h
    WORD    MinorSubsystemVersion;					//							18;IMAGE_NT_HEADERS+18h+32h
    DWORD   Win32VersionValue;						//							19;IMAGE_NT_HEADERS+18h+34h
    DWORD   SizeOfImage;					//	镜像大小，n*SectionAlignment	20;IMAGE_NT_HEADERS+18h+38h	;IMAGE_NT_HEADERS+0050h
    DWORD   SizeOfHeaders;					//	PE头大小，	n*200h				21;IMAGE_NT_HEADERS+18h+3ch	;IMAGE_NT_HEADERS+0054h
    DWORD   CheckSum;								//							22;IMAGE_NT_HEADERS+18h+40h
    WORD    Subsystem;								//	所需的子系统类型		23;IMAGE_NT_HEADERS+18h+44h ;IMAGE_NT_HEADERS+005ch
    WORD    DllCharacteristics;						//							24;IMAGE_NT_HEADERS+18h+46h
    DWORD   SizeOfStackReserve;						//							25;IMAGE_NT_HEADERS+18h+48h
    DWORD   SizeOfStackCommit;						//							26;IMAGE_NT_HEADERS+18h+4ch
    DWORD   SizeOfHeapReserve;						//							27;IMAGE_NT_HEADERS+18h+50h
    DWORD   SizeOfHeapCommit;						//							28;IMAGE_NT_HEADERS+18h+54h
    DWORD   LoaderFlags;							//							29;IMAGE_NT_HEADERS+18h+58h
    DWORD   NumberOfRvaAndSizes;					//目录项数目,固定为16		30;IMAGE_NT_HEADERS+18h+5ch ;IMAGE_NT_HEADERS+0074h
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];	  //31;IMAGE_NT_HEADERS+18h+60h ;IMAGE_NT_HEADERS+0078h
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;


//
// Data Directory(IMAGE_DATA_DIRECTORY)
// #define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
// IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
// address: IMAGE_NT_HEADERS->DataDirectory or IMAGE_NT_HEADERS+0078h or IMAGE_OPTIONAL_HEADER+60h
// size: 8h
//
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

//NumberOfRvaAndSizes的默认值，目录项数目默认为16
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor



//
// DLL support.
//

//
// Export Format
//

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;


//
// Import Format
//

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
//导入方式：Ordinal是否是一个序号？即是否按按序号导入IAT|IMAGE_THUNK_DATA32.Function？(或按名称导入INT|IMAGE_THUNK_DATA32.AddressOfData|IMAGE_IMPORT_BY_NAME)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

//IID
//#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    };
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

// 
// INT  (IMAGE_THUNK_DATA32数组,以0为结束。OriginalFirstThunk始终指向INT表首地址)
// DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress --> IMAGE_IMPORT_DESCRIPTOR
// IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk --> IMAGE_THUNK_DATA32 (INT表首地址)
// INT表每个IMAGE_THUNK_DATA32.AddressOfData --> IMAGE_IMPORT_BY_NAME数组首地址
//
// IAT  (IMAGE_THUNK_DATA32数组,以0为结束。载入内存后IAT表每一项指向函数实际地址)
// DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress --> IMAGE_IMPORT_DESCRIPTOR
// INT表每个IMAGE_IMPORT_DESCRIPTOR.FirstThunk --> IMAGE_THUNK_DATA32(载入前和OriginalFirstThunk一样指向INT) / 实际函数地址表的首地址(载入后指向IAT表首地址)
// or
// DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress --> IMAGE_THUNK_DATA32(载入后指向IAT表首地址)
//
// IAT表每个IMAGE_THUNK_DATA32.Function --> IMAGE_IMPORT_BY_NAME数组首地址
//
typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;      // PBYTE 
        DWORD Function;             // PDWORD
        DWORD Ordinal;
        DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;


typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    BYTE    Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;



//
// Based relocation format.
//

typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
//  WORD    TypeOffset[1];
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;




#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)ntheader +                                              \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))
//
// Section header(IMAGE_SECTION_HEADER)
// IMAGE_SECTION_HEADER数组address: IMAGE_FIRST_SECTION : ImageBase(NT_HEADERS的首地址) + OptionalHeader在NT_HEADERS的偏移 + FileHeader.SizeOfOptionalHeader(OptionalHeader的大小)
// size: 28h (#define IMAGE_SIZEOF_SECTION_HEADER 40)  
//

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SHORT_NAME              8
#define IMAGE_SIZEOF_SECTION_HEADER          40
