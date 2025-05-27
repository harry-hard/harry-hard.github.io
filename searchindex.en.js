var relearn_searchindex = [
  {
    "breadcrumb": "hacker 0x0ff \u003e  pe loader",
    "content": "从硬盘映射PE到内存 从硬盘直接读取的PE文件头名为**RawData。\nPointerToRawData 字段记录的是该节在 PE 文件中的起始偏移量（以字节为单位）。也就是说，通过这个偏移量，我们可以在磁盘上的 PE 文件中准确找到该节的原始数据。\n所以通过以下代码可以将硬盘中的pe文件放到内存中的pe结构中，模拟了windows从硬盘加载PE文件的过程：\n// 给PE文件分配内存 if ((pPeBaseAddress = VirtualAlloc(NULL, pPeHdrs-\u003epImgNtHdrs-\u003eOptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) == NULL) { PRINT_WINAPI_ERR(\"VirtualAlloc\"); return FALSE; } // Copying PE headers - IOC // memcpy(pPeBaseAddress, pPeHdrs-\u003epFileBuffer, pPeHdrs-\u003epImgNtHdrs-\u003eOptionalHeader.SizeOfHeaders); for (int i = 0; i \u003c pPeHdrs-\u003epImgNtHdrs-\u003eFileHeader.NumberOfSections; i++) { memcpy( (PVOID)(pPeBaseAddress + pPeHdrs-\u003epImgSecHdr[i].VirtualAddress),//目的地址：内存地址+RVA (PVOID)((ULONG_PTR)pPeHdrs-\u003epFileBuffer + pPeHdrs-\u003epImgSecHdr[i].PointerToRawData),//源地址：硬盘地址+RVA pPeHdrs-\u003epImgSecHdr[i].SizeOfRawData ); }",
    "description": "从硬盘映射PE到内存 从硬盘直接读取的PE文件头名为**RawData。\nPointerToRawData 字段记录的是该节在 PE 文件中的起始偏移量（以字节为单位）。也就是说，通过这个偏移量，我们可以在磁盘上的 PE 文件中准确找到该节的原始数据。\n所以通过以下代码可以将硬盘中的pe文件放到内存中的pe结构中，模拟了windows从硬盘加载PE文件的过程：\n// 给PE文件分配内存 if ((pPeBaseAddress = VirtualAlloc(NULL, pPeHdrs-\u003epImgNtHdrs-\u003eOptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) == NULL) { PRINT_WINAPI_ERR(\"VirtualAlloc\"); return FALSE; } // Copying PE headers - IOC // memcpy(pPeBaseAddress, pPeHdrs-\u003epFileBuffer, pPeHdrs-\u003epImgNtHdrs-\u003eOptionalHeader.SizeOfHeaders); for (int i = 0; i \u003c pPeHdrs-\u003epImgNtHdrs-\u003eFileHeader.NumberOfSections; i++) { memcpy( (PVOID)(pPeBaseAddress + pPeHdrs-\u003epImgSecHdr[i].VirtualAddress),//目的地址：内存地址+RVA (PVOID)((ULONG_PTR)pPeHdrs-\u003epFileBuffer + pPeHdrs-\u003epImgSecHdr[i].PointerToRawData),//源地址：硬盘地址+RVA pPeHdrs-\u003epImgSecHdr[i].SizeOfRawData ); }",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "1.将硬盘上的PE文件写入内存",
    "uri": "/pe-loader/%E5%86%99%E5%85%A5pe%E8%87%B3%E5%86%85%E5%AD%98/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  pe loader",
    "content": "2.重定位PE文件的重定位块和重定位项 当可执行映像加载到的地址与其首选基地址（IMAGE_OPTIONAL_HEADER.ImageBase）不同时，重定位对于调整可执行映像中的硬编码地址是必要的。在大多数情况下，PE 文件会被映射到除 IMAGE_OPTIONAL_HEADER.ImageBase 之外的地址，因此需要对 PE 文件中的某些硬编码地址进行调整。 通过计算得出地址差值：\n// The difference between the current PE image base address and its preferable base address. ULONG_PTR uDeltaOffset = pPeBaseAddress - pPreferableAddress; 下面是微软SDK定义的重定位块的头部结构\ntypedef struct _IMAGE_BASE_RELOCATION { DWORD VirtualAddress; DWORD SizeOfBlock; } IMAGE_BASE_RELOCATION; 并没有对BASE_RELOCATION_ENTRY做出定义，但描述为：\n每个重定位条目占用2字节(WORD)\n每个重定位条目占用2字节(WORD) 高4位是类型(Type) 低12位是偏移量(Offset) 代码具体实现可以是：\ntypedef struct _BASE_RELOCATION_ENTRY { WORD\tOffset\t: 12; //前12字节 WORD\tType\t: 4; //后4字节 //WORD总共占16位 } BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY; IMAGE_BASE_RELOCATION和BASE_RELOCATION_ENTRY在PE文件中的位置关系是：\n+——————————–+——————+——————+— | IMAGE_BASE_RELOCATION (8字节) | 重定位条目1 | 重定位条目2 | … | - VirtualAddress (4字节) | (2字节) | (2字节) | | - SizeOfBlock (4字节) | | | +—————————————-+—————-+———–+— ↑ ↑ pImgBaseRelocation pImgBaseRelocation + 1\n于是可以通过以下代码访问BASE_RELOCATION_ENTRY：\npBaseRelocEntry = (PBASE_RELOCATION_ENTRY)(pImgBaseRelocation + 1); 并通过下列switch语句根据预定义Type改变重定位地址：\nswitch (pBaseRelocEntry-\u003eType) { case IMAGE_REL_BASED_DIR64: // Adjust a 64-bit field by the delta offset. *((ULONG_PTR*)(pPeBaseAddress + pImgBaseRelocation-\u003eVirtualAddress + pBaseRelocEntry-\u003eOffset)) += uDeltaOffset; break; case IMAGE_REL_BASED_HIGHLOW: // Adjust a 32-bit field by the delta offset. *((DWORD*)(pPeBaseAddress + pImgBaseRelocation-\u003eVirtualAddress + pBaseRelocEntry-\u003eOffset)) += (DWORD)uDeltaOffset; break; case IMAGE_REL_BASED_HIGH: // Adjust the high 16 bits of a 32-bit field. *((WORD*)(pPeBaseAddress + pImgBaseRelocation-\u003eVirtualAddress + pBaseRelocEntry-\u003eOffset)) += HIWORD(uDeltaOffset); break; case IMAGE_REL_BASED_LOW: // Adjust the low 16 bits of a 32-bit field. *((WORD*)(pPeBaseAddress + pImgBaseRelocation-\u003eVirtualAddress + pBaseRelocEntry-\u003eOffset)) += LOWORD(uDeltaOffset); break; case IMAGE_REL_BASED_ABSOLUTE: // No relocation is required. break; default: // Handle unknown relocation types. printf(\"[!] Unknown relocation type: %d | Offset: 0x%08X \\n\", pBaseRelocEntry-\u003eType, pBaseRelocEntry-\u003eOffset); return FALSE; } 总结就是：\nPE（Portable Executable）文件的重定位块是为了解决PE文件在加载到内存时，实际加载地址与首选加载地址不一致的问题。当文件不能被加载到其首选基地址（IMAGE_OPTIONAL_HEADER.ImageBase）时，就需要对文件中硬编码的地址进行调整，这些调整信息就存储在重定位块中。以下详细介绍重定位块的结构和包含的信息：\n重定位表的整体布局 重定位信息存储在.reloc节中，重定位表由多个重定位块（Base Relocation Block）组成。每个重定位块描述一个4KB（4096字节）的内存页面。\n重定位块的结构 1. 重定位块头部（IMAGE_BASE_RELOCATION 结构） 每个重定位块以 IMAGE_BASE_RELOCATION 结构开头，该结构定义在 Windows 头文件中，其结构如下：\ntypedef struct _IMAGE_BASE_RELOCATION { DWORD VirtualAddress; // RVA to the base address of the section this block describes. DWORD SizeOfBlock; // The total size of the block, including the block header and all entries (discussed below). } IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION; VirtualAddress：这是一个相对虚拟地址（RVA），表示该重定位块所描述的内存页面的起始地址。也就是说，这个 RVA 指向需要进行重定位操作的内存页面的基地址。 SizeOfBlock：表示整个重定位块的大小，包括块头部（IMAGE_BASE_RELOCATION 结构本身）和后续的所有重定位条目（BASE_RELOCATION_ENTRY 结构数组）。通过这个值可以确定该重定位块在内存中占用的字节数，从而可以正确遍历块内的所有重定位条目。 2. 重定位条目（BASE_RELOCATION_ENTRY 结构数组） 重定位块头部之后紧跟着一个 BASE_RELOCATION_ENTRY 结构数组，每个结构代表一个重定位条目。BASE_RELOCATION_ENTRY 结构定义如下：\ntypedef struct _BASE_RELOCATION_ENTRY { WORD Offset : 12; // Specifies where the base relocation is to be applied. WORD Type : 4; // Indicates the type of base relocation to be applied. } BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY; Offset：占用 12 位，指定了从当前重定位块的 VirtualAddress 开始的偏移量。通过这个偏移量，可以确定需要进行重定位操作的具体内存位置。例如，如果 VirtualAddress 是某个页面的起始地址，Offset 则表示在这个页面内需要调整地址的具体偏移位置。 Type：占用 4 位，指示了要应用的基址重定位类型。不同的重定位类型决定了如何对相应的地址进行调整。常见的重定位类型如下： IMAGE_REL_BASED_DIR64：用于 64 位地址的重定位，需要将整个 64 位的地址加上基地址的偏移量。 IMAGE_REL_BASED_HIGHLOW：用于 32 位地址的重定位，将 32 位地址加上基地址偏移量的低 32 位。 IMAGE_REL_BASED_HIGH：用于调整 32 位地址的高 16 位，只需要加上基地址偏移量的高 16 位。 IMAGE_REL_BASED_LOW：用于调整 32 位地址的低 16 位，只需要加上基地址偏移量的低 16 位。 IMAGE_REL_BASED_ABSOLUTE：表示该条目不需要进行重定位，通常用于占位或预留。 重定位块的遍历过程 在进行重定位操作时，需要遍历所有的重定位块和每个块内的重定位条目。大致的遍历过程如下：\n从重定位表的起始位置开始，获取第一个重定位块的头部（IMAGE_BASE_RELOCATION 结构）。 根据 VirtualAddress 和 SizeOfBlock 信息，确定该重定位块所描述的页面和块的大小。 从块头部之后开始，依次读取每个 BASE_RELOCATION_ENTRY 结构，根据 Type 字段确定重定位类型，根据 Offset 字段确定要调整的具体内存位置，然后进行相应的地址调整。 当遍历完当前重定位块内的所有条目后，根据 SizeOfBlock 移动到下一个重定位块的头部，重复上述步骤，直到所有重定位块都被处理完毕。 通过这种方式，可以确保 PE 文件在加载到任意内存地址时，其内部的硬编码地址都能被正确调整，从而保证程序的正常运行。",
    "description": "2.重定位PE文件的重定位块和重定位项 当可执行映像加载到的地址与其首选基地址（IMAGE_OPTIONAL_HEADER.ImageBase）不同时，重定位对于调整可执行映像中的硬编码地址是必要的。在大多数情况下，PE 文件会被映射到除 IMAGE_OPTIONAL_HEADER.ImageBase 之外的地址，因此需要对 PE 文件中的某些硬编码地址进行调整。 通过计算得出地址差值：\n// The difference between the current PE image base address and its preferable base address. ULONG_PTR uDeltaOffset = pPeBaseAddress - pPreferableAddress; 下面是微软SDK定义的重定位块的头部结构\ntypedef struct _IMAGE_BASE_RELOCATION { DWORD VirtualAddress; DWORD SizeOfBlock; } IMAGE_BASE_RELOCATION; 并没有对BASE_RELOCATION_ENTRY做出定义，但描述为：\n每个重定位条目占用2字节(WORD)\n每个重定位条目占用2字节(WORD) 高4位是类型(Type) 低12位是偏移量(Offset) 代码具体实现可以是：\ntypedef struct _BASE_RELOCATION_ENTRY { WORD\tOffset\t: 12; //前12字节 WORD\tType\t: 4; //后4字节 //WORD总共占16位 } BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY; IMAGE_BASE_RELOCATION和BASE_RELOCATION_ENTRY在PE文件中的位置关系是：\n+——————————–+——————+——————+— | IMAGE_BASE_RELOCATION (8字节) | 重定位条目1 | 重定位条目2 | … | - VirtualAddress (4字节) | (2字节) | (2字节) | | - SizeOfBlock (4字节) | | | +—————————————-+—————-+———–+— ↑ ↑ pImgBaseRelocation pImgBaseRelocation + 1",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "重定位的处理",
    "uri": "/pe-loader/%E9%87%8D%E5%AE%9A%E4%BD%8D%E8%A1%A8%E7%9A%84%E5%A4%84%E7%90%86/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  pe loader",
    "content": "IAT修复 IAT修复有双层循环，第一层循环是判断还有没有dll文件，第二层循环是判断dll内的函数到没到头。\n导入表的访问从IMAGE_DATA_DIRECTORY结构开始\npehdr.peNtHdr-\u003eOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]\n在pe的基地址加上这个IMAGE_DATA_DIRECTORY的VA，访问到第一个PIMAGE_IMPORT_DESCRIPTOR结构\nIMAGE_IMPORT_DESCRIPTOR 结构体布局\n| 偏移 | 字段名称 | 类型 | 大小(字节) | 说明 |\n|——|———-|——|————|——|\n| 0x00 | OriginalFirstThunk | DWORD | 4 | 指向 INT (导入名称表) 的 RVA |\n| 0x04 | TimeDateStamp | DWORD | 4 | 时间戳，0表示未绑定 |\n| 0x08 | ForwarderChain | DWORD | 4 | 转发链信息 |\n| 0x0C | Name | DWORD | 4 | 指向 DLL 名称字符串的 RVA |\n| 0x10 | FirstThunk | DWORD | 4 | 指向 IAT (导入地址表) 的 RVA |\n第一层循环就是PIMAGE_IMPORT_DESCRIPTOR→name≠0时\nIMAGE_IMPORT_DESCRIPTOR 这个结构体里面可以获取OriginalFirstThunk 和FirstThunk 的RVA\n加载dll，用LoadLibraryA加载base+PIMAGE_IMPORT_DESCRIPTOR→name\nOriginalFirstThunk 和FirstThunk 都是PIMAGE_THUNK_DATA结构\n这俩都通过基地址加上RVA获得\n其中OriginalFirstThunk 是不变的，专门保存函数的名字和信息\nFirstThunk 是应该改变的，pe文件加载后变成FirstThunk.function变成实际地址\n所以通过OriginalFirstThunk 访问u1联合体，\nIMAGE_SNAP_BY_ORDINAL(OriginalFirstThunk .u1.ordinal)宏判断是否用ordinal获取函数地址\n如果不是，就用OriginalFirstThunk .u1.AddressOfData\n值得注意的是，为了获取dll里全部应该获取的函数，需要在这一层循环中每次获取OriginalFirstThunk 和FirstThunk时加上一个他们的大小，以跳到下一个OriginalFirstThunk 和FirstThunk。\n最后在最外出循环PIMAGE_IMPORT_DESCRIPTOR自增，跳到下一个PIMAGE_IMPORT_DESCRIPTOR获取dll。",
    "description": "IAT修复 IAT修复有双层循环，第一层循环是判断还有没有dll文件，第二层循环是判断dll内的函数到没到头。\n导入表的访问从IMAGE_DATA_DIRECTORY结构开始\npehdr.peNtHdr-\u003eOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]\n在pe的基地址加上这个IMAGE_DATA_DIRECTORY的VA，访问到第一个PIMAGE_IMPORT_DESCRIPTOR结构\nIMAGE_IMPORT_DESCRIPTOR 结构体布局\n| 偏移 | 字段名称 | 类型 | 大小(字节) | 说明 |\n|——|———-|——|————|——|\n| 0x00 | OriginalFirstThunk | DWORD | 4 | 指向 INT (导入名称表) 的 RVA |\n| 0x04 | TimeDateStamp | DWORD | 4 | 时间戳，0表示未绑定 |\n| 0x08 | ForwarderChain | DWORD | 4 | 转发链信息 |\n| 0x0C | Name | DWORD | 4 | 指向 DLL 名称字符串的 RVA |",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "导入表修复",
    "uri": "/pe-loader/iat%E4%BF%AE%E5%A4%8D/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  pe loader",
    "content": "Fix Protection PE 文件中的每个节区（Section）在 IMAGE_SECTION_HEADER 中通过 Characteristics 字段定义了初始内存保护属性。例如：\nIMAGE_SCN_MEM_EXECUTE (可执行) IMAGE_SCN_MEM_READ (可读) IMAGE_SCN_MEM_WRITE (可写) 内存保护属性转换 将 PE 文件节区的 Characteristics 转换为 Windows 内存保护常量：\nPE 节区属性 内存保护属性 (WinAPI) EXECUTE PAGE_EXECUTE READ PAGE_READONLY READ + EXECUTE PAGE_EXECUTE_READ READ + WRITE PAGE_READWRITE READ + WRITE + EXECUTE PAGE_EXECUTE_READWRITE “由于 IMAGE_SECTION_HEADER.Characteristics 是一个位域（bitfield），它可能同时包含多个标志（flags）。例如，检查 IMAGE_SCN_MEM_READ 标志时，必须使用按位与运算符（\u0026），而不是相等性比较（==）。”\n代码注释：\nBOOL FixMemPermissions(IN ULONG_PTR pPeBaseAddress, IN PIMAGE_NT_HEADERS pImgNtHdrs, IN PIMAGE_SECTION_HEADER pImgSecHdr) { //其中pPeBaseAddress：是使用virtualAlloc分配的PE基地址 //IN PIMAGE_NT_HEADERS pImgNtHdrs：是Headers.NTheaders //IN PIMAGE_SECTION_HEADER pImgSecHdr:是IMAGE_SECTION_HEADER里面的Characteristics for (DWORD i = 0; i \u003c pImgNtHdrs-\u003eFileHeader.NumberOfSections; i++) { DWORD dwProtection = PAGE_NOACCESS; // 默认无访问权限 DWORD dwOldProtection = 0x00; // 跳过无效节 if (!pImgSecHdr[i].SizeOfRawData || !pImgSecHdr[i].VirtualAddress) continue; // 按优先级判断组合 DWORD ch = pImgSecHdr[i].Characteristics; if (ch \u0026 IMAGE_SCN_MEM_EXECUTE) { if ((ch \u0026 IMAGE_SCN_MEM_WRITE) \u0026\u0026 (ch \u0026 IMAGE_SCN_MEM_READ)) { dwProtection = PAGE_EXECUTE_READWRITE; } else if (ch \u0026 IMAGE_SCN_MEM_WRITE) { dwProtection = PAGE_EXECUTE_READWRITE; // WRITE 隐含 READ } else if (ch \u0026 IMAGE_SCN_MEM_READ) { dwProtection = PAGE_EXECUTE_READ; } else { dwProtection = PAGE_EXECUTE; } } else { if ((ch \u0026 IMAGE_SCN_MEM_WRITE) \u0026\u0026 (ch \u0026 IMAGE_SCN_MEM_READ)) { dwProtection = PAGE_READWRITE; } else if (ch \u0026 IMAGE_SCN_MEM_WRITE) { dwProtection = PAGE_READWRITE; // WRITE 隐含 READ } else if (ch \u0026 IMAGE_SCN_MEM_READ) { dwProtection = PAGE_READONLY; } } // 应用保护属性 if (!VirtualProtect( (PVOID)(pPeBaseAddress + pImgSecHdr[i].VirtualAddress), pImgSecHdr[i].SizeOfRawData, dwProtection, \u0026dwOldProtection )) { PRINT_WINAPI_ERR(\"VirtualProtect\"); return FALSE; } } return TRUE; } 每个头的应有之权限都储存在SECTION头的character字段中\n通过FIRST_SECTION(NT)访问IMAGE_SECTION_HEADER字段\n接下来就很简单了\nint numOfSec=pNt-\u003eFileHeader.NumberOfSections;//头的数量储存在这里 for(int i=0;i\u003cnumOfSec;i++){//处理每个头 DWORD dwprotction=0;//将要赋予的权限 DWORD oldprotc=0; printf(\"节区%s\\t\",pSec[i].Name); //单一权限判断 if(pSec[i].Characteristics\u0026IMAGE_SCN_MEM_WRITE){ dwprotction=PAGE_WRITECOPY; } if(pSec[i].Characteristics\u0026IMAGE_SCN_MEM_READ){ dwprotction=PAGE_READONLY; } if(pSec[i].Characteristics\u0026IMAGE_SCN_MEM_EXECUTE){ dwprotction=PAGE_EXECUTE; } //双重权限判断 if((pSec[i].Characteristics\u0026IMAGE_SCN_MEM_WRITE)\u0026\u0026 (pSec[i].Characteristics\u0026IMAGE_SCN_MEM_READ)){ dwprotction=PAGE_READWRITE; } if((pSec[i].Characteristics\u0026IMAGE_SCN_MEM_WRITE)\u0026\u0026 (pSec[i].Characteristics\u0026IMAGE_SCN_MEM_EXECUTE)){ dwprotction=PAGE_EXECUTE_WRITECOPY; } if((pSec[i].Characteristics\u0026IMAGE_SCN_MEM_READ)\u0026\u0026 (pSec[i].Characteristics\u0026IMAGE_SCN_MEM_EXECUTE)){ dwprotction=PAGE_EXECUTE_READ; } //全部权限 if((pSec[i].Characteristics\u0026IMAGE_SCN_MEM_READ)\u0026\u0026 (pSec[i].Characteristics\u0026IMAGE_SCN_MEM_EXECUTE)\u0026\u0026 (pSec[i].Characteristics\u0026IMAGE_SCN_MEM_WRITE)){ dwprotction=PAGE_EXECUTE_READWRITE; } printf(\"新保护：0x%08x\\n\",dwprotction); //通过VirtualProtect赋予新权限 if(!VirtualProtect(peBase+pSec[i].VirtualAddress, //这里当VirtualSize为0时才使用硬盘大小 pSec[i].Misc.VirtualSize?pSec[i].Misc.VirtualSize:pSec[i].SizeOfRawData, dwprotction, \u0026oldprotc)){ printf(\"VirtualProtect error:0x%08x\\n\",GetLastError()); return FALSE; } } return TRUE;",
    "description": "Fix Protection PE 文件中的每个节区（Section）在 IMAGE_SECTION_HEADER 中通过 Characteristics 字段定义了初始内存保护属性。例如：\nIMAGE_SCN_MEM_EXECUTE (可执行) IMAGE_SCN_MEM_READ (可读) IMAGE_SCN_MEM_WRITE (可写) 内存保护属性转换 将 PE 文件节区的 Characteristics 转换为 Windows 内存保护常量：\nPE 节区属性 内存保护属性 (WinAPI) EXECUTE PAGE_EXECUTE READ PAGE_READONLY READ + EXECUTE PAGE_EXECUTE_READ READ + WRITE PAGE_READWRITE READ + WRITE + EXECUTE PAGE_EXECUTE_READWRITE “由于 IMAGE_SECTION_HEADER.Characteristics 是一个位域（bitfield），它可能同时包含多个标志（flags）。例如，检查 IMAGE_SCN_MEM_READ 标志时，必须使用按位与运算符（\u0026），而不是相等性比较（==）。”\n代码注释：\nBOOL FixMemPermissions(IN ULONG_PTR pPeBaseAddress, IN PIMAGE_NT_HEADERS pImgNtHdrs, IN PIMAGE_SECTION_HEADER pImgSecHdr) { //其中pPeBaseAddress：是使用virtualAlloc分配的PE基地址 //IN PIMAGE_NT_HEADERS pImgNtHdrs：是Headers.NTheaders //IN PIMAGE_SECTION_HEADER pImgSecHdr:是IMAGE_SECTION_HEADER里面的Characteristics for (DWORD i = 0; i \u003c pImgNtHdrs-\u003eFileHeader.",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "节区权限处理",
    "uri": "/pe-loader/%E6%9D%83%E9%99%90%E4%BF%AE%E5%A4%8D/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: BloodyStealer",
    "uri": "/tags/bloodystealer/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  病毒源码分析 \u003e  Predator The Thief源码分析",
    "content": "这是Predator The Thief病毒源码中浏览器密码提取的单独部分，两部分示例代码分别使用python和c语言编写，仅支持edge，Google chrome，以及chrome内核的其他浏览器\n浏览器密码提取 流程图与原理说明 本文档解释浏览器密码提取工具的工作原理和流程。\ngithub\n工作流程图 flowchart TD A[开始] --\u003e B[获取浏览器信息] B --\u003e C{浏览器文件存在?} C --\u003e|否| D[报错: 文件不存在] C --\u003e|是| E[读取加密主密钥] E --\u003e F{主密钥获取成功?} F --\u003e|否| G[报错: 主密钥获取失败] F --\u003e|是| H[复制数据库到临时文件] H --\u003e I[连接SQLite数据库] I --\u003e J[查询密码记录] J --\u003e K[遍历每条密码记录] K --\u003e L{密码格式是v10?} L --\u003e|是| M[使用AES-GCM解密] L --\u003e|否| N[使用DPAPI解密] M --\u003e O[显示解密结果] N --\u003e O O --\u003e P{还有更多记录?} P --\u003e|是| K P --\u003e|否| Q[显示统计信息] Q --\u003e R[结束] 密码解密原理 现代浏览器采用两级加密策略来保护存储的密码：\n主密钥获取 浏览器在Local State文件中存储加密的主密钥 主密钥使用Windows DPAPI (Data Protection API)加密 使用CryptUnprotectData函数解密主密钥 密码解密 v10格式 (Chrome/Edge最新格式) 格式: v10 + IV(12字节) + 加密数据 + 认证标签(16字节) 使用AES-GCM算法和主密钥解密 旧格式 直接使用DPAPI (CryptUnprotectData)解密 实现细节 浏览器密码存储位置 Chrome: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data Edge: %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data 主密钥存储位置 Chrome: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State Edge: %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Local State 密码数据库 SQLite格式 包含URL、用户名和加密密码 查询: SELECT origin_url, username_value, password_value FROM logins 安全注意事项 本工具仅用于教育目的。未经授权访问他人密码数据可能违反法律法规。使用本工具时请遵守相关法律和道德准则。",
    "description": "这是Predator The Thief病毒源码中浏览器密码提取的单独部分，两部分示例代码分别使用python和c语言编写，仅支持edge，Google chrome，以及chrome内核的其他浏览器\n浏览器密码提取 流程图与原理说明 本文档解释浏览器密码提取工具的工作原理和流程。\ngithub\n工作流程图 flowchart TD A[开始] --\u003e B[获取浏览器信息] B --\u003e C{浏览器文件存在?} C --\u003e|否| D[报错: 文件不存在] C --\u003e|是| E[读取加密主密钥] E --\u003e F{主密钥获取成功?} F --\u003e|否| G[报错: 主密钥获取失败] F --\u003e|是| H[复制数据库到临时文件] H --\u003e I[连接SQLite数据库] I --\u003e J[查询密码记录] J --\u003e K[遍历每条密码记录] K --\u003e L{密码格式是v10?} L --\u003e|是| M[使用AES-GCM解密] L --\u003e|否| N[使用DPAPI解密] M --\u003e O[显示解密结果] N --\u003e O O --\u003e P{还有更多记录?} P --\u003e|是| K P --\u003e|否| Q[显示统计信息] Q --\u003e R[结束] 密码解密原理 现代浏览器采用两级加密策略来保护存储的密码：",
    "tags": [
      "病毒",
      "源代码",
      "分析",
      "Windows",
      "BloodyStealer",
      "Source Code"
    ],
    "title": "predator the thief浏览器密码提取",
    "uri": "/%E7%97%85%E6%AF%92%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90/predator-the-thief/browser-decipher/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  病毒源码分析",
    "content": "浏览器密码提取\n病毒源码分析报告",
    "description": "浏览器密码提取\n病毒源码分析报告",
    "tags": [
      "病毒",
      "源代码",
      "分析",
      "Windows",
      "BloodyStealer",
      "Source Code"
    ],
    "title": "Predator The Thief源码分析",
    "uri": "/%E7%97%85%E6%AF%92%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90/predator-the-thief/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: Source Code",
    "uri": "/tags/source-code/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tags",
    "uri": "/tags/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: Windows",
    "uri": "/tags/windows/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: 分析",
    "uri": "/tags/%E5%88%86%E6%9E%90/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: 源代码",
    "uri": "/tags/%E6%BA%90%E4%BB%A3%E7%A0%81/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: 病毒",
    "uri": "/tags/%E7%97%85%E6%AF%92/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  病毒源码分析",
    "content": "恶意软件分析报告 - BloodyStealer 重整化病毒代码github 原始代码github(反编译输出) 1. 概述 这份分析报告基于对一个名为BloodyStealer的恶意软件样本的逆向工程分析。该恶意软件主要设计用于从受感染系统中窃取各种敏感信息，包括浏览器凭据、游戏平台账户信息、即时通讯工具数据以及其他敏感文件。代码经过大量混淆处理，但通过分析，我们可以确定其主要功能和工作原理。\n2. 代码结构分析 2.1 主程序结构 恶意软件的主要功能在Program.cs文件的Main方法中实现，该方法负责协调整个恶意软件的运行流程：\n防重复执行机制：\n生成一个基于系统特征的唯一标识符 检查特定目录是否存在标记文件，如存在则退出 执行完毕后在随机选择的目录创建标记文件 反分析技术：\n反虚拟机检测(Anti.VT.Core.Execute()) 反逆向工程技术(Anti.Reverse.Core.Execute()) 检测独联体(CIS)国家，如果用户位于这些国家则退出 多线程数据收集：\n浏览器数据收集线程(Application.Grabber.Browsers.Core.Execute()) 应用程序数据收集线程(Application.Grabber.Applications.Core.Execute()) 文件数据收集线程(Files.Execute()) 数据处理与发送：\n处理收集的数据，去除重复项 收集系统信息和屏幕截图 创建ZIP归档文件 将数据发送到远程服务器 2.2 混淆特征 代码显示出明显的混淆特征，这表明它已经过反混淆处理:\n无意义的命名：\n类名使用格式如c0000b4、delegate0c9等无语义命名 方法名使用格式如f000094、m000001等序列名称 字符串加密：\n使用c0000c0.m00000f(\"ýn*\\rÈ\\u001a\")等形式的加密字符串 所有明文字符串都被替换为加密形式 控制流混淆：\n使用如delegate0da.f0000d7(-3)的数值来控制执行流程 复杂的switch语句和goto标签结构 无限循环和条件跳转的非结构化组合 委托调用：\n使用委托字段而非直接方法调用，如delegate0c9.f000094 方法与实现分离，增加跟踪难度 3. 功能分析 3.1 数据收集目标 恶意软件针对以下数据类型进行收集：\n浏览器数据：\n保存的密码 (Chromium_Edited.Passwords) Cookies (Chromium_Edited.Cookies和Firefox_Edited.Cookies) 自动填充表单数据 (Chromium_Edited.Forms) 保存的信用卡信息 (Chromium_Edited.Cards) 应用程序账户数据：\nTelegram聊天工具 游戏平台: EpicGames、GOG、Origin、Steam、VimeWorld 文件共享: uTorrent 系统信息：\n用户名 IP地址和地理位置信息 屏幕截图 特定类型的用户文件 3.2 传输机制 收集的数据通过以下方式传输：\n将所有收集的信息打包成ZIP文件 使用基于国家和IP地址的命名格式 通过Sender.Execute方法发送至远程服务器 使用TLS协议进行安全传输 3.3 规避技术 该恶意软件采用多种技术来规避检测：\n反虚拟机检测：检测是否在虚拟环境中运行 反调试/反分析：检测调试器和分析工具 独联体国家规避：避开特定地区，可能是开发者所在地区 一次性执行：使用标记文件防止重复感染 代码混淆：使代码难以分析和理解 4. 技术细节 4.1 主要类和方法 Program类：\nMain：主入口点，协调整个恶意软件行为 NormalizeResults：处理收集的数据，去除重复和无效项 内部类c000007：包含三个数据收集线程方法 核心执行方法：\nApplication.Grabber.Browsers.Core.Execute()：收集浏览器数据 Application.Grabber.Applications.Core.Execute()：收集应用程序数据 Files.Execute()：收集文件数据 辅助功能：\nSystem.Screenshot()：捕获屏幕截图 System.Geo()：获取地理位置信息 System.UserName()：获取用户名 System.Other()：获取其他系统信息 4.2 混淆技术分析 代码混淆在该样本中广泛存在，主要表现为：\n对象引用混淆：\ndelegate0c9.f000094(array2[i]); // 可能是Thread.Start()方法 控制流混淆：\nint num = delegate0da.f0000d7(-3); // 状态机控制 字符串加密：\nc0000c0.m00000f(\"ýn*\\rÈ\\u001a\") // 加密的字符串常量 根据分析，该混淆可能使用了ConfuserEx或其变种工具，这从命名模式delegate0xx和控制流混淆特征可以推断。\n4.3 防护措施 该恶意软件采取多种措施防止被分析或在特定环境中执行：\n地理位置检测：\nif (Settings.AntiCis \u0026\u0026 Settings.CisCountries.Where(new Func\u003cstring, bool\u003e(c.m000004)).Count\u003cstring\u003e() \u003e 0) { delegate0d3.f0000c4(null); // 如果在CIS国家，则退出 } 防重复执行：\n// 在特定目录创建标记文件 delegate0d9.f0000d5(delegate0d1.f0000bd(new string[] { text2, c0000c0.m00000f(\"Í\"), text6, c0000c0.m00000f(\"Í\"), text })); 5. 恶意行为评估 基于代码分析，该恶意软件主要具有以下恶意特征：\n信息窃取：从多个来源广泛收集用户敏感信息 隐蔽通信：使用加密通信发送窃取的数据 反分析技术：采用多种技术规避检测和分析 持久性：通过标记文件确保执行但不重复感染 有针对性：避开特定地理区域，表明有特定目标 这些特征表明该恶意软件是一个专业设计的信息窃取工具，可能是用于有针对性的攻击或商业间谍活动。\n6. 混淆技术分析 6.1 代码标记 代码中存在大量类似以下的标记：\n// Token: 0x040003E2 RID: 994 internal static delegate0c9 f000094; 这些不是原始代码中的注释，而是反编译工具(如ILSpy或dnSpy)生成的元数据标记。它们提供了关于反编译过程的额外信息：\nToken: 0x040003E2：.NET元数据中的唯一标识符 RID: 994：在元数据表中的行号 这些标记证实了代码是通过反编译获得的，而非原始源代码。\n6.2 推断的混淆器 基于代码特征，特别是命名模式和控制流混淆方式，该样本很可能使用了以下混淆工具之一：\nConfuserEx：最可能的候选，其特征与样本高度匹配 Eazfuscator.NET：也可能被使用 SmartAssembly：较低可能性 自定义混淆工具：不能排除 7. 总结与建议 BloodyStealer是一个复杂的信息窃取恶意软件，设计用于收集和窃取用户敏感数据。它采用先进的混淆技术和反分析措施，表明其开发者具有相当的技术能力。\n防护建议 保持安全软件更新：确保防病毒和防恶意软件解决方案是最新的 网络监控：监控异常网络流量和连接 用户教育：提高对社会工程学攻击的警惕性 多因素认证：对敏感账户启用多因素认证 定期备份：保持数据备份，以防受到攻击 研究建议 深入分析文件组成：检查其他组件文件的功能 监控网络通信：分析数据传输目的地和协议 动态分析：在受控环境中执行样本以观察实际行为 IOC提取：提取可用于检测的指标 8. 附录：代码关键部分 主要执行流程 private static void Main() { // 创建程序上下文对象 Program.c000007 c = new Program.c000007(); // 防重复运行检查... // 反虚拟机/沙盒检测 if (Settings.AntiVT) { Application.Anti.VT.Core.Execute(); } // 反逆向工程检测 if (Settings.AntiReverse) { Application.Anti.Reverse.Core.Execute(); } // 多线程数据收集 Thread[] array = new Thread[] { new Thread(new ThreadStart(c.m000001)), // 浏览器数据收集线程 new Thread(new ThreadStart(c.m000002)), // 应用程序数据收集线程 new Thread(new ThreadStart(c.m000003)) // 文件数据收集线程 }; // 启动和等待线程... // 处理数据并发送... // 创建标记文件防止再次运行 } 数据收集线程 // 浏览器数据收集 internal void m000001() { this.results.AddRange(Application.Grabber.Browsers.Core.Execute()); } // 应用程序数据收集 internal void m000002() { this.results.AddRange(Application.Grabber.Applications.Core.Execute()); } // 文件数据收集 internal void m000003() { this.results.AddRange(Files.Execute()); } 反CIS国家检测 // 如果启用了反CIS国家功能，且当前地理位置在CIS国家列表中，则退出程序 if (Settings.AntiCis \u0026\u0026 Settings.CisCountries.Where(new Func\u003cstring, bool\u003e(c.m000004)).Count\u003cstring\u003e() \u003e 0) { delegate0d3.f0000c4(null); }",
    "description": "恶意软件分析报告 - BloodyStealer 重整化病毒代码github 原始代码github(反编译输出) 1. 概述 这份分析报告基于对一个名为BloodyStealer的恶意软件样本的逆向工程分析。该恶意软件主要设计用于从受感染系统中窃取各种敏感信息，包括浏览器凭据、游戏平台账户信息、即时通讯工具数据以及其他敏感文件。代码经过大量混淆处理，但通过分析，我们可以确定其主要功能和工作原理。\n2. 代码结构分析 2.1 主程序结构 恶意软件的主要功能在Program.cs文件的Main方法中实现，该方法负责协调整个恶意软件的运行流程：\n防重复执行机制：\n生成一个基于系统特征的唯一标识符 检查特定目录是否存在标记文件，如存在则退出 执行完毕后在随机选择的目录创建标记文件 反分析技术：\n反虚拟机检测(Anti.VT.Core.Execute()) 反逆向工程技术(Anti.Reverse.Core.Execute()) 检测独联体(CIS)国家，如果用户位于这些国家则退出 多线程数据收集：\n浏览器数据收集线程(Application.Grabber.Browsers.Core.Execute()) 应用程序数据收集线程(Application.Grabber.Applications.Core.Execute()) 文件数据收集线程(Files.Execute()) 数据处理与发送：\n处理收集的数据，去除重复项 收集系统信息和屏幕截图 创建ZIP归档文件 将数据发送到远程服务器 2.2 混淆特征 代码显示出明显的混淆特征，这表明它已经过反混淆处理:\n无意义的命名：\n类名使用格式如c0000b4、delegate0c9等无语义命名 方法名使用格式如f000094、m000001等序列名称 字符串加密：\n使用c0000c0.m00000f(\"ýn*\\rÈ\\u001a\")等形式的加密字符串 所有明文字符串都被替换为加密形式 控制流混淆：\n使用如delegate0da.f0000d7(-3)的数值来控制执行流程 复杂的switch语句和goto标签结构 无限循环和条件跳转的非结构化组合 委托调用：\n使用委托字段而非直接方法调用，如delegate0c9.f000094 方法与实现分离，增加跟踪难度 3. 功能分析 3.1 数据收集目标 恶意软件针对以下数据类型进行收集：\n浏览器数据：\n保存的密码 (Chromium_Edited.Passwords) Cookies (Chromium_Edited.Cookies和Firefox_Edited.Cookies) 自动填充表单数据 (Chromium_Edited.Forms) 保存的信用卡信息 (Chromium_Edited.Cards) 应用程序账户数据：\nTelegram聊天工具 游戏平台: EpicGames、GOG、Origin、Steam、VimeWorld 文件共享: uTorrent 系统信息：\n用户名 IP地址和地理位置信息 屏幕截图 特定类型的用户文件 3.",
    "tags": [
      "病毒",
      "源代码",
      "分析",
      "Windows",
      "BloodyStealer",
      "Source Code"
    ],
    "title": "BloodyStealer源码分析",
    "uri": "/%E7%97%85%E6%AF%92%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90/bloodystealer/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff",
    "content": "Blood Stealer病毒源码分析\nPredator The Thief源码分析",
    "description": "Blood Stealer病毒源码分析\nPredator The Thief源码分析",
    "tags": [
      "病毒",
      "源代码",
      "分析",
      "Windows"
    ],
    "title": "病毒源码分析",
    "uri": "/%E7%97%85%E6%AF%92%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: Windows系统",
    "uri": "/tags/windows%E7%B3%BB%E7%BB%9F/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: 病毒分析",
    "uri": "/tags/%E7%97%85%E6%AF%92%E5%88%86%E6%9E%90/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: 逆向工程",
    "uri": "/tags/%E9%80%86%E5%90%91%E5%B7%A5%E7%A8%8B/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  reflective DLL injection",
    "content": "peb结构获取dll地址\n源码地址： https://github.com/harry-hard/blog-dev_code/tree/main/PEB\nPBYTE getDllAddress(wchar_t* dllName) { //通过PEB结构获取dll地址 PPEB pPeb = __readgsqword(0x60); PPEB_LDR_DATA ldr = pPeb-\u003eLdr; PLIST_ENTRY head = \u0026ldr-\u003eInMemoryOrderModuleList; PLIST_ENTRY flink = head-\u003eFlink; PBYTE kernel32dllAddr = NULL; while (flink != head) { PLDR_DATA_TABLE_ENTRY entry = (ULONG_PTR)flink - LDR_OFFSET; //AI写的 PWSTR filename = wcsrchr(entry-\u003eFullDllName.Buffer, L'\\\\'); filename = filename ? filename + 1 : entry-\u003eFullDllName.Buffer; //AI结束 if (_wcsicmp(filename, dllName) == 0) { kernel32dllAddr = entry-\u003eDllBase; break; } else flink = flink-\u003eFlink; } if (!kernel32dllAddr) { printf(\"Failed to find kernel32.dll\\n\"); return (PVOID)0; } return kernel32dllAddr; } graph TD A[开始] --\u003e B[获取PEB地址] B --\u003e C[访问PEB_LDR_DATA] C --\u003e D[定位模块链表头部] D --\u003e E[遍历链表节点] E --\u003e F{是否链表头?} F --\u003e|是| Z[结束遍历] F --\u003e|否| G[计算LDR_DATA_TABLE_ENTRY地址] G --\u003e H[提取DLL文件名] H --\u003e I{文件名匹配?} I --\u003e|是| J[记录DLL基地址] J --\u003e K[跳出循环] I --\u003e|否| L[移动到下一个节点] K --\u003e Z L --\u003e E Z --\u003e M{找到基地址?} M --\u003e|是| N[返回基地址] M --\u003e|否| O[输出错误信息] O --\u003e P[返回空指针] classDef startEnd fill:#90EE90,stroke:#4CAF50; classDef process fill:#E3F2FD,stroke:#2196F3; classDef decision fill:#FFF3E0,stroke:#FF9800; classDef error fill:#FFEBEE,stroke:#F44336; class A,Z,N,P startEnd; class B,C,D,E,G,H,J,L process; class F,I,M decision; class O error; style A stroke-width:2px style N stroke-width:2px style P stroke-width:2px 遍历dll导出表获取函数地址：\nPBYTE getFuncAddress(const char* funcName,PBYTE kernel32dllAddr) { //根据获取到的dll寻找函数导出表 PIMAGE_DOS_HEADER imgPe = (PIMAGE_DOS_HEADER)kernel32dllAddr; PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(kernel32dllAddr + imgPe-\u003ee_lfanew); //PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt); /*IMAGE_OPTIONAL_HEADER opt = nt-\u003eOptionalHeader;*/ PIMAGE_DATA_DIRECTORY dataDir = \u0026nt-\u003eOptionalHeader.DataDirectory[0]; PIMAGE_EXPORT_DIRECTORY exp = kernel32dllAddr + dataDir-\u003eVirtualAddress; PDWORD nameFunc = kernel32dllAddr + exp-\u003eAddressOfNames; PDWORD addrFunc = kernel32dllAddr + exp-\u003eAddressOfFunctions; PWORD ordinals = kernel32dllAddr + exp-\u003eAddressOfNameOrdinals; for (int i = 0; i \u003c exp-\u003eNumberOfNames; i++) { DWORD name_rva = nameFunc[i]; if (name_rva == 0 || name_rva \u003e= nt-\u003eOptionalHeader.SizeOfImage) { printf(\"Invalid RVA: 0x%08X\\n\", name_rva); continue; } if (strcmp(funcName, kernel32dllAddr + (DWORD)nameFunc[i]) == 0) { return kernel32dllAddr + (DWORD)addrFunc[ordinals[i]]; } } } graph TD subgraph 模块遍历流程 Start([开始]) --\u003e A[获取PEB地址] A --\u003e B[访问PEB-\u003eLdr] B --\u003e C[定位链表头部] C --\u003e D[初始化遍历指针] D --\u003e E{当前节点≠头部?} E --\u003e|是| F[计算LDR_DATA入口] F --\u003e G[提取DLL文件名] G --\u003e H{名称匹配?} H --\u003e|是| I[记录基地址] H --\u003e|否| J[移动下一节点] I --\u003e K[终止循环] J --\u003e E E --\u003e|否| L[结束遍历] L --\u003e M{基地址有效?} M --\u003e|是| N([返回基地址]) M --\u003e|否| O[输出错误信息] O --\u003e P([返回空指针]) end classDef startEnd fill:#C8E6C9,stroke:#4CAF50,color:#2E7D32; classDef process fill:#E3F2FD,stroke:#2196F3,color:#0D47A1; classDef decision fill:#FFE0B2,stroke:#FF9800,color:#BF360C; classDef error fill:#FFCDD2,stroke:#F44336,color:#B71C1C; class Start,N,P startEnd; class A,B,C,D,F,G process; class E,H,M decision; class O error; style Start stroke-width:2px style N stroke-width:2px style P stroke-width:2px KernelBase.dll与Kernel32.dll中函数的异同：\n其中要获取LoadLibraryA()函数地址，在win11 x64操作系统中，已无法通过kernel32.dll获取其函数地址，而是要通过KernelBase.dll，以下是windbg的验证：\n输入：\nx kernel32!LoadLibraryA 无返回结果，\n输入：\nx kernelbase!LoadLibraryA 查看kernelbase中LoadLibraryA的地址，输出为：\n和代码输出一致\n在x64dbg中观察到的现象为：\nkernel32.dll中的LoadLibrary地址和代码获取的一致，反汇编此代码所在位置：\n可以看到直接跳转到了kernelBase的LoadLibraryA的地址。\n在此出现的LoadLibraryA的地址也和代码返回一致\n可以得出结论：\nkernel32.dll 中的 LoadLibraryA 是转发存根（Forwarder Stub），实际代码在 kernelbase.dll 中。",
    "description": "peb结构获取dll地址\n源码地址： https://github.com/harry-hard/blog-dev_code/tree/main/PEB\nPBYTE getDllAddress(wchar_t* dllName) { //通过PEB结构获取dll地址 PPEB pPeb = __readgsqword(0x60); PPEB_LDR_DATA ldr = pPeb-\u003eLdr; PLIST_ENTRY head = \u0026ldr-\u003eInMemoryOrderModuleList; PLIST_ENTRY flink = head-\u003eFlink; PBYTE kernel32dllAddr = NULL; while (flink != head) { PLDR_DATA_TABLE_ENTRY entry = (ULONG_PTR)flink - LDR_OFFSET; //AI写的 PWSTR filename = wcsrchr(entry-\u003eFullDllName.Buffer, L'\\\\'); filename = filename ? filename + 1 : entry-\u003eFullDllName.Buffer; //AI结束 if (_wcsicmp(filename, dllName) == 0) { kernel32dllAddr = entry-\u003eDllBase; break; } else flink = flink-\u003eFlink; } if (!",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "通过PEB和PE导出表获取函数",
    "uri": "/reflectivedllinjection/peb%E5%92%8Cpe%E8%8E%B7%E5%8F%96%E5%87%BD%E6%95%B0%E5%9C%B0%E5%9D%80/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: 《周期》",
    "uri": "/tags/%E5%91%A8%E6%9C%9F/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: 书评",
    "uri": "/tags/%E4%B9%A6%E8%AF%84/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  书评",
    "content": "《周期书评》 很好的书，比较适合刚刚入门股票的小白\n书中主要讲了如何判断我们现在所处的周期位置，我们不可能预测周期，但可以通过现在的市场和政策表现来判断目前市场所处的位置\n本书最主要的内容就是：\n周期永远存在\n周期有很多种，人的心理钟摆会加强周期\n在人们恐惧时贪婪，在人们贪婪时恐惧",
    "description": "《周期书评》 很好的书，比较适合刚刚入门股票的小白\n书中主要讲了如何判断我们现在所处的周期位置，我们不可能预测周期，但可以通过现在的市场和政策表现来判断目前市场所处的位置\n本书最主要的内容就是：\n周期永远存在\n周期有很多种，人的心理钟摆会加强周期\n在人们恐惧时贪婪，在人们贪婪时恐惧",
    "tags": [
      "读书",
      "摘要",
      "投资",
      "书评",
      "《周期》"
    ],
    "title": "周期-霍华德马克思",
    "uri": "/%E4%B9%A6%E8%AF%84/%E5%91%A8%E6%9C%9F-%E9%9C%8D%E5%8D%8E%E5%BE%B7%E9%A9%AC%E5%85%8B%E6%96%AF/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: 投资",
    "uri": "/tags/%E6%8A%95%E8%B5%84/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: 摘要",
    "uri": "/tags/%E6%91%98%E8%A6%81/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: 读书",
    "uri": "/tags/%E8%AF%BB%E4%B9%A6/index.html"
  },
  {
    "breadcrumb": "",
    "content": "欢迎我的朋友 👋 你好！我是 Harry，一名专注于Windows系统恶意软件分析的安全研究员。\n我的研究领域 🔍 恶意软件逆向工程与分析 🛡️ Windows系统漏洞研究 � 病毒行为特征提取 🚫 反病毒规避技术研究 📊 威胁情报分析 常用技术栈 工具集： - IDA Pro - OllyDbg - WinDbg - Wireshark - VirtualBox沙箱环境 编程语言： - C（样本复现） - Python（自动化分析） - PowerShell（系统检测） - Assembly（逆向工程） 最新研究重点 Predator The Thief 恶意病毒(2025/04/20至今)\nPredator The Thief分析\ncheckpoint网站研究\nbloody stealer 信息窃取病毒代码分析(2025/04/19至2025/04/20)\ngithub_code 反射式dll注入(2025/02至2025/04/19)\n反射式dll注入 PE文件加载器(2024-12至2025-02)\nPE Loader",
    "description": "欢迎我的朋友 👋 你好！我是 Harry，一名专注于Windows系统恶意软件分析的安全研究员。\n我的研究领域 🔍 恶意软件逆向工程与分析 🛡️ Windows系统漏洞研究 � 病毒行为特征提取 🚫 反病毒规避技术研究 📊 威胁情报分析 常用技术栈 工具集： - IDA Pro - OllyDbg - WinDbg - Wireshark - VirtualBox沙箱环境 编程语言： - C（样本复现） - Python（自动化分析） - PowerShell（系统检测） - Assembly（逆向工程） 最新研究重点 Predator The Thief 恶意病毒(2025/04/20至今)\nPredator The Thief分析\ncheckpoint网站研究\nbloody stealer 信息窃取病毒代码分析(2025/04/19至2025/04/20)\ngithub_code 反射式dll注入(2025/02至2025/04/19)\n反射式dll注入 PE文件加载器(2024-12至2025-02)\nPE Loader",
    "tags": [
      "安全研究",
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "hacker 0x0ff",
    "uri": "/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff",
    "content": "周期 霍华德·马克斯",
    "description": "周期 霍华德·马克斯",
    "tags": [
      "读书",
      "摘要",
      "投资",
      "书评"
    ],
    "title": "书评",
    "uri": "/%E4%B9%A6%E8%AF%84/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: 安全研究",
    "uri": "/tags/%E5%AE%89%E5%85%A8%E7%A0%94%E7%A9%B6/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: Dll注入",
    "uri": "/tags/dll%E6%B3%A8%E5%85%A5/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff",
    "content": "Local PE Injection 把PE(可执行)文件映射到内存并使之成功执行，和shellcode不一样，shellcode注入简单，PE映射困难(.exe .dll)\nIAT修复\n写入PE至内存\n权限修复\n编译器选择\n重定位表的处理",
    "description": "Local PE Injection 把PE(可执行)文件映射到内存并使之成功执行，和shellcode不一样，shellcode注入简单，PE映射困难(.exe .dll)\nIAT修复\n写入PE至内存\n权限修复\n编译器选择\n重定位表的处理",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "pe loader",
    "uri": "/pe-loader/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff",
    "content": "项目地址 source code: Github-ReflectiveInjection\n函数总览\n导出表获取\n注意事项\nwindbg调试dll\nwindbg查看PEB\n通过PEB和PE获取函数地址",
    "description": "项目地址 source code: Github-ReflectiveInjection\n函数总览\n导出表获取\n注意事项\nwindbg调试dll\nwindbg查看PEB\n通过PEB和PE获取函数地址",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "reflective DLL injection",
    "uri": "/reflectivedllinjection/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  Tags",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Tag :: Windbg",
    "uri": "/tags/windbg/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  reflective DLL injection",
    "content": "对于peb来说，ldr结构体指向的PEB_LDR_DATA结构;\nPEB_LDR_DATA包含InMemoryOrderModuleList\nInMemoryOrderModuleList 是链表的头节点\n#首先更新符号： .reload /f ntdll.dll #查看peb，可以区分是x86还是x64: !peb 虽然是amd64架构，但程序是x86\n（下文InMemoryOrderModuleList和InMemoryOrderLinks不要搞混）\n所以有PEB_LDR_DATA→InMemoryOrderModuleList\nInMemoryOrderModuleList→Flink，\nFlink包含的指针指向LDR_DATA_TABLE_ENTRY\n在LDR_DATA_TABLE_ENTRY 中又有InMemoryOrderLinks （和InMemoryOrderModuleList完全不是一回事，其中InMemoryOrderModuleList 是头节点，而InMemoryOrderLinks 是链表的组成部分）\n**InMemoryOrderModuleList**32位进程中，于PEB_LDR_DATA中的偏移（offset）为0x14,\n64位偏移为0x20;\nInMemoryOrderLinks 32位进程中，在LDR_DATA_TABLE_ENTRY中的偏移为0x08，\n64位偏移为0x10;\nclassDiagram class PEB { +0x00 Ldr : Ptr64 _PEB_LDR_DATA } class PEB_LDR_DATA { +0x00 Length : Uint4B +0x04 Initialized : UChar +0x08 SsHandle : Ptr64 Void +0x10 InLoadOrderModuleList : _LIST_ENTRY (32位偏移: 0x0C) +0x20 InMemoryOrderModuleList : _LIST_ENTRY (32位偏移: 0x14 | 64位偏移: 0x20) +0x30 InInitializationOrderModuleList : _LIST_ENTRY } class LDR_DATA_TABLE_ENTRY { +0x00 InLoadOrderLinks : _LIST_ENTRY (链表节点1) +0x08 InMemoryOrderLinks : _LIST_ENTRY (32位偏移: 0x08 | 64位偏移: 0x10) +0x10 InInitializationOrderLinks : _LIST_ENTRY +0x18 DllBase : Ptr64 Void +0x20 BaseDllName : _UNICODE_STRING } class _LIST_ENTRY { +0x00 Flink : Ptr64 _LIST_ENTRY +0x08 Blink : Ptr64 _LIST_ENTRY } PEB --\u003e PEB_LDR_DATA : Ldr PEB_LDR_DATA --\u003e _LIST_ENTRY : InMemoryOrderModuleList (头节点) _LIST_ENTRY --\u003e LDR_DATA_TABLE_ENTRY : Flink -\u003e InMemoryOrderLinks (链表节点) 1. 结构体层级关系 PEB 包含 Ldr 字段，指向 PEB_LDR_DATA 结构体。 PEB_LDR_DATA 关键成员：InMemoryOrderModuleList（链表头节点）。 偏移量： 32位：+0x14 64位：+0x20 LDR_DATA_TABLE_ENTRY 关键成员：InMemoryOrderLinks（链表节点成员）。 偏移量： 32位：+0x08 64位：+0x10 _LIST_ENTRY 双向链表的节点结构，包含 Flink 和 Blink 指针。",
    "description": "对于peb来说，ldr结构体指向的PEB_LDR_DATA结构;\nPEB_LDR_DATA包含InMemoryOrderModuleList\nInMemoryOrderModuleList 是链表的头节点\n#首先更新符号： .reload /f ntdll.dll #查看peb，可以区分是x86还是x64: !peb 虽然是amd64架构，但程序是x86\n（下文InMemoryOrderModuleList和InMemoryOrderLinks不要搞混）\n所以有PEB_LDR_DATA→InMemoryOrderModuleList\nInMemoryOrderModuleList→Flink，\nFlink包含的指针指向LDR_DATA_TABLE_ENTRY\n在LDR_DATA_TABLE_ENTRY 中又有InMemoryOrderLinks （和InMemoryOrderModuleList完全不是一回事，其中InMemoryOrderModuleList 是头节点，而InMemoryOrderLinks 是链表的组成部分）\n**InMemoryOrderModuleList**32位进程中，于PEB_LDR_DATA中的偏移（offset）为0x14,\n64位偏移为0x20;\nInMemoryOrderLinks 32位进程中，在LDR_DATA_TABLE_ENTRY中的偏移为0x08，\n64位偏移为0x10;\nclassDiagram class PEB { +0x00 Ldr : Ptr64 _PEB_LDR_DATA } class PEB_LDR_DATA { +0x00 Length : Uint4B +0x04 Initialized : UChar +0x08 SsHandle : Ptr64 Void +0x10 InLoadOrderModuleList : _LIST_ENTRY (32位偏移: 0x0C) +0x20 InMemoryOrderModuleList : _LIST_ENTRY (32位偏移: 0x14 | 64位偏移: 0x20) +0x30 InInitializationOrderModuleList : _LIST_ENTRY } class LDR_DATA_TABLE_ENTRY { +0x00 InLoadOrderLinks : _LIST_ENTRY (链表节点1) +0x08 InMemoryOrderLinks : _LIST_ENTRY (32位偏移: 0x08 | 64位偏移: 0x10) +0x10 InInitializationOrderLinks : _LIST_ENTRY +0x18 DllBase : Ptr64 Void +0x20 BaseDllName : _UNICODE_STRING } class _LIST_ENTRY { +0x00 Flink : Ptr64 _LIST_ENTRY +0x08 Blink : Ptr64 _LIST_ENTRY } PEB --\u003e PEB_LDR_DATA : Ldr PEB_LDR_DATA --\u003e _LIST_ENTRY : InMemoryOrderModuleList (头节点) _LIST_ENTRY --\u003e LDR_DATA_TABLE_ENTRY : Flink -\u003e InMemoryOrderLinks (链表节点) 1.",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "windbg访问peb结构",
    "uri": "/reflectivedllinjection/windbg_peb/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  reflective DLL injection",
    "content": "通过windbg调试dll:\n首先要用relese模式编译dll文件，这样pdb调试文件的校验和才会注册\n接下来要在注入器把dll注入到宿主进程之前，windbg附加到宿主进程\n附加到宿主进程后会自动触发断点：\n确保dll目录中有与之匹配的pdb文件\n接下来输入需要加载的符号文件(.pdb)\n.sympath+ C:\\Project\\Debug # 添加DLL的PDB路径（需编译时生成） .reload /f mydll.dll #重新加载要查看的dll的符号文件 重要！\n在注入之前打上在dllmain上断点\nbp myDll!DLLmain 接下来运行程序，\ng 然后执行注入程序\n如果pdb文件正确导入，那么在注入成功的一瞬间，会触发windbg的断点\n调试pe结构：\n# 假设DLL基地址为0x180000000： !dh 0x180000000 # 打印PE头（查找可选头） dt ntdll!_IMAGE_OPTIONAL_HEADER # 查看可选头结构定义 ? 0x180000000 + \u003cImportTable RVA\u003e # 计算导入表实际地址 基地址在processHacker2内可以找到\n!dh 0x你的基地址 会打印头部信息\n如果想要手动查找nt头和可选头，可以使用\n# 读取 e_lfanew 的值（基址 + 0x3C） dd 0x你的基地址 + 0x3C L1 #3C是e_lfanew的固定大小 打印的100是nt头的偏移\n# 基址 + NT Headers偏移 db 0x你的基地址 + 0x100 验证前4个字节是否为 50 45 00 00（nt头固定）\n接下来通过基址+nt偏移+Signature+file header长度\n# 查看 Optional Header 的全部内容（通常长度 0xE0） db 0x你的基质 + 0xnt的偏移 + 0x(Signature+file header长度) L0xE0 如果使用dc会更清楚：\n可以看到.text和.rdata字符",
    "description": "通过windbg调试dll:\n首先要用relese模式编译dll文件，这样pdb调试文件的校验和才会注册\n接下来要在注入器把dll注入到宿主进程之前，windbg附加到宿主进程\n附加到宿主进程后会自动触发断点：\n确保dll目录中有与之匹配的pdb文件\n接下来输入需要加载的符号文件(.pdb)\n.sympath+ C:\\Project\\Debug # 添加DLL的PDB路径（需编译时生成） .reload /f mydll.dll #重新加载要查看的dll的符号文件 重要！\n在注入之前打上在dllmain上断点\nbp myDll!DLLmain 接下来运行程序，\ng 然后执行注入程序\n如果pdb文件正确导入，那么在注入成功的一瞬间，会触发windbg的断点\n调试pe结构：\n# 假设DLL基地址为0x180000000： !dh 0x180000000 # 打印PE头（查找可选头） dt ntdll!_IMAGE_OPTIONAL_HEADER # 查看可选头结构定义 ? 0x180000000 + \u003cImportTable RVA\u003e # 计算导入表实际地址 基地址在processHacker2内可以找到\n!dh 0x你的基地址 会打印头部信息\n如果想要手动查找nt头和可选头，可以使用\n# 读取 e_lfanew 的值（基址 + 0x3C） dd 0x你的基地址 + 0x3C L1 #3C是e_lfanew的固定大小 打印的100是nt头的偏移\n# 基址 + NT Headers偏移 db 0x你的基地址 + 0x100 验证前4个字节是否为 50 45 00 00（nt头固定）",
    "tags": [
      "Windbg",
      "Dll注入",
      "Windows系统",
      "病毒分析"
    ],
    "title": "windbg调试dll",
    "uri": "/reflectivedllinjection/windbg_dll/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  reflective DLL injection",
    "content": "DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader() { // 1. 定位自身 PE 头（略） // 2. 分配内存并复制 PE 头和节区（略） // 3. 处理重定位 ProcessRelocations(memBase, delta); // 4. 解析导入表 ResolveImports(memBase); // 5. 设置内存权限 SetMemoryProtections(memBase); // 6. 调用 DllMain CallDllMain(memBase, DLL_PROCESS_ATTACH); return memBase; }",
    "description": "DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader() { // 1. 定位自身 PE 头（略） // 2. 分配内存并复制 PE 头和节区（略） // 3. 处理重定位 ProcessRelocations(memBase, delta); // 4. 解析导入表 ResolveImports(memBase); // 5. 设置内存权限 SetMemoryProtections(memBase); // 6. 调用 DllMain CallDllMain(memBase, DLL_PROCESS_ATTACH); return memBase; }",
    "tags": [
      "Dll注入",
      "Windows系统",
      "病毒分析"
    ],
    "title": "函数总览",
    "uri": "/reflectivedllinjection/%E5%87%BD%E6%95%B0%E6%80%BB%E8%A7%88/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  pe loader \u003e  导入表修复",
    "content": "IAT dll包含 可以通过IMAGE_IMPORT_DESCRIPTOR访问PE文件中DLL名称，INT，IAT的地址\ntypedef struct _IMAGE_IMPORT_DESCRIPTOR { union { DWORD Characteristics; // 0 表示结构数组的结束 DWORD OriginalFirstThunk; // 指向 INT (Import Name Table) } DUMMYUNIONNAME; DWORD TimeDateStamp; // 时间戳 DWORD ForwarderChain; // 转发链 DWORD Name; // DLL名称的RVA DWORD FirstThunk; // 指向 IAT (Import Address Table) } IMAGE_IMPORT_DESCRIPTOR; // PE文件的导入表可能是这样的： 导入表 ├── Import Descriptor 1 (kernel32.dll) │ ├── Name: \"kernel32.dll\" //DLL的名称 │ ├── OriginalFirstThunk: -\u003e [函数1, 函数2, ...] //INT的RVA │ └── FirstThunk: -\u003e [地址1, 地址2, ...]//IAT的RVA ├── Import Descriptor 2 (user32.dll) │ ├── Name: \"user32.dll\" │ ├── OriginalFirstThunk: -\u003e [函数1, 函数2, ...] │ └── FirstThunk: -\u003e [地址1, 地址2, ...] └── Import Descriptor 3 (NULL 结束标记) 可以通过循环访问IAT导入表的IMAGE_IMPORT_DESCRIPTOR：\nfor (SIZE_T i = 0; i \u003c pEntryImportDataDir-\u003eSize; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) //pEntryImportDataDir-\u003eSize 表示整个导入目录的大小 //这个大小等于所有 IMAGE_IMPORT_DESCRIPTOR 结构的总大小 { //这里是DLL名称 LPSTR\tcDllName\t= (LPSTR)(pPeBaseAddress + pImgDescriptor-\u003eName); //这里是INT ULONG_PTR\tuOriginalFirstThunkRVA\t= pImgDescriptor-\u003eOriginalFirstThunk; //这里是IAT ULONG_PTR\tuFirstThunkRVA\t= pImgDescriptor-\u003eFirstThunk; //这里通过LoadLibraryA获取DLL if (!(hModule = LoadLibraryA(cDllName))) { PRINT_WINAPI_ERR(\"LoadLibraryA\"); return FALSE; } } INT和IAT的关系:\n// INT 包含了函数的名称信息 struct { union { DWORD Name; // 指向函数名称 WORD Ordinal; // 或者函数序号 } u1; } ImportNameTable[]; // IAT 最终会包含函数的实际地址 struct { union { DWORD Function; // 将被替换为函数的实际地址 } u1; } ImportAddressTable[]; INT里又包含一个u1数据结构：\ntypedef struct _IMAGE_THUNK_DATA64 { union { ULONGLONG ForwarderString; // 不使用 ULONGLONG Function; // 函数地址 ULONGLONG Ordinal; // 函数Ordinal ULONGLONG AddressOfData; // RVA to PIMAGE_IMPORT_BY_NAME - used only if the function is imported by name rather by ordinal. } u1; } IMAGE_THUNK_DATA64; 然后再在for循环内部增加一个while循环，获取IMAGE_IMPORT_DESCRIPTOR每个数据结构中的具体地址：\n// 如果是ordinal函数，通过GetProcAddress(dllName,ordinal)获取函数地址 if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk-\u003eu1.Ordinal)) { //pOriginalFirstThunk指向INT里面的u1数据结构 if ( !(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, IMAGE_ORDINAL(pOriginalFirstThunk-\u003eu1.Ordinal))) ) { printf(\"[!] Could Not Import !%s#%d \\n\", cDllName, (int)pOriginalFirstThunk-\u003eu1.Ordinal); return FALSE; } } //通过函数名称获取 else { pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(pPeBaseAddress + pOriginalFirstThunk-\u003eu1.AddressOfData); if ( !(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, pImgImportByName-\u003eName)) ) { printf(\"[!] Could Not Import !%s.%s \\n\", cDllName, pImgImportByName-\u003eName); return FALSE; } } // 最后把函数地址patch到IAT上 pFirstThunk-\u003eu1.Function = (ULONGLONG)pFuncAddress;",
    "description": "IAT dll包含 可以通过IMAGE_IMPORT_DESCRIPTOR访问PE文件中DLL名称，INT，IAT的地址\ntypedef struct _IMAGE_IMPORT_DESCRIPTOR { union { DWORD Characteristics; // 0 表示结构数组的结束 DWORD OriginalFirstThunk; // 指向 INT (Import Name Table) } DUMMYUNIONNAME; DWORD TimeDateStamp; // 时间戳 DWORD ForwarderChain; // 转发链 DWORD Name; // DLL名称的RVA DWORD FirstThunk; // 指向 IAT (Import Address Table) } IMAGE_IMPORT_DESCRIPTOR; // PE文件的导入表可能是这样的： 导入表 ├── Import Descriptor 1 (kernel32.dll) │ ├── Name: \"kernel32.dll\" //DLL的名称 │ ├── OriginalFirstThunk: -\u003e [函数1, 函数2, ...] //INT的RVA │ └── FirstThunk: -\u003e [地址1, 地址2, .",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "更多导入表内容",
    "uri": "/pe-loader/iat%E4%BF%AE%E5%A4%8D/%E6%9B%B4%E5%A4%9A/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  pe loader",
    "content": "编译器选择 在windows系统级编程中，当MinGW编译时，这些关键的系统调用会通过MinGW的包装层：\n// MinGW内部可能的实现过程 VirtualAlloc -\u003e _mingw_VirtualAlloc -\u003e ntdll!NtAllocateVirtualMemory 这导致： 内存分配可能不符合Windows PE加载要求 页面权限设置可能不完全正确 系统调用的参数传递可能有偏差\n更严重的问题 - 加载器本身的内存布局也会因为不是标准windows编译器而改变\n如果一定要用MinGW编译PE加载器，需要：\n避免使用MinGW的API包装层\n直接使用系统调用或ntdll函数\n确保内存对齐和保护属性正确\n手动实现某些Windows内部功能\n避免使用MinGW的API包装层 直接使用系统调用或ntdll函数 确保内存对齐和保护属性正确 手动实现某些Windows内部功能 但说实话，这样做：\n开发难度大大增加\n可能引入新的兼容性问题\n维护成本很高\n开发难度大大增加 可能引入新的兼容性问题 维护成本很高 所以最终建议还是：\n使用MSVC编译PE加载器\n或者使用更底层的方法（如直接系统调用）\n如果一定要用MinGW，需要重写大量底层代码\n使用MSVC编译PE加载器 或者使用更底层的方法（如直接系统调用） 如果一定要用MinGW，需要重写大量底层代码",
    "description": "编译器选择",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "更重要的...",
    "uri": "/pe-loader/%E7%BC%96%E8%AF%91%E5%99%A8%E9%80%89%E6%8B%A9/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  reflective DLL injection",
    "content": "在编写dll部分时，为了方便执行dll，我写了一个程序快速执行dll\nHMODULE dllname = LoadLibraryA(\"dll.dll\"); if (!dllname) { printf(\"dllname don't exitsts!\\n\"); return 0; } ReflectiveLoaderFunc myfuc = (ReflectiveLoaderFunc)GetProcAddress(dllname, \"ReflectiveLoader\"); myfuc(); 然而这样的程序在反射式dll处理重定位表时会出大问题： • 通过 LoadLibrary 加载的DLL已被系统修改（重定位+导入表处理），.reloc 节可能被丢弃或擦写。\n及其重要的一点是不要提前返回，因为反射式注入的dll代码无法及时调试，所以一定要勤用反汇编软件查看内存分配，或在注入器代码中内嵌调试语句。",
    "description": "在编写dll部分时，为了方便执行dll，我写了一个程序快速执行dll\nHMODULE dllname = LoadLibraryA(\"dll.dll\"); if (!dllname) { printf(\"dllname don't exitsts!\\n\"); return 0; } ReflectiveLoaderFunc myfuc = (ReflectiveLoaderFunc)GetProcAddress(dllname, \"ReflectiveLoader\"); myfuc(); 然而这样的程序在反射式dll处理重定位表时会出大问题： • 通过 LoadLibrary 加载的DLL已被系统修改（重定位+导入表处理），.reloc 节可能被丢弃或擦写。\n及其重要的一点是不要提前返回，因为反射式注入的dll代码无法及时调试，所以一定要勤用反汇编软件查看内存分配，或在注入器代码中内嵌调试语句。",
    "tags": [
      "Dll注入",
      "Windows系统",
      "病毒分析"
    ],
    "title": "注意事项1",
    "uri": "/reflectivedllinjection/%E6%B3%A8%E6%84%8F%E4%BA%8B%E9%A1%B9/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  reflective DLL injection",
    "content": "磁盘中的RVA和加载后的RVA访问方式是不同的\n如果已经按内存要求加载：\n基地址+DataDirectory[0]\n如果还是硬盘格式：\n偏移量 = RVA - 区段的VirtualAddress + 区段的PointerToRawData 基地址+偏移量\n这里主要理解内存格式和硬盘格式对RVA的影响",
    "description": "磁盘中的RVA和加载后的RVA访问方式是不同的\n如果已经按内存要求加载：\n基地址+DataDirectory[0]\n如果还是硬盘格式：\n偏移量 = RVA - 区段的VirtualAddress + 区段的PointerToRawData 基地址+偏移量\n这里主要理解内存格式和硬盘格式对RVA的影响",
    "tags": [
      "Dll注入",
      "Windows系统",
      "病毒分析"
    ],
    "title": "获取磁盘dll(未加载)的导出表",
    "uri": "/reflectivedllinjection/%E5%AF%BC%E5%87%BA%E8%A1%A8%E8%8E%B7%E5%8F%96%E7%A3%81%E7%9B%98/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff",
    "content": "",
    "description": "",
    "tags": [],
    "title": "Categories",
    "uri": "/categories/index.html"
  }
]
