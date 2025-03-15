var relearn_searchindex = [
  {
    "breadcrumb": "hacker 0x0ff \u003e  pe loader",
    "content": "",
    "description": "",
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
    "content": "",
    "description": "",
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
    "content": "",
    "description": "",
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
    "content": "",
    "description": "",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "节区权限处理",
    "uri": "/pe-loader/%E6%9D%83%E9%99%90%E4%BF%AE%E5%A4%8D/index.html"
  },
  {
    "breadcrumb": "",
    "content": "欢迎我的朋友 👋 你好！我是 Harry，一名专注于Windows系统恶意软件分析的安全研究员。\n我的研究领域 🔍 恶意软件逆向工程与分析 🛡️ Windows系统漏洞研究 � 病毒行为特征提取 🚫 反病毒规避技术研究 📊 威胁情报分析 常用技术栈 工具集： - IDA Pro - OllyDbg - WinDbg - Wireshark - VirtualBox沙箱环境 编程语言： - C（样本复现） - Python（自动化分析） - PowerShell（系统检测） - Assembly（逆向工程） 最新研究重点 目前正在深入分析以下方向的恶意软件样本：\n反射式dll注入(202502至今) PE文件加载器(2024-12至2025-02)",
    "description": "欢迎我的朋友 👋 你好！我是 Harry，一名专注于Windows系统恶意软件分析的安全研究员。\n我的研究领域 🔍 恶意软件逆向工程与分析 🛡️ Windows系统漏洞研究 � 病毒行为特征提取 🚫 反病毒规避技术研究 📊 威胁情报分析 常用技术栈 工具集： - IDA Pro - OllyDbg - WinDbg - Wireshark - VirtualBox沙箱环境 编程语言： - C（样本复现） - Python（自动化分析） - PowerShell（系统检测） - Assembly（逆向工程） 最新研究重点 目前正在深入分析以下方向的恶意软件样本：\n反射式dll注入(202502至今) PE文件加载器(2024-12至2025-02)",
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
    "title": "Tag :: Windows系统",
    "uri": "/tags/windows%E7%B3%BB%E7%BB%9F/index.html"
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
    "breadcrumb": "hacker 0x0ff",
    "content": "Local PE Injection 把PE(可执行)文件映射到内存并使之成功执行，和shellcode不一样，shellcode注入简单，PE映射困难(.exe .dll)",
    "description": "Local PE Injection 把PE(可执行)文件映射到内存并使之成功执行，和shellcode不一样，shellcode注入简单，PE映射困难(.exe .dll)",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "pe loader",
    "uri": "/pe-loader/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  pe loader \u003e  节区权限处理",
    "content": "Fix Protection PE 文件中的每个节区（Section）在 IMAGE_SECTION_HEADER 中通过 Characteristics 字段定义了初始内存保护属性。例如：\nIMAGE_SCN_MEM_EXECUTE (可执行) IMAGE_SCN_MEM_READ (可读) IMAGE_SCN_MEM_WRITE (可写) 内存保护属性转换 将 PE 文件节区的 Characteristics 转换为 Windows 内存保护常量：\nPE 节区属性 内存保护属性 (WinAPI) EXECUTE PAGE_EXECUTE READ PAGE_READONLY READ + EXECUTE PAGE_EXECUTE_READ READ + WRITE PAGE_READWRITE READ + WRITE + EXECUTE PAGE_EXECUTE_READWRITE “由于 IMAGE_SECTION_HEADER.Characteristics 是一个位域（bitfield），它可能同时包含多个标志（flags）。例如，检查 IMAGE_SCN_MEM_READ 标志时，必须使用按位与运算符（\u0026），而不是相等性比较（==）。”\n代码注释：\nBOOL FixMemPermissions(IN ULONG_PTR pPeBaseAddress, IN PIMAGE_NT_HEADERS pImgNtHdrs, IN PIMAGE_SECTION_HEADER pImgSecHdr) { //其中pPeBaseAddress：是使用virtualAlloc分配的PE基地址 //IN PIMAGE_NT_HEADERS pImgNtHdrs：是Headers.NTheaders //IN PIMAGE_SECTION_HEADER pImgSecHdr:是IMAGE_SECTION_HEADER里面的Characteristics for (DWORD i = 0; i \u003c pImgNtHdrs-\u003eFileHeader.NumberOfSections; i++) { DWORD dwProtection = PAGE_NOACCESS; // 默认无访问权限 DWORD dwOldProtection = 0x00; // 跳过无效节 if (!pImgSecHdr[i].SizeOfRawData || !pImgSecHdr[i].VirtualAddress) continue; // 按优先级判断组合 DWORD ch = pImgSecHdr[i].Characteristics; if (ch \u0026 IMAGE_SCN_MEM_EXECUTE) { if ((ch \u0026 IMAGE_SCN_MEM_WRITE) \u0026\u0026 (ch \u0026 IMAGE_SCN_MEM_READ)) { dwProtection = PAGE_EXECUTE_READWRITE; } else if (ch \u0026 IMAGE_SCN_MEM_WRITE) { dwProtection = PAGE_EXECUTE_READWRITE; // WRITE 隐含 READ } else if (ch \u0026 IMAGE_SCN_MEM_READ) { dwProtection = PAGE_EXECUTE_READ; } else { dwProtection = PAGE_EXECUTE; } } else { if ((ch \u0026 IMAGE_SCN_MEM_WRITE) \u0026\u0026 (ch \u0026 IMAGE_SCN_MEM_READ)) { dwProtection = PAGE_READWRITE; } else if (ch \u0026 IMAGE_SCN_MEM_WRITE) { dwProtection = PAGE_READWRITE; // WRITE 隐含 READ } else if (ch \u0026 IMAGE_SCN_MEM_READ) { dwProtection = PAGE_READONLY; } } // 应用保护属性 if (!VirtualProtect( (PVOID)(pPeBaseAddress + pImgSecHdr[i].VirtualAddress), pImgSecHdr[i].SizeOfRawData, dwProtection, \u0026dwOldProtection )) { PRINT_WINAPI_ERR(\"VirtualProtect\"); return FALSE; } } return TRUE; }",
    "description": "Fix Protection PE 文件中的每个节区（Section）在 IMAGE_SECTION_HEADER 中通过 Characteristics 字段定义了初始内存保护属性。例如：\nIMAGE_SCN_MEM_EXECUTE (可执行) IMAGE_SCN_MEM_READ (可读) IMAGE_SCN_MEM_WRITE (可写) 内存保护属性转换 将 PE 文件节区的 Characteristics 转换为 Windows 内存保护常量：\nPE 节区属性 内存保护属性 (WinAPI) EXECUTE PAGE_EXECUTE READ PAGE_READONLY READ + EXECUTE PAGE_EXECUTE_READ READ + WRITE PAGE_READWRITE READ + WRITE + EXECUTE PAGE_EXECUTE_READWRITE “由于 IMAGE_SECTION_HEADER.Characteristics 是一个位域（bitfield），它可能同时包含多个标志（flags）。例如，检查 IMAGE_SCN_MEM_READ 标志时，必须使用按位与运算符（\u0026），而不是相等性比较（==）。”\n代码注释：\nBOOL FixMemPermissions(IN ULONG_PTR pPeBaseAddress, IN PIMAGE_NT_HEADERS pImgNtHdrs, IN PIMAGE_SECTION_HEADER pImgSecHdr) { //其中pPeBaseAddress：是使用virtualAlloc分配的PE基地址 //IN PIMAGE_NT_HEADERS pImgNtHdrs：是Headers.NTheaders //IN PIMAGE_SECTION_HEADER pImgSecHdr:是IMAGE_SECTION_HEADER里面的Characteristics for (DWORD i = 0; i \u003c pImgNtHdrs-\u003eFileHeader.",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "pe节区权限的修复",
    "uri": "/pe-loader/%E6%9D%83%E9%99%90%E4%BF%AE%E5%A4%8D/fix-protection/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  pe loader \u003e  节区权限处理",
    "content": "内存保护权限修复 每个头的应有之权限都储存在SECTION头的character字段中\n通过FIRST_SECTION(NT)访问IMAGE_SECTION_HEADER字段\n接下来就很简单了\nint numOfSec=pNt-\u003eFileHeader.NumberOfSections;//头的数量储存在这里 for(int i=0;i\u003cnumOfSec;i++){//处理每个头 DWORD dwprotction=0;//将要赋予的权限 DWORD oldprotc=0; printf(\"节区%s\\t\",pSec[i].Name); //单一权限判断 if(pSec[i].Characteristics\u0026IMAGE_SCN_MEM_WRITE){ dwprotction=PAGE_WRITECOPY; } if(pSec[i].Characteristics\u0026IMAGE_SCN_MEM_READ){ dwprotction=PAGE_READONLY; } if(pSec[i].Characteristics\u0026IMAGE_SCN_MEM_EXECUTE){ dwprotction=PAGE_EXECUTE; } //双重权限判断 if((pSec[i].Characteristics\u0026IMAGE_SCN_MEM_WRITE)\u0026\u0026 (pSec[i].Characteristics\u0026IMAGE_SCN_MEM_READ)){ dwprotction=PAGE_READWRITE; } if((pSec[i].Characteristics\u0026IMAGE_SCN_MEM_WRITE)\u0026\u0026 (pSec[i].Characteristics\u0026IMAGE_SCN_MEM_EXECUTE)){ dwprotction=PAGE_EXECUTE_WRITECOPY; } if((pSec[i].Characteristics\u0026IMAGE_SCN_MEM_READ)\u0026\u0026 (pSec[i].Characteristics\u0026IMAGE_SCN_MEM_EXECUTE)){ dwprotction=PAGE_EXECUTE_READ; } //全部权限 if((pSec[i].Characteristics\u0026IMAGE_SCN_MEM_READ)\u0026\u0026 (pSec[i].Characteristics\u0026IMAGE_SCN_MEM_EXECUTE)\u0026\u0026 (pSec[i].Characteristics\u0026IMAGE_SCN_MEM_WRITE)){ dwprotction=PAGE_EXECUTE_READWRITE; } printf(\"新保护：0x%08x\\n\",dwprotction); //通过VirtualProtect赋予新权限 if(!VirtualProtect(peBase+pSec[i].VirtualAddress, //这里当VirtualSize为0时才使用硬盘大小 pSec[i].Misc.VirtualSize?pSec[i].Misc.VirtualSize:pSec[i].SizeOfRawData, dwprotction, \u0026oldprotc)){ printf(\"VirtualProtect error:0x%08x\\n\",GetLastError()); return FALSE; } } return TRUE;",
    "description": "内存保护权限修复 每个头的应有之权限都储存在SECTION头的character字段中\n通过FIRST_SECTION(NT)访问IMAGE_SECTION_HEADER字段\n接下来就很简单了\nint numOfSec=pNt-\u003eFileHeader.NumberOfSections;//头的数量储存在这里 for(int i=0;i\u003cnumOfSec;i++){//处理每个头 DWORD dwprotction=0;//将要赋予的权限 DWORD oldprotc=0; printf(\"节区%s\\t\",pSec[i].Name); //单一权限判断 if(pSec[i].Characteristics\u0026IMAGE_SCN_MEM_WRITE){ dwprotction=PAGE_WRITECOPY; } if(pSec[i].Characteristics\u0026IMAGE_SCN_MEM_READ){ dwprotction=PAGE_READONLY; } if(pSec[i].Characteristics\u0026IMAGE_SCN_MEM_EXECUTE){ dwprotction=PAGE_EXECUTE; } //双重权限判断 if((pSec[i].Characteristics\u0026IMAGE_SCN_MEM_WRITE)\u0026\u0026 (pSec[i].Characteristics\u0026IMAGE_SCN_MEM_READ)){ dwprotction=PAGE_READWRITE; } if((pSec[i].Characteristics\u0026IMAGE_SCN_MEM_WRITE)\u0026\u0026 (pSec[i].Characteristics\u0026IMAGE_SCN_MEM_EXECUTE)){ dwprotction=PAGE_EXECUTE_WRITECOPY; } if((pSec[i].Characteristics\u0026IMAGE_SCN_MEM_READ)\u0026\u0026 (pSec[i].Characteristics\u0026IMAGE_SCN_MEM_EXECUTE)){ dwprotction=PAGE_EXECUTE_READ; } //全部权限 if((pSec[i].Characteristics\u0026IMAGE_SCN_MEM_READ)\u0026\u0026 (pSec[i].Characteristics\u0026IMAGE_SCN_MEM_EXECUTE)\u0026\u0026 (pSec[i].Characteristics\u0026IMAGE_SCN_MEM_WRITE)){ dwprotction=PAGE_EXECUTE_READWRITE; } printf(\"新保护：0x%08x\\n\",dwprotction); //通过VirtualProtect赋予新权限 if(!VirtualProtect(peBase+pSec[i].VirtualAddress, //这里当VirtualSize为0时才使用硬盘大小 pSec[i].Misc.VirtualSize?pSec[i].Misc.VirtualSize:pSec[i].SizeOfRawData, dwprotction, \u0026oldprotc)){ printf(\"VirtualProtect error:0x%08x\\n\",GetLastError()); return FALSE; } } return TRUE;",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "pe节区权限的修复",
    "uri": "/pe-loader/%E6%9D%83%E9%99%90%E4%BF%AE%E5%A4%8D/%E5%86%85%E5%AD%98%E4%BF%9D%E6%8A%A4%E6%9D%83%E9%99%90%E4%BF%AE%E5%A4%8D/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  pe loader \u003e  导入表修复",
    "content": "IAT修复 IAT修复有双层循环，第一层循环是判断还有没有dll文件，第二层循环是判断dll内的函数到没到头。\n导入表的访问从IMAGE_DATA_DIRECTORY结构开始\npehdr.peNtHdr-\u003eOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]\n在pe的基地址加上这个IMAGE_DATA_DIRECTORY的VA，访问到第一个PIMAGE_IMPORT_DESCRIPTOR结构\nIMAGE_IMPORT_DESCRIPTOR 结构体布局\n| 偏移 | 字段名称 | 类型 | 大小(字节) | 说明 |\n|——|———-|——|————|——|\n| 0x00 | OriginalFirstThunk | DWORD | 4 | 指向 INT (导入名称表) 的 RVA |\n| 0x04 | TimeDateStamp | DWORD | 4 | 时间戳，0表示未绑定 |\n| 0x08 | ForwarderChain | DWORD | 4 | 转发链信息 |\n| 0x0C | Name | DWORD | 4 | 指向 DLL 名称字符串的 RVA |\n| 0x10 | FirstThunk | DWORD | 4 | 指向 IAT (导入地址表) 的 RVA |\n第一层循环就是PIMAGE_IMPORT_DESCRIPTOR→name≠0时\nIMAGE_IMPORT_DESCRIPTOR 这个结构体里面可以获取OriginalFirstThunk 和FirstThunk 的RVA\n加载dll，用LoadLibraryA加载base+PIMAGE_IMPORT_DESCRIPTOR→name\nOriginalFirstThunk 和FirstThunk 都是PIMAGE_THUNK_DATA结构\n这俩都通过基地址加上RVA获得\n其中OriginalFirstThunk 是不变的，专门保存函数的名字和信息\nFirstThunk 是应该改变的，pe文件加载后变成FirstThunk.function变成实际地址\n所以通过OriginalFirstThunk 访问u1联合体，\nIMAGE_SNAP_BY_ORDINAL(OriginalFirstThunk .u1.ordinal)宏判断是否用ordinal获取函数地址\n如果不是，就用OriginalFirstThunk .u1.AddressOfData\n值得注意的是，为了获取dll里全部应该获取的函数，需要在这一层循环中每次获取OriginalFirstThunk 和FirstThunk时加上一个他们的大小，以跳到下一个OriginalFirstThunk 和FirstThunk。\n最后在最外出循环PIMAGE_IMPORT_DESCRIPTOR自增，跳到下一个PIMAGE_IMPORT_DESCRIPTOR获取dll。",
    "description": "IAT修复 IAT修复有双层循环，第一层循环是判断还有没有dll文件，第二层循环是判断dll内的函数到没到头。\n导入表的访问从IMAGE_DATA_DIRECTORY结构开始\npehdr.peNtHdr-\u003eOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]\n在pe的基地址加上这个IMAGE_DATA_DIRECTORY的VA，访问到第一个PIMAGE_IMPORT_DESCRIPTOR结构\nIMAGE_IMPORT_DESCRIPTOR 结构体布局\n| 偏移 | 字段名称 | 类型 | 大小(字节) | 说明 |\n|——|———-|——|————|——|\n| 0x00 | OriginalFirstThunk | DWORD | 4 | 指向 INT (导入名称表) 的 RVA |\n| 0x04 | TimeDateStamp | DWORD | 4 | 时间戳，0表示未绑定 |\n| 0x08 | ForwarderChain | DWORD | 4 | 转发链信息 |\n| 0x0C | Name | DWORD | 4 | 指向 DLL 名称字符串的 RVA |",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "修复Import Address Table",
    "uri": "/pe-loader/iat%E4%BF%AE%E5%A4%8D/iat%E4%BF%AE%E5%A4%8D/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  pe loader \u003e  导入表修复 \u003e  更多导入表内容",
    "content": "IAT dll包含 可以通过IMAGE_IMPORT_DESCRIPTOR访问PE文件中DLL名称，INT，IAT的地址\ntypedef struct _IMAGE_IMPORT_DESCRIPTOR { union { DWORD Characteristics; // 0 表示结构数组的结束 DWORD OriginalFirstThunk; // 指向 INT (Import Name Table) } DUMMYUNIONNAME; DWORD TimeDateStamp; // 时间戳 DWORD ForwarderChain; // 转发链 DWORD Name; // DLL名称的RVA DWORD FirstThunk; // 指向 IAT (Import Address Table) } IMAGE_IMPORT_DESCRIPTOR; // PE文件的导入表可能是这样的： 导入表 ├── Import Descriptor 1 (kernel32.dll) │ ├── Name: \"kernel32.dll\" //DLL的名称 │ ├── OriginalFirstThunk: -\u003e [函数1, 函数2, ...] //INT的RVA │ └── FirstThunk: -\u003e [地址1, 地址2, ...]//IAT的RVA ├── Import Descriptor 2 (user32.dll) │ ├── Name: \"user32.dll\" │ ├── OriginalFirstThunk: -\u003e [函数1, 函数2, ...] │ └── FirstThunk: -\u003e [地址1, 地址2, ...] └── Import Descriptor 3 (NULL 结束标记) 可以通过循环访问IAT导入表的IMAGE_IMPORT_DESCRIPTOR：\nfor (SIZE_T i = 0; i \u003c pEntryImportDataDir-\u003eSize; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) //pEntryImportDataDir-\u003eSize 表示整个导入目录的大小 //这个大小等于所有 IMAGE_IMPORT_DESCRIPTOR 结构的总大小 { //这里是DLL名称 LPSTR\tcDllName\t= (LPSTR)(pPeBaseAddress + pImgDescriptor-\u003eName); //这里是INT ULONG_PTR\tuOriginalFirstThunkRVA\t= pImgDescriptor-\u003eOriginalFirstThunk; //这里是IAT ULONG_PTR\tuFirstThunkRVA\t= pImgDescriptor-\u003eFirstThunk; //这里通过LoadLibraryA获取DLL if (!(hModule = LoadLibraryA(cDllName))) { PRINT_WINAPI_ERR(\"LoadLibraryA\"); return FALSE; } } INT和IAT的关系:\n// INT 包含了函数的名称信息 struct { union { DWORD Name; // 指向函数名称 WORD Ordinal; // 或者函数序号 } u1; } ImportNameTable[]; // IAT 最终会包含函数的实际地址 struct { union { DWORD Function; // 将被替换为函数的实际地址 } u1; } ImportAddressTable[]; INT里又包含一个u1数据结构：\ntypedef struct _IMAGE_THUNK_DATA64 { union { ULONGLONG ForwarderString; // 不使用 ULONGLONG Function; // 函数地址 ULONGLONG Ordinal; // 函数Ordinal ULONGLONG AddressOfData; // RVA to PIMAGE_IMPORT_BY_NAME - used only if the function is imported by name rather by ordinal. } u1; } IMAGE_THUNK_DATA64; 然后再在for循环内部增加一个while循环，获取IMAGE_IMPORT_DESCRIPTOR每个数据结构中的具体地址：\n// 如果是ordinal函数，通过GetProcAddress(dllName,ordinal)获取函数地址 if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk-\u003eu1.Ordinal)) { //pOriginalFirstThunk指向INT里面的u1数据结构 if ( !(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, IMAGE_ORDINAL(pOriginalFirstThunk-\u003eu1.Ordinal))) ) { printf(\"[!] Could Not Import !%s#%d \\n\", cDllName, (int)pOriginalFirstThunk-\u003eu1.Ordinal); return FALSE; } } //通过函数名称获取 else { pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(pPeBaseAddress + pOriginalFirstThunk-\u003eu1.AddressOfData); if ( !(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, pImgImportByName-\u003eName)) ) { printf(\"[!] Could Not Import !%s.%s \\n\", cDllName, pImgImportByName-\u003eName); return FALSE; } } // 最后把函数地址patch到IAT上 pFirstThunk-\u003eu1.Function = (ULONGLONG)pFuncAddress;",
    "description": "IAT dll包含 可以通过IMAGE_IMPORT_DESCRIPTOR访问PE文件中DLL名称，INT，IAT的地址\ntypedef struct _IMAGE_IMPORT_DESCRIPTOR { union { DWORD Characteristics; // 0 表示结构数组的结束 DWORD OriginalFirstThunk; // 指向 INT (Import Name Table) } DUMMYUNIONNAME; DWORD TimeDateStamp; // 时间戳 DWORD ForwarderChain; // 转发链 DWORD Name; // DLL名称的RVA DWORD FirstThunk; // 指向 IAT (Import Address Table) } IMAGE_IMPORT_DESCRIPTOR; // PE文件的导入表可能是这样的： 导入表 ├── Import Descriptor 1 (kernel32.dll) │ ├── Name: \"kernel32.dll\" //DLL的名称 │ ├── OriginalFirstThunk: -\u003e [函数1, 函数2, ...] //INT的RVA │ └── FirstThunk: -\u003e [地址1, 地址2, .",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "关于IAT",
    "uri": "/pe-loader/iat%E4%BF%AE%E5%A4%8D/%E6%9B%B4%E5%A4%9A/%E5%85%B3%E4%BA%8Eiat/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  pe loader \u003e  1.将硬盘上的PE文件写入内存",
    "content": "1.从硬盘映射PE到内存 从硬盘直接读取的PE文件头名为**RawData。**\nPointerToRawData 字段记录的是该节在 PE 文件中的起始偏移量（以字节为单位）。也就是说，通过这个偏移量，我们可以在磁盘上的 PE 文件中准确找到该节的原始数据。\n所以通过以下代码可以将硬盘中的pe文件放到内存中的pe结构中，模拟了windows从硬盘加载PE文件的过程：\n// 给PE文件分配内存 if ((pPeBaseAddress = VirtualAlloc(NULL, pPeHdrs-\u003epImgNtHdrs-\u003eOptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) == NULL) { PRINT_WINAPI_ERR(\"VirtualAlloc\"); return FALSE; } // Copying PE headers - IOC // memcpy(pPeBaseAddress, pPeHdrs-\u003epFileBuffer, pPeHdrs-\u003epImgNtHdrs-\u003eOptionalHeader.SizeOfHeaders); for (int i = 0; i \u003c pPeHdrs-\u003epImgNtHdrs-\u003eFileHeader.NumberOfSections; i++) { memcpy( (PVOID)(pPeBaseAddress + pPeHdrs-\u003epImgSecHdr[i].VirtualAddress),//目的地址：内存地址+RVA (PVOID)((ULONG_PTR)pPeHdrs-\u003epFileBuffer + pPeHdrs-\u003epImgSecHdr[i].PointerToRawData),//源地址：硬盘地址+RVA pPeHdrs-\u003epImgSecHdr[i].SizeOfRawData ); }",
    "description": "1.从硬盘映射PE到内存 从硬盘直接读取的PE文件头名为**RawData。**\nPointerToRawData 字段记录的是该节在 PE 文件中的起始偏移量（以字节为单位）。也就是说，通过这个偏移量，我们可以在磁盘上的 PE 文件中准确找到该节的原始数据。\n所以通过以下代码可以将硬盘中的pe文件放到内存中的pe结构中，模拟了windows从硬盘加载PE文件的过程：\n// 给PE文件分配内存 if ((pPeBaseAddress = VirtualAlloc(NULL, pPeHdrs-\u003epImgNtHdrs-\u003eOptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) == NULL) { PRINT_WINAPI_ERR(\"VirtualAlloc\"); return FALSE; } // Copying PE headers - IOC // memcpy(pPeBaseAddress, pPeHdrs-\u003epFileBuffer, pPeHdrs-\u003epImgNtHdrs-\u003eOptionalHeader.SizeOfHeaders); for (int i = 0; i \u003c pPeHdrs-\u003epImgNtHdrs-\u003eFileHeader.NumberOfSections; i++) { memcpy( (PVOID)(pPeBaseAddress + pPeHdrs-\u003epImgSecHdr[i].VirtualAddress),//目的地址：内存地址+RVA (PVOID)((ULONG_PTR)pPeHdrs-\u003epFileBuffer + pPeHdrs-\u003epImgSecHdr[i].PointerToRawData),//源地址：硬盘地址+RVA pPeHdrs-\u003epImgSecHdr[i].SizeOfRawData ); }",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "写入pe至内存中",
    "uri": "/pe-loader/%E5%86%99%E5%85%A5pe%E8%87%B3%E5%86%85%E5%AD%98/1-%E4%BB%8E%E7%A1%AC%E7%9B%98%E6%98%A0%E5%B0%84pe%E5%88%B0%E5%86%85%E5%AD%98/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  pe loader \u003e  导入表修复",
    "content": "",
    "description": "",
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
    "content": "",
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
    "breadcrumb": "hacker 0x0ff \u003e  pe loader \u003e  更重要的...",
    "content": "编译器选择 在windows系统级编程中，当MinGW编译时，这些关键的系统调用会通过MinGW的包装层：\n// MinGW内部可能的实现过程 VirtualAlloc -\u003e _mingw_VirtualAlloc -\u003e ntdll!NtAllocateVirtualMemory 这导致： 内存分配可能不符合Windows PE加载要求 页面权限设置可能不完全正确 系统调用的参数传递可能有偏差\n更严重的问题 - 加载器本身的内存布局也会因为不是标准windows编译器而改变\n如果一定要用MinGW编译PE加载器，需要：\n避免使用MinGW的API包装层\n直接使用系统调用或ntdll函数\n确保内存对齐和保护属性正确\n手动实现某些Windows内部功能\n避免使用MinGW的API包装层 直接使用系统调用或ntdll函数 确保内存对齐和保护属性正确 手动实现某些Windows内部功能 但说实话，这样做：\n开发难度大大增加\n可能引入新的兼容性问题\n维护成本很高\n开发难度大大增加 可能引入新的兼容性问题 维护成本很高 所以最终建议还是：\n使用MSVC编译PE加载器\n或者使用更底层的方法（如直接系统调用）\n如果一定要用MinGW，需要重写大量底层代码\n使用MSVC编译PE加载器 或者使用更底层的方法（如直接系统调用） 如果一定要用MinGW，需要重写大量底层代码",
    "description": "编译器选择",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "最重要的是编译器",
    "uri": "/pe-loader/%E7%BC%96%E8%AF%91%E5%99%A8%E9%80%89%E6%8B%A9/%E7%BC%96%E8%AF%91%E5%99%A8%E9%80%89%E6%8B%A9/index.html"
  },
  {
    "breadcrumb": "hacker 0x0ff \u003e  pe loader \u003e  重定位的处理",
    "content": "2.重定位PE文件的重定位块和重定位项 当可执行映像加载到的地址与其首选基地址（IMAGE_OPTIONAL_HEADER.ImageBase）不同时，重定位对于调整可执行映像中的硬编码地址是必要的。在大多数情况下，PE 文件会被映射到除 IMAGE_OPTIONAL_HEADER.ImageBase 之外的地址，因此需要对 PE 文件中的某些硬编码地址进行调整。 通过计算得出地址差值：\n// The difference between the current PE image base address and its preferable base address. ULONG_PTR uDeltaOffset = pPeBaseAddress - pPreferableAddress; 下面是微软SDK定义的重定位块的头部结构\ntypedef struct _IMAGE_BASE_RELOCATION { DWORD VirtualAddress; DWORD SizeOfBlock; } IMAGE_BASE_RELOCATION; 并没有对BASE_RELOCATION_ENTRY做出定义，但描述为：\n每个重定位条目占用2字节(WORD)\n每个重定位条目占用2字节(WORD) 高4位是类型(Type) 低12位是偏移量(Offset) 代码具体实现可以是：\ntypedef struct _BASE_RELOCATION_ENTRY { WORD\tOffset\t: 12; //前12字节 WORD\tType\t: 4; //后4字节 //WORD总共占16位 } BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY; IMAGE_BASE_RELOCATION和BASE_RELOCATION_ENTRY在PE文件中的位置关系是：\n+——————————–+——————+——————+— | IMAGE_BASE_RELOCATION (8字节) | 重定位条目1 | 重定位条目2 | … | - VirtualAddress (4字节) | (2字节) | (2字节) | | - SizeOfBlock (4字节) | | | +—————————————-+—————-+———–+— ↑ ↑ pImgBaseRelocation pImgBaseRelocation + 1\n于是可以通过以下代码访问BASE_RELOCATION_ENTRY：\npBaseRelocEntry = (PBASE_RELOCATION_ENTRY)(pImgBaseRelocation + 1); 并通过下列switch语句根据预定义Type改变重定位地址：\nswitch (pBaseRelocEntry-\u003eType) { case IMAGE_REL_BASED_DIR64: // Adjust a 64-bit field by the delta offset. *((ULONG_PTR*)(pPeBaseAddress + pImgBaseRelocation-\u003eVirtualAddress + pBaseRelocEntry-\u003eOffset)) += uDeltaOffset; break; case IMAGE_REL_BASED_HIGHLOW: // Adjust a 32-bit field by the delta offset. *((DWORD*)(pPeBaseAddress + pImgBaseRelocation-\u003eVirtualAddress + pBaseRelocEntry-\u003eOffset)) += (DWORD)uDeltaOffset; break; case IMAGE_REL_BASED_HIGH: // Adjust the high 16 bits of a 32-bit field. *((WORD*)(pPeBaseAddress + pImgBaseRelocation-\u003eVirtualAddress + pBaseRelocEntry-\u003eOffset)) += HIWORD(uDeltaOffset); break; case IMAGE_REL_BASED_LOW: // Adjust the low 16 bits of a 32-bit field. *((WORD*)(pPeBaseAddress + pImgBaseRelocation-\u003eVirtualAddress + pBaseRelocEntry-\u003eOffset)) += LOWORD(uDeltaOffset); break; case IMAGE_REL_BASED_ABSOLUTE: // No relocation is required. break; default: // Handle unknown relocation types. printf(\"[!] Unknown relocation type: %d | Offset: 0x%08X \\n\", pBaseRelocEntry-\u003eType, pBaseRelocEntry-\u003eOffset); return FALSE; } 总结就是：\nPE（Portable Executable）文件的重定位块是为了解决PE文件在加载到内存时，实际加载地址与首选加载地址不一致的问题。当文件不能被加载到其首选基地址（IMAGE_OPTIONAL_HEADER.ImageBase）时，就需要对文件中硬编码的地址进行调整，这些调整信息就存储在重定位块中。以下详细介绍重定位块的结构和包含的信息：\n重定位表的整体布局 重定位信息存储在.reloc节中，重定位表由多个重定位块（Base Relocation Block）组成。每个重定位块描述一个4KB（4096字节）的内存页面。\n重定位块的结构 1. 重定位块头部（IMAGE_BASE_RELOCATION 结构） 每个重定位块以 IMAGE_BASE_RELOCATION 结构开头，该结构定义在 Windows 头文件中，其结构如下：\ntypedef struct _IMAGE_BASE_RELOCATION { DWORD VirtualAddress; // RVA to the base address of the section this block describes. DWORD SizeOfBlock; // The total size of the block, including the block header and all entries (discussed below). } IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION; VirtualAddress：这是一个相对虚拟地址（RVA），表示该重定位块所描述的内存页面的起始地址。也就是说，这个 RVA 指向需要进行重定位操作的内存页面的基地址。 SizeOfBlock：表示整个重定位块的大小，包括块头部（IMAGE_BASE_RELOCATION 结构本身）和后续的所有重定位条目（BASE_RELOCATION_ENTRY 结构数组）。通过这个值可以确定该重定位块在内存中占用的字节数，从而可以正确遍历块内的所有重定位条目。 2. 重定位条目（BASE_RELOCATION_ENTRY 结构数组） 重定位块头部之后紧跟着一个 BASE_RELOCATION_ENTRY 结构数组，每个结构代表一个重定位条目。BASE_RELOCATION_ENTRY 结构定义如下：\ntypedef struct _BASE_RELOCATION_ENTRY { WORD Offset : 12; // Specifies where the base relocation is to be applied. WORD Type : 4; // Indicates the type of base relocation to be applied. } BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY; Offset：占用 12 位，指定了从当前重定位块的 VirtualAddress 开始的偏移量。通过这个偏移量，可以确定需要进行重定位操作的具体内存位置。例如，如果 VirtualAddress 是某个页面的起始地址，Offset 则表示在这个页面内需要调整地址的具体偏移位置。 Type：占用 4 位，指示了要应用的基址重定位类型。不同的重定位类型决定了如何对相应的地址进行调整。常见的重定位类型如下： IMAGE_REL_BASED_DIR64：用于 64 位地址的重定位，需要将整个 64 位的地址加上基地址的偏移量。 IMAGE_REL_BASED_HIGHLOW：用于 32 位地址的重定位，将 32 位地址加上基地址偏移量的低 32 位。 IMAGE_REL_BASED_HIGH：用于调整 32 位地址的高 16 位，只需要加上基地址偏移量的高 16 位。 IMAGE_REL_BASED_LOW：用于调整 32 位地址的低 16 位，只需要加上基地址偏移量的低 16 位。 IMAGE_REL_BASED_ABSOLUTE：表示该条目不需要进行重定位，通常用于占位或预留。 重定位块的遍历过程 在进行重定位操作时，需要遍历所有的重定位块和每个块内的重定位条目。大致的遍历过程如下：\n从重定位表的起始位置开始，获取第一个重定位块的头部（IMAGE_BASE_RELOCATION 结构）。 根据 VirtualAddress 和 SizeOfBlock 信息，确定该重定位块所描述的页面和块的大小。 从块头部之后开始，依次读取每个 BASE_RELOCATION_ENTRY 结构，根据 Type 字段确定重定位类型，根据 Offset 字段确定要调整的具体内存位置，然后进行相应的地址调整。 当遍历完当前重定位块内的所有条目后，根据 SizeOfBlock 移动到下一个重定位块的头部，重复上述步骤，直到所有重定位块都被处理完毕。 通过这种方式，可以确保 PE 文件在加载到任意内存地址时，其内部的硬编码地址都能被正确调整，从而保证程序的正常运行。",
    "description": "2.重定位PE文件的重定位块和重定位项 当可执行映像加载到的地址与其首选基地址（IMAGE_OPTIONAL_HEADER.ImageBase）不同时，重定位对于调整可执行映像中的硬编码地址是必要的。在大多数情况下，PE 文件会被映射到除 IMAGE_OPTIONAL_HEADER.ImageBase 之外的地址，因此需要对 PE 文件中的某些硬编码地址进行调整。 通过计算得出地址差值：\n// The difference between the current PE image base address and its preferable base address. ULONG_PTR uDeltaOffset = pPeBaseAddress - pPreferableAddress; 下面是微软SDK定义的重定位块的头部结构\ntypedef struct _IMAGE_BASE_RELOCATION { DWORD VirtualAddress; DWORD SizeOfBlock; } IMAGE_BASE_RELOCATION; 并没有对BASE_RELOCATION_ENTRY做出定义，但描述为：\n每个重定位条目占用2字节(WORD)\n每个重定位条目占用2字节(WORD) 高4位是类型(Type) 低12位是偏移量(Offset) 代码具体实现可以是：\ntypedef struct _BASE_RELOCATION_ENTRY { WORD\tOffset\t: 12; //前12字节 WORD\tType\t: 4; //后4字节 //WORD总共占16位 } BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY; IMAGE_BASE_RELOCATION和BASE_RELOCATION_ENTRY在PE文件中的位置关系是：\n+——————————–+——————+——————+— | IMAGE_BASE_RELOCATION (8字节) | 重定位条目1 | 重定位条目2 | … | - VirtualAddress (4字节) | (2字节) | (2字节) | | - SizeOfBlock (4字节) | | | +—————————————-+—————-+———–+— ↑ ↑ pImgBaseRelocation pImgBaseRelocation + 1",
    "tags": [
      "逆向工程",
      "Windows系统",
      "病毒分析"
    ],
    "title": "重定位表处理",
    "uri": "/pe-loader/%E9%87%8D%E5%AE%9A%E4%BD%8D%E8%A1%A8%E7%9A%84%E5%A4%84%E7%90%86/2-%E9%87%8D%E5%AE%9A%E4%BD%8Dpe%E6%96%87%E4%BB%B6%E7%9A%84%E9%87%8D%E5%AE%9A%E4%BD%8D%E5%9D%97%E5%92%8C%E9%87%8D%E5%AE%9A%E4%BD%8D%E9%A1%B9/index.html"
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
