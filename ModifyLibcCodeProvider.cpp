#include "ModifyLibcCodeProvider.h"
#include "BinaryEditor.h"
#include "KSEngine.h"
#include "CSEngine.h"
#include "Config.h"

void ModifyLibcCodeProvider::getCode(uint64_t virtualAddress, std::vector<uint8_t> & allcode)
{
	uint64_t offset = 0;
	std::vector<uint8_t> findLibcBase;

	getLibcbaseAtStart(virtualAddress, findLibcBase);
	
	offset += findLibcBase.size();
	allcode.insert(allcode.end(), findLibcBase.begin(), findLibcBase.end());

	if (Config::instance()->isProviderActionEnabled(ModifyLibcCodeProvider::name(), "setNoBufStdout"))
	{
		std::cout << "++ setNoBufStdout" << std::endl;
		std::vector<uint8_t> setnobuf;
		setNoBufStdout(virtualAddress + offset, setnobuf);
		offset += setnobuf.size();
		allcode.insert(allcode.end(), setnobuf.begin(), setnobuf.end());
	}

	if (Config::instance()->isProviderActionEnabled(ModifyLibcCodeProvider::name(), "modifyGlobalMaxFast"))
	{
		std::cout << "++ modifyGlobalMaxFast" << std::endl;
		std::vector<uint8_t> modifyGMF;
		modifyGlobalMaxFast(virtualAddress + offset, modifyGMF);
		offset += modifyGMF.size();
		allcode.insert(allcode.end(), modifyGMF.begin(), modifyGMF.end());
	}

	if (Config::instance()->isProviderActionEnabled(ModifyLibcCodeProvider::name(), "closeTcache"))
	{
		std::cout << "++ closeTcache" << std::endl;
		std::vector<uint8_t> closeTca;
		closeTcache(virtualAddress + offset, closeTca);
		offset += closeTca.size();
		allcode.insert(allcode.end(), closeTca.begin(), closeTca.end());
	}

	if (Config::instance()->isProviderActionEnabled(ModifyLibcCodeProvider::name(), "nopbinsh"))
	{
		std::cout << "++ nopbinsh" << std::endl;
		std::vector<uint8_t> code;
		nopbinsh(virtualAddress + offset, code);
		offset += code.size();
		allcode.insert(allcode.end(), code.begin(), code.end());
	}
}

//返回寻找libc基址的代码，IMAGE基址放在rbp/ebp中，start的代码都是将rbp/ebp清零而没有使用，比较安全
//注意调用之前要保存所有寄存器
//这段代码应用使用call调用，使用ret进行结尾
void ModifyLibcCodeProvider::getLibcbaseAtStart(uint64_t virtualAddress, std::vector<uint8_t> & allcode)
{
	bool isX64 = BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS64;
	bool ispie = BinaryEditor::instance()->isPIE();
	bool isBindNow = BinaryEditor::instance()->isBindNow();
	const std::string & libc_start_main_offset = Config::instance()->getLibcAttrString("__libc_start_main");

	if (isBindNow)//立即加载模式，这种最简单，可以直接拿到libcbase
	{
		Relocation * reloc = BinaryEditor::instance()->getRelocation("__libc_start_main");
		if (reloc == nullptr)
		{
			std::cerr << "__libc_start_main GOT entry not found." << std::endl;
			throw 1;
		}

		if (isX64)
		{
			if (ispie)//pie情况下基址放到rdx中，得到GOT表地址
			{
				std::string insn = "add rbp, " + std::to_string(reloc->address());
				insn += ";mov rbp, [rbp]";
				insn += ";sub rbp,";
				insn += libc_start_main_offset;
				std::vector<uint8_t> getGotEntryAddrCode;
				KSEngine::instance()->assemble(insn.c_str(), 0, getGotEntryAddrCode);
				if (getGotEntryAddrCode.empty())
				{
					throw 1;
				}
				allcode.insert(allcode.end(), getGotEntryAddrCode.begin(), getGotEntryAddrCode.end());
			}
			else
			{
				std::string insn = "mov rbp, " + std::to_string(reloc->address());
				insn += ";mov rbp,[rbp]";
				insn += ";sub rbp,";
				insn += libc_start_main_offset;
				std::vector<uint8_t> getGotEntryAddrCode;
				KSEngine::instance()->assemble(insn.c_str(), 0, getGotEntryAddrCode);
				if (getGotEntryAddrCode.empty())
				{
					throw 1;
				}
				allcode.insert(allcode.end(), getGotEntryAddrCode.begin(), getGotEntryAddrCode.end());
			}
		}
		else
		{
			if (ispie)
			{
				std::string insn = "add ebp, " + std::to_string(reloc->address());
				insn += ";mov ebp, [ebp]";
				insn += ";sub ebp,";
				insn += libc_start_main_offset;
				std::vector<uint8_t> getGotEntryAddrCode;
				KSEngine::instance()->assemble(insn.c_str(), 0, getGotEntryAddrCode);
				if (getGotEntryAddrCode.empty())
				{
					throw 1;
				}
				allcode.insert(allcode.end(), getGotEntryAddrCode.begin(), getGotEntryAddrCode.end());
			}
			else
			{
				std::string insn = "mov ebp, " + std::to_string(reloc->address());
				insn += ";mov ebp,[ebp]";
				insn += ";sub ebp,";
				insn += libc_start_main_offset;
				std::vector<uint8_t> getGotEntryAddrCode;
				KSEngine::instance()->assemble(insn.c_str(), 0, getGotEntryAddrCode);
				if (getGotEntryAddrCode.empty())
				{
					throw 1;
				}
				allcode.insert(allcode.end(), getGotEntryAddrCode.begin(), getGotEntryAddrCode.end());
			}
		}
	}
	else
	{
		Section sect;
		if (!BinaryEditor::instance()->getGOTPLTSection(sect))
		{
			std::cout << "Section .got.plt not found." << std::endl;
			throw 1;
		}
		//非立即加载模式，要通过ld.so中的got[0]的_dl_runtime_resolve通过got[1]中linkmap查找定位
		if (isX64)
		{
			uint64_t linkmap = sect.virtual_address() + 8; //GOT[1]
			if (ispie)//pie情况下要先获取基址，才能得到linkmap地址
			{
				//sub rax, 偏移常量 得到IMAGEBASE
				//add rax, got[1]偏移量
				std::string insn = "mov r8, rbp";
				insn += ";add r8, " + std::to_string(linkmap);
				std::vector<uint8_t> getLinkMakpCode;
				KSEngine::instance()->assemble(insn.c_str(), 0, getLinkMakpCode);
				if (getLinkMakpCode.empty())
				{
					throw 1;
				}
				allcode.insert(allcode.end(), getLinkMakpCode.begin(), getLinkMakpCode.end());
			}
			else
			{
				//非PIE，直接获取到的就是linkmap地址
				std::string insn = "mov r8, " + std::to_string(linkmap);
				std::vector<uint8_t> getLinkMakpCode;
				KSEngine::instance()->assemble(insn.c_str(), 0, getLinkMakpCode);
				if (getLinkMakpCode.empty())
				{
					throw 1;
				}
				allcode.insert(allcode.end(), getLinkMakpCode.begin(), getLinkMakpCode.end());
			}

			std::vector<uint8_t> findLibcbaseCode = {
				//0x49, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, //mov     r8, 1122334455667788h linkmap地址放入r8
				0x48, 0x8D, 0x7C, 0x24, 0xE8, //lea     rdi, [rsp+var_18]
				0x90, //NOP
				//loc_2B0:
				0x49, 0x8B, 0x50, 0x08, //mov     rdx, [r8+8]
				0x48, 0xB8, 0x6C, 0x69, 0x62, 0x63, 0x2E, 0x73, 0x6F, 0x2E, //mov     rax, 2E6F732E6362696Ch libc.so.6
				0x48, 0x89, 0x44, 0x24, 0xE8, //mov     [rsp+var_18], rax
				0xB8, 0x36, 0x00, 0x00, 0x00, //mov     eax, 36h
				0x66, 0x89, 0x44, 0x24, 0xF0, //mov     [rsp+var_10], ax
				0x48, 0x89, 0xD0, //mov     rax, rdx
				//loc_2D0:
				0x48, 0x83, 0xC0, 0x01, //add     rax, 1
				0x80, 0x78, 0xFF, 0x00, //cmp     byte ptr [rax-1], 0
				0x75, 0xF6, //jnz     short loc_2D0
				0x48, 0x29, 0xD0, //sub     rax, rdx
				0x83, 0xE8, 0x01, //sub     eax, 1
				0x48, 0x98, //cdqe
				0x48, 0x8D, 0x74, 0x02, 0xF7, //lea     rsi, [rdx+rax-9]
				0x31, 0xC0, //xor     eax, eax
				0xEB, 0x0D, //jmp     short loc_2F8
				0x0F, 0x1F, 0x44, 0x00, 0x00, //align 10h
				//loc_2F0:
				0x48, 0x83, 0xC0, 0x01, //add     rax, 1
				0x38, 0xCA, //cmp     dl, cl
				0x75, 0x28, //jnz     short loc_320
				//loc_2F8:
				0x0F, 0xB6, 0x14, 0x06, //movzx   edx, byte ptr [rsi+rax]
				0x0F, 0xB6, 0x0C, 0x07, //movzx   ecx, byte ptr [rdi+rax]
				0x84, 0xD2, //test    dl, dl
				0x75, 0xEC, //jnz     short loc_2F0
				0x0F, 0xB6, 0xD1, //movzx   edx, cl
				0xF7, 0xDA, //neg     edx
				0x85, 0xD2, //test    edx, edx
				0x74, 0x19, //jz      short loc_326
				// loc_30D: 
				0x4D, 0x8B, 0x40, 0x18, //mov     r8, [r8+18h]
				0x4D, 0x85, 0xC0, //test    r8, r8
				0x75, 0x9A, //jnz     short loc_2B0
				0xF3, 0xC3, //rep retn
				0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,//align 20h
				//loc_320: 
				0x29, 0xCA, //sub     edx, ecx
				0x85, 0xD2, //test    edx, edx
				0x75, 0xE7, //jnz     short loc_30D
				//loc_326:
				0x49, 0x8B, 0x10, // mov     rdx, [r8]
				0x48, 0x85, 0xD2, // test    rdx, rdx
				0x75, 0x02, //jnz     short locret_33F
				0xF3, 0xC3, //rep retn
				//locret_33F:
				0x90
			};
			allcode.insert(allcode.end(), findLibcbaseCode.begin(), findLibcbaseCode.end());
		}
		else
		{
			uint32_t linkmap = (uint32_t)(sect.virtual_address() + 4); //GOT[1]
			if (ispie)//pie情况下要先获取基址，才能得到linkmap地址
			{
				std::vector<uint8_t> getEIPcode = {
					0xe8, 0,    0,    0,    0, //call 5
					0x5d //pop ebp 获得EIP
				};
				//sub rax, 偏移常量 得到IMAGEBASE
				//add rax, got[1]偏移量
				std::string insn = "sub ebp, ";
				insn += std::to_string(virtualAddress + 5);
				insn += ";add ebp, " + std::to_string(linkmap);
				std::vector<uint8_t> getLinkMakpCode;
				KSEngine::instance()->assemble(insn.c_str(), 0, getLinkMakpCode);
				if (getLinkMakpCode.empty())
				{
					throw 1;
				}
				allcode.insert(allcode.end(), getEIPcode.begin(), getEIPcode.end());
				allcode.insert(allcode.end(), getLinkMakpCode.begin(), getLinkMakpCode.end());
			}
			else
			{
				//非PIE，直接获取到的就是linkmap地址
				std::string insn = "mov ebp, " + std::to_string(linkmap);
				std::vector<uint8_t> getLinkMakpCode;
				KSEngine::instance()->assemble(insn.c_str(), 0, getLinkMakpCode);
				if (getLinkMakpCode.empty())
				{
					throw 1;
				}
				allcode.insert(allcode.end(), getLinkMakpCode.begin(), getLinkMakpCode.end());
			}
			std::vector<uint8_t> findLibcbaseCode = {
				//0xBD, 0x44, 0x33, 0x22, 0x11, //mov     ebp, 11223344h linkmap参数放在ebp
				0x83, 0xEC, 0x1C, //sub     esp, 1Ch
				0x8D, 0x4C, 0x24, 0x06,//lea     ecx, [esp+2Ch+var_26]
				//loc_1F0: 
				0xB8, 0x36, 0x00, 0x00, 0x00, //mov     eax, 36h ;
				0xC7, 0x44, 0x24, 0x06, 0x6C, 0x69, 0x62, 0x63, //mov     [esp+2Ch+var_26], 6362696Ch
				0xC7, 0x44, 0x24, 0x0A, 0x2E, 0x73, 0x6F, 0x2E, //mov     [esp+2Ch+var_22], 2E6F732Eh
				0x66, 0x89, 0x44, 0x24, 0x0E, // mov     [esp+2Ch+var_1E], ax
				0x8B, 0x45, 0x04, // mov     eax, [ebp+4]
				0x8D, 0x76, 0x00, //lea     esi, [esi+0]
				//loc_210: 
				0x83, 0xC0, 0x01, // add     eax, 1
				0x80, 0x78, 0xFF, 0x00, //cmp     byte ptr [eax-1], 0
				0x75, 0xF7, //jnz     short loc_210
				0x8D, 0x78, 0xF6, //lea     edi, [eax-0Ah]
				0x31, 0xC0, //xor     eax, eax
				0xEB, 0x07, //jmp     short loc_227
				//loc_220:
				0x83, 0xC0, 0x01, // add     eax, 1
				0x38, 0xDA, //cmp     dl, bl
				0x75, 0x29, //jnz     short loc_250
				//loc_227:
				0x0F, 0xB6, 0x14, 0x07, //movzx   edx, byte ptr [edi+eax]
				0x0F, 0xB6, 0x1C, 0x01, //movzx   ebx, byte ptr [ecx+eax]
				0x84, 0xD2, //test    dl, dl
				0x75, 0xED, //jnz     short loc_220
				0x0F, 0xB6, 0xD3, //movzx   edx, bl
				0xF7, 0xDA, //neg     edx
				0x85, 0xD2, //test    edx, edx
				0x74, 0x1D, //jz      short loc_259
				//loc_23C: 
				0x8B, 0x6D, 0x0C, //mov     ebp, [ebp+0Ch]
				0x85, 0xED, //test    ebp, ebp
				0x75, 0xAD, //jnz     short loc_1F0
				//loc_243:
				0x83, 0xC4, 0x1C, //add     esp, 1Ch
				0x90, 0x90, 0x90, 0x90,
				0xC3, //ret
				0x90, 0x8D, 0x74, 0x26, 0x00,//align 10h
				//loc_250:
				0x0F, 0xB6, 0xF3, //movzx   esi, bl
				0x29, 0xF2, //sub     edx, esi
				0x85, 0xD2, //test    edx, edx
				0x75, 0xE3, //jnz     short loc_23C
				//loc_259:
				0x8B, 0x45, 0x00, //mov     eax, [ebp+0]
				0x85, 0xC0, //test    eax, eax
				0x74, 0xE3, //jz      short loc_243
				0x89, 0xC2, //mov edx,eax
				0x90
			};
			allcode.insert(allcode.end(), findLibcbaseCode.begin(), findLibcbaseCode.end());
		}
	}

	//CSEngine::instance()->disasmShow(allcode, virtualAddress);
}

void ModifyLibcCodeProvider::modifyGlobalMaxFast(uint64_t virtualAddress, std::vector<uint8_t> & allcode)
{
	uint64_t malloc_size = BinaryEditor::instance()->getRandomAligned(0, 100);
	std::string malloc_offset = Config::instance()->getLibcAttrString("malloc");
	std::string globalmaxfast = Config::instance()->getLibcAttrString(GLOBAL_MAX_FAST);
	std::string newValue = Config::instance()->getGlobalMaxFastValue();
	if (malloc_offset.empty() || globalmaxfast.empty() || newValue.empty())
	{
		std::cerr << "modifyGlobalMaxFast config error." << std::endl;
		return;
	}

	std::string insn;
	//rbp/ebp中存放libcbase
	//要修改global_max_fast，需要先调用malloc初始化
	bool isX32 = BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS32;
	if (isX32)
	{
		insn = "push ebp"; //先将libc基础保存
		insn += ";add ebp," + malloc_offset;//ebp是malloc地址
		insn += ";mov edi," + std::to_string(malloc_size);
		insn += ";push edi";//参数
		insn += ";call ebp";//调用malloc
		insn += ";pop edi"; //把参数POP出来
		insn += ";mov ebp,[esp]";//取出libcbase
		insn += ";add ebp," + globalmaxfast;
		insn += ";mov dword ptr [ebp], " + newValue;
		insn += ";pop ebp";//ebp仍然是libcbase，留给下一段代码使用
	}
	else
	{
		insn = "push rbp"; //先将libc基础保存
		insn += ";add rbp," + malloc_offset;//rbp是malloc地址
		insn += ";mov rdi," + std::to_string(malloc_size);
		insn += ";call rbp";//调用malloc
		insn += ";mov rbp,[rsp]";//取出libcbase
		insn += ";add rbp," + globalmaxfast;
		insn += ";mov qword ptr [rbp], " + newValue;
		insn += ";pop rbp";//rbp仍然是libcbase，留给下一段代码使用
	}

	std::vector<uint8_t> glbCode;
	KSEngine::instance()->assemble(insn.c_str(), virtualAddress, glbCode);
	if (glbCode.empty())
	{
		return;
	}

	allcode.insert(allcode.end(), glbCode.begin(), glbCode.end());
}

void ModifyLibcCodeProvider::closeTcache(uint64_t virtualAddress, std::vector<uint8_t> & allcode)
{
	std::string tcache_count_offset = Config::instance()->getLibcAttrString(TCACHE_COUNT);
	if (tcache_count_offset.empty())
	{
		std::cout << TCACHE_COUNT" config not found." << std::endl;
		return;
	}

	std::string insn;
	//rbp/ebp中存放libcbase
	//要修改global_max_fast，需要先调用malloc初始化
	bool isX32 = BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS32;
	if (isX32)
	{
		insn = "push ebp";
		insn += ";add ebp," + tcache_count_offset;
		insn += ";mov dword ptr [ebp], " + std::to_string(0);
		insn += ";pop ebp";
	}
	else
	{
		insn = "push rbp";
		insn += ";add rbp," + tcache_count_offset;
		insn += ";mov qword ptr [rbp], " + std::to_string(0);
		insn += ";pop rbp";
	}

	std::vector<uint8_t> tcacheCode;
	KSEngine::instance()->assemble(insn.c_str(), virtualAddress, tcacheCode);
	if (tcacheCode.empty())
	{
		return;
	}

	allcode.insert(allcode.end(), tcacheCode.begin(), tcacheCode.end());
}

void ModifyLibcCodeProvider::setNoBufStdout(uint64_t virtual_addr, std::vector<uint8_t> & allcode)
{
	//stdout->_flags |= _IO_UNBUFFERED; 
	//修改stdout的flags，使其不缓冲
	std::string stdout_offset = Config::instance()->getLibcAttrString(STDOUT);
	if (stdout_offset.empty())
	{
		std::cout << STDOUT" config not found." << std::endl;
		return;
	}

	std::string insn;
	bool isX64 = BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS64;
	if (isX64)
	{
		insn = "push rbp";
		insn += ";add rbp, " + stdout_offset;
		insn += ";or dword ptr [rbp], 2";
		insn += ";pop rbp";
	}
	else
	{
		insn = "push ebp";
		insn += ";add ebp, " + stdout_offset;
		insn += ";or dword ptr [ebp], 2";
		insn += ";pop ebp";
	}
	std::vector<uint8_t> code;
	KSEngine::instance()->assemble(insn.c_str(), virtual_addr, code);
	if (code.empty())
	{
		return;
	}
	allcode.insert(allcode.end(), code.begin(), code.end());
}

void ModifyLibcCodeProvider::nopbinsh(uint64_t virtual_addr, std::vector<uint8_t> & allcode)
{
	std::string binsh_offset = Config::instance()->getLibcAttrString(BINSH);
	if (binsh_offset.empty())
	{
		std::cout << BINSH" config not found." << std::endl;
		return;
	}

	std::string insn;
	bool isX64 = BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS64;
	if (isX64)
	{
		//mprotect()
		insn = "push rbp";
		insn += ";add rbp," + binsh_offset;
		insn += ";mov rdi,rbp";
		insn += ";and rdi,0xfffffffffffff000";
		insn += ";mov rsi,0x1000";
		insn += ";xor rdx,rdx";
		insn += ";xor rax,rax";
		insn += ";mov dl, 7";//RWX
		insn += ";mov al, 0xa";
		insn += ";syscall";
		insn += ";mov qword ptr [rbp], 0";
		insn += ";mov dl, 5";//恢复权限
		insn += ";mov al, 0xa";
		insn += ";syscall";
		insn += ";pop rbp";
	}
	else
	{
		insn = "push ebp";
		insn += ";add ebp, " + binsh_offset;
		insn += ";mov ebx,ebp";
		insn += ";and ebx,0xfffff000";
		insn += ";push 0x1000";
		insn += ";pop ecx";
		insn += ";push 7";
		insn += ";pop edx";
		insn += ";push 0x7d";
		insn += ";pop eax";
		insn += ";int 0x80";
		insn += ";mov dword ptr [ebp],0";
		insn += ";mov dword ptr [ebp+4],0";
		insn += ";push 5";
		insn += ";pop edx";
		insn += ";push 0x7d";
		insn += ";pop eax";
		insn += ";int 0x80";
		insn += ";pop ebp";
	}
	std::vector<uint8_t> code;
	KSEngine::instance()->assemble(insn.c_str(), virtual_addr, code);
	if (code.empty())
	{
		return;
	}
	allcode.insert(allcode.end(), code.begin(), code.end());
}
