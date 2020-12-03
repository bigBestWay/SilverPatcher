#include "ModifyLibcCodeProvider.h"
#include "MainInjectPolicy.h"
#include "BinaryEditor.h"
#include "KSEngine.h"
#include "CSEngine.h"
#include "Config.h"

void ModifyLibcCodeProvider::getCode(uint64_t virtualAddress, std::vector<uint8_t> & allcode)
{
	uint64_t offset = 0;
	std::vector<uint8_t> findLibcBase;

	getLibcbaseAtMain(virtualAddress, findLibcBase);
	
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

//main函数获取libc非常简单，直接取栈顶就可以
void ModifyLibcCodeProvider::getLibcbaseAtMain(uint64_t virtualAddress, std::vector<uint8_t> & allcode)
{
	const std::string & libccall_main_ret_offset =  Config::instance()->getLibcAttrString("libccall_main_ret_offset");
	bool isX64 = BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS64;
	std::string insn;
	if (isX64)
	{
		insn = "mov rbp, rax;";
		insn += "sub rbp, " + libccall_main_ret_offset;
	}
	else
	{
		insn = "mov ebp, eax;";
		insn += "sub ebp, " + libccall_main_ret_offset;
	}

	std::vector<uint8_t> getLinkMakpCode;
	KSEngine::instance()->assemble(insn.c_str(), 0, getLinkMakpCode);
	if (getLinkMakpCode.empty())
	{
		throw 1;
	}
	allcode.insert(allcode.end(), getLinkMakpCode.begin(), getLinkMakpCode.end());
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
