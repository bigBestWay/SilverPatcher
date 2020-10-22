#include "ClearBackdoorCodeProvider.h"
#include "BinaryEditor.h"
#include "KSEngine.h"

void ClearBackdoorCodeProvider::getCode(uint64_t virtualAddress, std::vector<uint8_t> & allcode)
{
    if (BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS64)
	{
        std::vector<uint8_t> codeX64;
        std::string asmtext = 
            "xor rax,rax;\
            mov al,0x3e;\
            mov rdi, 0xffffffffffffffff;\
            push 9;\
            pop rsi;\
            syscall;\
            ";
        KSEngine::instance()->assemble(asmtext.c_str(), 0, codeX64);
		allcode.insert(allcode.end(), codeX64.begin(), codeX64.end());
    }
    else
    {
        std::string x32asm = 
            "xor eax,eax;\
            mov al,0x25;\
            mov ebx,0xffffffff;\
            push 9;\
            pop ecx;\
            int 0x80;\
            ";
        std::vector<uint8_t> codeX32;
		KSEngine::instance()->assemble(x32asm.c_str(), 0, codeX32);
		allcode.insert(allcode.end(), codeX32.begin(), codeX32.end());
    }
}
