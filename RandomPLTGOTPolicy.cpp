#include "RandomPLTGOTPolicy.h"
#include "BinaryEditor.h"
#include "CSEngine.h"
#include <map>
#include <string>
#include <list>

#define ELF32_R_SYM(val)		((val) >> 8)
#define ELF32_R_TYPE(val)		((val) & 0xff)
#define ELF32_R_INFO(sym, type)		(((sym) << 8) + ((type) & 0xff))

#define ELF64_R_SYM(i)			((i) >> 32)
#define ELF64_R_TYPE(i)			((i) & 0xffffffff)
#define ELF64_R_INFO(sym,type)		((((Elf64_Xword) (sym)) << 32) + (type))

void RandomPLTGOTPolicy::do_patch()
{
	label("RandomPLTGOTPolicy");
	bool isX32 = BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS32;
	//key 符号名 value call指令的地址
	std::map<std::string, std::list<uint64_t> > pltCalls;
	//key 符号名 value 字符串偏移量
	std::map<std::string, Elf64_Rela *> sym2rela;
	if (BinaryEditor::instance()->isGotReadonly())
	{
		if (!isX32)
		{
			Section relaDyn;
			if (!BinaryEditor::instance()->getReladynSection(relaDyn))
			{
				std::cerr << "Not found .rela.dyn section" << std::endl;
				return;
			}

			Section dynstr;
			if (!BinaryEditor::instance()->getDynstrSection(dynstr))
			{
				std::cerr << "Not found .dynstr section" << std::endl;
				return;
			}

			std::vector<uint8_t> data = relaDyn.content();
			const char * strtab = (char *)dynstr.content().data();
			Elf64_Rela * rela = (Elf64_Rela *)data.data();
			for (size_t i = 0; i < data.size()/sizeof(Elf64_Rela); ++i)
			{
                                uint64_t offset = ELF64_R_SYM(rela[i].r_info);
				const char *str = strtab + offset;
				std::cout << "RELA " << std::string(str) << " " << std::hex << offset <<std::endl;
				sym2rela[str] = rela;
			}
		}
		else
		{

		}
	}
	else
	{

	}
}
