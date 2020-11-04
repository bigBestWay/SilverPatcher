#include "RandomPLTGOTPolicy.h"
#include "BinaryEditor.h"
#include "CSEngine.h"
#include <map>
#include <string>
#include <list>

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
				const char *str = strtab + ELF64_R_SYM(rela[i].r_info);
				std::cout << "RELA " << std::string(str) << " " < std::hex << ELF64_R_SYM(rela[i].r_info);
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
