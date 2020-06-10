#include "DisableFreePolicy.h"
#include "BinaryEditor.h"
#include <iostream>
#include "CSEngine.h"

void DisableFreePolicy::do_patch()
{
	label("DisableFreePolicy");
	try
	{
		const Relocation * reloc = BinaryEditor::instance()->getRelocation("free");
		if (reloc == nullptr)
		{
			std::cerr << "No free." << std::endl;
			return;
		}

		uint64_t patch_addr = getCallEntryPoint(reloc);
		std::cout << "PATCH AT:" << std::hex << patch_addr << std::endl;
		BinaryEditor::instance()->patch_address(patch_addr, std::vector<uint8_t>{0xC3});
		std::cout << "Free disabled." << std::endl;
	}
	catch (...)
	{
		std::cerr << "Other error." << std::endl;
	}
}

uint64_t DisableFreePolicy::getCallEntryPoint(const Relocation * reloc)
{
	//�ҵ�free��PLT������תֱ��RET
	if (BinaryEditor::instance()->isGotReadonly())
	{
		//FULL RELRO������Ҫ����.plt.got
		Section pltgot_section;
		if (!BinaryEditor::instance()->getPLTGOTSection(pltgot_section))
		{
			std::cerr << "Not found .plt.got section." << std::endl;
			throw 1;
		}

		//.plt.got����32����64����8�ֽ�һ��
		#define PLT_GOT_SECTION_ENTRY_SIZE 8
		bool isX32 = BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS32;
		if (!isX32)
		{
			//x64 PIE�ͷ�PIE�ṹһ��
			for (uint64_t pos = pltgot_section.virtual_address();
				pos != pltgot_section.virtual_address() + pltgot_section.size();
				pos += PLT_GOT_SECTION_ENTRY_SIZE)
			{
				const std::vector<uint8_t> & code = BinaryEditor::instance()->get_content(pos, PLT_GOT_SECTION_ENTRY_SIZE);
				cs_insn *insn = nullptr;
				size_t count = CSEngine::instance()->disasm(code, pos, &insn);
				if (count == 0)
				{
					std::cerr << "Disasm fail at " << std::hex << pos << std::endl;
					throw 1;
				}

				//jmp dword ptr [rip + 0x20021c]������ʽ
				uint64_t addr = getJmpAddress(insn[0]) + insn[0].address + insn[0].size;
				//std::cout << "addr=" << std::hex << addr << std::endl;
				if (addr == reloc->address())
				{
					//CSEngine::instance()->disasmShow(code, pos);
					return pos;
				}
			}
			throw 1;
		}
		else
		{
			if (!BinaryEditor::instance()->isPIE())
			{
				//x32��PIE���Ǿ��Ե�ַ
				for (uint64_t pos = pltgot_section.virtual_address();
					pos != pltgot_section.virtual_address() + pltgot_section.size();
					pos += PLT_GOT_SECTION_ENTRY_SIZE)
				{
					const std::vector<uint8_t> & code = BinaryEditor::instance()->get_content(pos, PLT_GOT_SECTION_ENTRY_SIZE);
					cs_insn *insn = nullptr;
					size_t count = CSEngine::instance()->disasm(code, pos, &insn);
					if (count == 0)
					{
						std::cerr << "Disasm fail at " << std::hex << pos << std::endl;
						throw 1;
					}

					uint64_t addr = getJmpAddress(insn[0]);
					//std::cout << "addr=" << std::hex << addr << std::endl;
					if (addr == reloc->address())
					{
						//CSEngine::instance()->disasmShow(code, pos);
						return pos;
					}
				}

				throw 1;
			}
			else
			{
				Section gotSection;
				if (!BinaryEditor::instance()->getGOTSection(gotSection))
				{
					std::cerr << "Not found .got section." << std::endl;
					throw 1;
				}

				for (uint64_t pos = pltgot_section.virtual_address();
					pos != pltgot_section.virtual_address() + pltgot_section.size();
					pos += PLT_GOT_SECTION_ENTRY_SIZE)
				{
					const std::vector<uint8_t> & code = BinaryEditor::instance()->get_content(pos, PLT_GOT_SECTION_ENTRY_SIZE);
					cs_insn *insn = nullptr;
					size_t count = CSEngine::instance()->disasm(code, pos, &insn);
					if (count == 0)
					{
						std::cerr << "Disasm fail at " << std::hex << pos << std::endl;
						throw 1;
					}

					uint64_t addr = 0;
					//x32 PIEʱ��.plt.gotÿ����Ŀ��jmp dword ptr [ebx+0xc]��ebx��.got�ڻ�ַ
					addr = getJmpAddress(insn[0]) + gotSection.virtual_address();
					//std::cout << "addr=" << std::hex << addr << std::endl;
					if (addr == reloc->address())
					{
						//CSEngine::instance()->disasmShow(code, pos);
						return pos;
					}
				}

				throw 1;
			}
		}
	}
	else
	{
		uint64_t plt_6 = BinaryEditor::instance()->getGotSlotValue(reloc->address());
		return plt_6 - 6;
	}
}

uint64_t DisableFreePolicy::getJmpAddress(const cs_insn & insn)
{
	cs_x86 * x86 = &(insn.detail->x86);
	for (int j = 0; j < x86->op_count; j++) {
		cs_x86_op *op = &(x86->operands[j]);

		switch ((int)op->type) {
		case X86_OP_MEM:
			return op->mem.disp;
			break;
		default:
			break;
		}
	}
	return 0;
}
