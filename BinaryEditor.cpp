#include "BinaryEditor.h"
#include "CSEngine.h"

BinaryEditor * BinaryEditor::_instance = nullptr;

bool BinaryEditor::init(const std::string & elfname)
{
	try {
		_binary = Parser::parse(elfname);
	}
	catch (const LIEF::exception& e) {
		std::cerr << e.what() << std::endl;
		return false;
	}
	//loadCodeDefaultCaves();
	return true;
}

bool BinaryEditor::getSegment(SEGMENT_TYPES type, Segment *& out)
{
	try
	{
		out = &_binary->get(type);
	}
	catch (...)
	{
		return false;
	}
	return true;
}

bool BinaryEditor::getSegment(uint64_t addr, Segment * &out)
{
	try
	{
		out = &_binary->segment_from_virtual_address(addr);
	}
	catch (...)
	{
		return false;
	}
	return true;
}

void BinaryEditor::writeFile(const std::string & elfname)
{
	_binary->write(elfname);
}

bool BinaryEditor::getSectionByType(ELF_SECTION_TYPES type, Section * & out)
{
	try
	{
		out = &_binary->get(type);
	}
	catch (...)
	{
		return false;
	}
	return true;
}

bool BinaryEditor::getDynamicEntrysByTag(DYNAMIC_TAGS tag, DynamicEntry * &out)
{
	try
	{
		out = &_binary->get(tag);
	}
	catch (...)
	{
		return false;
	}
	return true;
}

LIEF::ELF::Relocation * BinaryEditor::getRelocation(const std::string & name)
{
	return _binary->get_relocation(name);
}

LIEF::ELF::Relocation * BinaryEditor::getRelocation(uint64_t address)
{
	return _binary->get_relocation(address);
}

uint64_t BinaryEditor::getRandomAligned(uint64_t low, uint64_t high)
{
	srand(time(0));
	uint64_t r = abs(rand()) % high + low;
	if (_binary->type() == ELF_CLASS::ELFCLASS32)
	{
		return r * 4;
	}
	else
	{
		return r * 8;
	}
}

void BinaryEditor::textFunctions(LIEF::Binary::functions_t & textFuncions)
{
	const Section & text = _binary->text_section();
	//std::cout << text << std::endl;
	for (const LIEF::Function & func : _binary->functions())
	{
		if (func.address() == _binary->entrypoint())
		{
			continue;
		}
		if (text.virtual_address() <= func.address() && func.address() <= text.virtual_address() + text.size())
		{
			textFuncions.push_back(func);
		}
	}
}

void BinaryEditor::patch_address(uint64_t address, const std::vector<uint8_t> & code)
{
	_binary->patch_address(address, code);
}

/*一个ELF文件加载到进程中的只看Segment，section是链接使用的。
因此寻找code cave可以使用加载进内存中但又没什么用的Segement。
比如PT_NOTE、PT_GNU_EH_FRAME，并修改标志位使该段可执行。
函数间的空隙太小，多为10字节以下，暂不考虑使用。
*/
void BinaryEditor::loadCodeDefaultCaves()
{
	for (Segment & segment : _binary->segments())
	{
		SEGMENT_TYPES type = segment.type();
		if (type == SEGMENT_TYPES::PT_GNU_EH_FRAME)
		{
			CodeCave cave;
			cave.virtual_addr = segment.virtual_address();
			cave.size = segment.virtual_size();
			segment.add(ELF_SEGMENT_FLAGS::PF_X);
			InstrumentManager::instance()->addCodeCave(cave);
		}
	}
}

uint32_t BinaryEditor::getDWORD(uint64_t address)
{
	uint32_t result = 0;
	const std::vector<uint8_t> &code = _binary->get_content_from_virtual_address(address, sizeof(uint32_t));
	std::memcpy(&result, code.data(), sizeof(uint32_t));
	return result;
}

uint64_t BinaryEditor::getQWORD(uint64_t address)
{
	uint64_t result = 0;
	const std::vector<uint8_t> &code = _binary->get_content_from_virtual_address(address, sizeof(uint64_t));
	std::memcpy(&result, code.data(), sizeof(uint64_t));
	return result;
}

CodeCave * BinaryEditor::addSection(size_t size)
{
	std::cout<< "\033[31m" << "Add section size " << size << "\033[0m" <<std::endl;
	//没有足够大小的cave了，只能添加段
	Section new_section{ ".gnu.text" };
	new_section.add(ELF_SECTION_FLAGS::SHF_EXECINSTR);
	new_section.add(ELF_SECTION_FLAGS::SHF_ALLOC);
	std::vector<uint8_t> data(size, 0x90);
	new_section.content(data);
	new_section = _binary->add(new_section);
	CodeCave cave;
	cave.virtual_addr = new_section.virtual_address();
	cave.size = new_section.size();
	return InstrumentManager::instance()->addCodeCave(cave);
}

bool BinaryEditor::isGotReadonly() const
{
	//满足两个条件：
	//1.存在PT_GNU_RELRO段
	//2.如果got定位后只读，就只有.got节而没有.got.plt节
	for (const Section & sec : _binary->sections())
	{
		if (sec.type() == ELF_SECTION_TYPES::SHT_PROGBITS && sec.name() == ".got.plt")
		{
			return false;
		}
	}

	try
	{
		return _binary->get(SEGMENT_TYPES::PT_GNU_RELRO).has(".got");
	}
	catch (...)
	{
		return false;
	}
}

bool BinaryEditor::isBindNow() const
{
	try
	{
		_binary->get(DYNAMIC_TAGS::DT_BIND_NOW);
		return true;
	}
	catch (...)
	{
		return false;
	}
}

bool BinaryEditor::getPLTSection(Section & section)
{
	for (const Section & sec : _binary->sections())
	{
		if (sec.type() == ELF_SECTION_TYPES::SHT_PROGBITS && sec.name() == ".plt")
		{
			section = sec;
			return true;
		}
	}

	return false;
}

bool BinaryEditor::getGOTPLTSection(Section & section)
{
	for (const Section & sec : _binary->sections())
	{
		if (sec.type() == ELF_SECTION_TYPES::SHT_PROGBITS && sec.name() == ".got.plt")
		{
			section = sec;
			return true;
		}
	}

	return false;
}

bool BinaryEditor::getPLTGOTSection(Section & section)
{
	for (const Section & sec : _binary->sections())
	{
		if (sec.type() == ELF_SECTION_TYPES::SHT_PROGBITS && sec.name() == ".plt.got")
		{
			section = sec;
			return true;
		}
	}

	return false;
}

bool BinaryEditor::getGOTSection(Section & section)
{
	for (const Section & sec : _binary->sections())
	{
		if (sec.type() == ELF_SECTION_TYPES::SHT_PROGBITS && sec.name() == ".got")
		{
			section = sec;
			return true;
		}
	}

	return false;
}

bool BinaryEditor::getTextSection(Section & section)
{
	for (const Section & sec : _binary->sections())
	{
		if (sec.type() == ELF_SECTION_TYPES::SHT_PROGBITS && sec.name() == ".text")
		{
			section = sec;
			return true;
		}
	}

	return false;
}

bool BinaryEditor::getReladynSection(Section & section)
{
	for (const Section & sec : _binary->sections())
	{
		if (sec.type() == ELF_SECTION_TYPES::SHT_RELA && sec.name() == ".rela.dyn")
		{
			section = sec;
			return true;
		}
	}

	return false;
}

bool BinaryEditor::getDynstrSection(Section & section)
{
	for (const Section & sec : _binary->sections())
	{
		if (sec.type() == ELF_SECTION_TYPES::SHT_STRTAB && sec.name() == ".dynstr")
		{
			section = sec;
			return true;
		}
	}

	return false;
}

void BinaryEditor::getPLTGOTRelocations(std::vector<Relocation *> & pltgotRel)
{
	std::list<uint64_t> plotTabEntryAddress;
	for (auto reloc : _binary->pltgot_relocations())
	{
		plotTabEntryAddress.push_back(reloc.address());
	}

	for (uint64_t addr : plotTabEntryAddress)
	{
		Relocation * reloc = _binary->get_relocation(addr);
		if (reloc)
		{
			pltgotRel.push_back(reloc);
		}
	}
}

uint32_t BinaryEditor::getPLTEntrySize()
{
	uint32_t plt_entry_size = 4;
	switch (_binary->header().machine_type())
	{
	case ARCH::EM_386:
	case ARCH::EM_X86_64:
		plt_entry_size = 16;
		if (this->isGotReadonly())
		{
			plt_entry_size = 8;
		}
		break;
	default:
		break;
	}
	return plt_entry_size;
}

uint64_t BinaryEditor::getGotSlotValue(uint64_t address)
{
	if (_binary->type() == ELF_CLASS::ELFCLASS32)
	{
		return getDWORD(address);
	}
	else
	{
		return getQWORD(address);
	}
}

