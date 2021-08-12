#include "BinaryEditor.h"
#include "CSEngine.h"
#include "LibelfEditor.h"
#include <unistd.h>
#include <sys/stat.h>

BinaryEditor * BinaryEditor::_instance = nullptr;
BinaryEditor::PatchMode BinaryEditor::_mode = LIBELF_PATCH_MODE;

bool BinaryEditor::init(const std::string & elfname)
{
	try {
		_binary = Parser::parse(elfname);
	}
	catch (const LIEF::exception& e) {
		std::cerr << e.what() << std::endl;
		return false;
	}

	_outfile = elfname + "_patched";

	if (_mode == LIBELF_PATCH_MODE)
	{
		LibelfEditor::copy_file(elfname, _outfile);
		if(!LibelfEditor::init(_outfile.c_str()))
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

bool BinaryEditor::enableNX()
{
	if (_mode == LIEF_PATCH_MODE)
	{
		try
		{
			Segment & segment = _binary->get(SEGMENT_TYPES::PT_GNU_STACK);
			segment.remove(ELF_SEGMENT_FLAGS::PF_X);
		}
		catch (...)
		{
			return false;
		}
		return true;
	}
	else
	{
		return LibelfEditor::enable_nx();
	}
}

bool BinaryEditor::enableBindnow()
{
	if (_mode == LIEF_PATCH_MODE)
	{
		try
		{
			DynamicEntry & dynEntry = _binary->get(DYNAMIC_TAGS::DT_DEBUG);
			dynEntry.tag(DYNAMIC_TAGS::DT_BIND_NOW);
			dynEntry.value(0);
		}
		catch (...)
		{
			return false;
		}
		return true;
	}
	else
	{
		return LibelfEditor::enable_bindnow();
	}
}

void BinaryEditor::writeFile()
{
	if(_mode == LIBELF_PATCH_MODE)
		LibelfEditor::writeFile();
	else
	{
		unlink(_outfile.c_str());
		_binary->write(_outfile);
	}
		
	chmod(_outfile.c_str(), S_IRWXU|S_IXGRP|S_IRGRP|S_IXOTH|S_IROTH);
	std::cout << "\033[1m\033[31m" << _outfile << " generated." << "\033[0m" << std::endl;
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

void BinaryEditor::symbol_swap(Symbol & sym1, Symbol & sym2)
{
	sym1.swap(sym2);
	if (_mode == LIBELF_PATCH_MODE)
	{
		LibelfEditor::symbol_swap(sym1.name(), sym2.name());
	}
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
	if (_mode == LIBELF_PATCH_MODE)
	{
		LibelfEditor::patch_address(address, code);
	}
	else
	{
		_binary->patch_address(address, code);
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
	if (_mode == LIBELF_PATCH_MODE)
	{
		LibelfEditor::abort();
		throw new NotSupportException();
	}
	
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

std::vector<uint8_t> BinaryEditor::get_content(uint64_t address, uint64_t size)
{
	if (_mode == LIBELF_PATCH_MODE)
	{
		return LibelfEditor::get_content_from_virtual_address(address, size);
	}
	return _binary->get_content_from_virtual_address(address, size);
}

void BinaryEditor::getAllRelocations(std::vector<Relocation *> & allrels)
{
	std::list<uint64_t> plotTabEntryAddress;
	for (auto reloc : _binary->relocations())
	{
		plotTabEntryAddress.push_back(reloc.address());
	}

	for (uint64_t addr : plotTabEntryAddress)
	{
		Relocation * reloc = _binary->get_relocation(addr);
		if (reloc)
		{
			allrels.push_back(reloc);
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

uint64_t BinaryEditor::original_size()const
{
	return _binary->original_size();
}

uint64_t BinaryEditor::imagebase()const
{
	return _binary->imagebase();
}

uint64_t BinaryEditor::entryPoint()const
{
	if (_mode == LIBELF_PATCH_MODE)
	{
		return LibelfEditor::entryPoint();
	}
	return _binary->entrypoint();
}
