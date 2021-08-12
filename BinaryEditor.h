#pragma once
#include <LIEF/ELF.hpp>
#include "InstrumentManager.h"
using namespace LIEF::ELF;

#define DEFAULT_SECTION_SIZE 4096

struct Elf;
class BinaryEditor
{
public:
	enum PatchMode
	{
		LIEF_PATCH_MODE = 0,
		LIBELF_PATCH_MODE
	};

	class NotSupportException
	{
	};

	static BinaryEditor * instance()
	{
		if (_instance == nullptr)
		{
			_instance = new BinaryEditor();
		}
		return _instance;
	}

	static void destroy()
	{
		delete _instance;
		_instance = nullptr;
	}

	static void set_patchmode(PatchMode mode)
	{
		_mode = mode;
	}

	uint64_t imagebase()const;

	uint64_t original_size()const;

	bool init(const std::string & elfname);

	bool getSegment(uint64_t addr, Segment * &out);

	bool enableNX();

	bool enableBindnow();

	void writeFile();

	bool getSectionByType(ELF_SECTION_TYPES type, Section * & out);

	bool getDynamicEntrysByTag(DYNAMIC_TAGS tag, DynamicEntry * &out);

	Relocation * getRelocation(const std::string & name);

	Relocation * getRelocation(uint64_t address);

	DynamicEntry & add(DynamicEntry & entry)
	{
		return _binary->add(entry);
	}

	ELF_CLASS getPlatform()
	{
		return _binary->type();
	}

	void symbol_swap(Symbol & sym1, Symbol & sym2);

	uint64_t getRandomAligned(uint64_t low, uint64_t high);

	void textFunctions(LIEF::Binary::functions_t & textFuncions);

	void patch_address(uint64_t address, const std::vector<uint8_t> & code);

	bool hasNX()const
	{
		return _binary->has_nx();
	}

	bool isPIE()const
	{
		return _binary->is_pie();
	}

	uint64_t entryPoint()const;

	CodeCave * addSection(size_t size = 4096);

	//加载GOT后，.got.plt段是只读的
	//gcc默认编译时，只有.init_array .fini_array .jcr .dynamic .got
	bool isGotReadonly()const;

	//GOT在ld阶段立即绑定，而不是lazy模式
	bool isBindNow()const;

	//.plt
	bool getPLTSection(Section & section);

	//.got.plt
	bool getGOTPLTSection(Section & section);
	//.plt.got
	bool getPLTGOTSection(Section & section);
	//.got
	bool getGOTSection(Section & section);

	void getAllRelocations(std::vector<Relocation *> & allrels);

	const Section & textSection()const
	{
		return _binary->text_section();
	}

	std::vector<uint8_t> get_content(uint64_t address, uint64_t size);

	uint32_t getPLTEntrySize();

	uint64_t getGotSlotValue(uint64_t address);
private:
	uint32_t getDWORD(uint64_t address);
	uint64_t getQWORD(uint64_t address);
private:
	BinaryEditor(){}
	~BinaryEditor(){}
	static BinaryEditor * _instance;
	static PatchMode _mode;
private:
	std::unique_ptr<Binary> _binary;
	std::string _outfile;
};

