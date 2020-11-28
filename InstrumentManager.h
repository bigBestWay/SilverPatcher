#pragma once
#include <list>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <string>
#include "GeneralCodeProvider.h"

class cs_insn;
struct CodeCave
{
	unsigned long virtual_addr;
	unsigned long size;
	CodeCave():virtual_addr(0), size(0)
	{}
	bool operator<(const CodeCave & o)const
	{
		return this->virtual_addr < o.virtual_addr;
	}
};

struct PatchUnit 
{
	uint64_t address;
	std::vector<uint8_t> code;
	PatchUnit(uint64_t addr, std::vector<uint8_t> & c)
	{
		address = addr;
		code.swap(c);
	}
	PatchUnit() :address(0)
	{

	}
};

class InstrumentManager
{
private:
	InstrumentManager() {}
	~InstrumentManager() {}
public:
	static InstrumentManager * instance()
	{
		if (_instance == nullptr)
		{
			_instance = new InstrumentManager();
		}
		return _instance;
	}

	static void destory()
	{
		delete _instance;
		_instance = nullptr;
	}

	CodeCave getCodeCave(unsigned int size);

	//在函数开头和结尾分别插入抬高和降低栈的代码
	void generateJmpCode(const cs_insn * insns, size_t count, uint64_t addressOffset, std::vector<PatchUnit> & patchUnits);

	void addCodeProvider(GeneralCodeProvider * provider)
	{
		_codeProviders.push_back(provider);
	}

	void insertCodeAtBegin(const cs_insn * insns, size_t count, std::vector<PatchUnit> & patchUnits);

	void insertCodeHere(const cs_insn & callInsn, const std::string & asmInsn, std::vector<PatchUnit> & patchUnits);

	CodeCave * addCodeCave(const CodeCave & cave);
private:
	static void generateJmpCode(const cs_insn * insns, size_t count, uint64_t addressOffset, CodeCave * cave, std::vector<PatchUnit> & patchUnits);
	void insertCodeAtBegin_i(const cs_insn * insns, size_t count, CodeCave * cave, std::vector<PatchUnit> & patchUnits);
	void insertCodeAtHere_i(const cs_insn & callInsn, const std::string & asmInsn, CodeCave * cave, std::vector<PatchUnit> & patchUnits);
	static void translate(uint64_t newaddress, const std::vector<const cs_insn *> & insns, std::vector<uint8_t> & code);
	static bool calc_rip_addressing(const cs_insn & insn, uint64_t newaddress, std::vector<uint8_t> & outcode);
private:
	std::list<CodeCave> m_caves;
	std::list<GeneralCodeProvider *> _codeProviders;
private:
	static InstrumentManager * _instance;
};

