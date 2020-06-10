#pragma once
#include "PatchPolicy.h"
#include "LIEF/ELF/Relocation.hpp"

class cs_insn;
class DisableFreePolicy:public PatchPolicy
{
public:
	static const char * name()
	{
		return "DisableFreePolicy";
	}

	DisableFreePolicy()
	{
		this->setRiskLevel(SECURE);
	}
	~DisableFreePolicy() {}
	virtual void do_patch() override;
protected:
	//根据动态符号名，找到plt stub
	uint64_t getCallEntryPoint(const LIEF::ELF::Relocation * reloc);
private:
	uint64_t getJmpAddress(const cs_insn & insn);
};

