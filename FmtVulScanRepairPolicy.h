#pragma once
#include "DisableFreePolicy.h"

class cs_x86_op;
class cs_insn;
class FmtVulScanRepairPolicy :
	public DisableFreePolicy
{
public:
	static const char * name()
	{
		return "FmtVulScanRepairPolicy";
	}

	FmtVulScanRepairPolicy();


	~FmtVulScanRepairPolicy() {}


	virtual void do_patch() override;
private:
	static const cs_x86_op * findSrcOp(const cs_insn * insns, size_t & index, const cs_x86_op * op);
	static std::string generateNewCode(int fmtParamIndex, uint64_t entryPoint);
	static void warn();
	void scanVul();
	static int getFmtParamIndex(const std::string & sym_name);
};

