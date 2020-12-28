#pragma once
#include "DisableFreePolicy.h"

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
	static std::string generateNewCode(int fmtParamIndex, uint64_t entryPoint);
	static int getFmtParamIndex(const std::string & sym_name);
};

