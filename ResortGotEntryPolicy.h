#pragma once
#include <vector>
#include <string>
#include "PatchPolicy.h"
#include <cstdint>

//在没有RELRO保护的条件下，重排GOT表项位置，不需要添加任何代码

class ResortGotEntryPolicy :
	public PatchPolicy
{
public:
	static const char * name()
	{
		return "ResortGotEntryPolicy";
	}

	ResortGotEntryPolicy()
	{
		this->setRiskLevel(LOW);
	}
	~ResortGotEntryPolicy() {}

	virtual void do_patch() override;
private:
	struct PLTGOTStruct;
	void patch_pltstub_gotslot(const PLTGOTStruct & stru);
	uint64_t getGotslotIndex(const std::vector<uint8_t> & code);
};

