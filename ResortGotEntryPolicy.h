#pragma once
#include <vector>
#include <string>
#include "PatchPolicy.h"
#include <cstdint>

//��û��RELRO�����������£�����GOT����λ�ã�����Ҫ����κδ���

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

