#pragma once
#include "GeneralCodeProvider.h"
class ClearBackdoorCodeProvider :
	public GeneralCodeProvider
{
public:
	const char * name()
	{
		return "ClearBackdoorCodeProvider";
	}
	virtual void getCode(uint64_t virtualAddress, std::vector<uint8_t> & allcode) override;

};
