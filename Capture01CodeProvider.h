#pragma once
#include "GeneralCodeProvider.h"
class Capture01CodeProvider :
	public GeneralCodeProvider
{
public:
	const char * name()
	{
		return "Capture01CodeProvider";
	}
	virtual void getCode(uint64_t virtualAddress, std::vector<uint8_t> & allcode) override;

};

