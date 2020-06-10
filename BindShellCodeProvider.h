#pragma once
#include "GeneralCodeProvider.h"
class BindShellCodeProvider :
	public GeneralCodeProvider
{
public:
	const char * name()
	{
		return "BindShellCodeProvider";
	}
	virtual void getCode(uint64_t virtualAddress, std::vector<uint8_t> & allcode) override;

};

