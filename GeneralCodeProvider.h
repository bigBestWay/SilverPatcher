#pragma once
#include <cstdint>
#include <vector>

class GeneralCodeProvider
{
public:
	GeneralCodeProvider() {}
	virtual ~GeneralCodeProvider() {}
	virtual const char * name() = 0;
	virtual void getCode(uint64_t virtualAddress, std::vector<uint8_t> & allcode) = 0;
};
