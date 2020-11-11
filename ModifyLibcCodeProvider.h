#pragma once
#include "GeneralCodeProvider.h"
class ModifyLibcCodeProvider :
	public GeneralCodeProvider
{
	
public:
	const char * name()
	{
		return "ModifyLibcCodeProvider";
	}
	virtual void getCode(uint64_t virtualAddress, std::vector<uint8_t> & allcode) override;
protected:
	void getLibcbase(uint64_t virtualAddress, std::vector<uint8_t> & allcode);
	void modifyGlobalMaxFast(uint64_t virtualAddress, std::vector<uint8_t> & allcode);
	void closeTcache(uint64_t virtualAddress, std::vector<uint8_t> & allcode);
	void setNoBufStdout(uint64_t virtual_addr, std::vector<uint8_t> & allcode);
	void nopbinsh(uint64_t virtual_addr, std::vector<uint8_t> & allcode);
};

