#pragma once
#include "PatchPolicy.h"
class enableFortifyPolicy :
	public PatchPolicy
{
public:
	enableFortifyPolicy();
	~enableFortifyPolicy() {}


	virtual void do_patch() override;
private:
	void do_patch(const char * symbolName);
};

