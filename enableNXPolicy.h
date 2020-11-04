#pragma once
#include "PatchPolicy.h"
class enableNXPolicy :
	public PatchPolicy
{
public:
	static const char * name()
	{
		return "enableNXPolicy";
	}
	enableNXPolicy();
	~enableNXPolicy() {};
	virtual void do_patch() override;

};

