#pragma once
#include "PatchPolicy.h"
class enableNXPolicy :
	public PatchPolicy
{
public:
	enableNXPolicy();
	~enableNXPolicy() {};
	virtual void do_patch() override;

};

