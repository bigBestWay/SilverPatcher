#pragma once
#include "PatchPolicy.h"
class BindNowPolicy :
	public PatchPolicy
{
public:
	static const char * name()
	{
		return "BindNowPolicy";
	}
	BindNowPolicy()
	{
		this->setRiskLevel(SECURE);
	}
	~BindNowPolicy() {}

	virtual void do_patch() override;

};

