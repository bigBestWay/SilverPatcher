#pragma once
#include "PatchPolicy.h"
class BindNowPolicy :
	public PatchPolicy
{
public:
	BindNowPolicy()
	{
		this->setRiskLevel(SECURE);
	}
	~BindNowPolicy() {}

	virtual void do_patch() override;

};

