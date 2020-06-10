#pragma once
#include "PatchPolicy.h"

//在_start入口点处插入代码
class StartInjectPolicy :
	public PatchPolicy
{
public:
	static const char * name()
	{
		return "StartInjectPolicy";
	}

	StartInjectPolicy()
	{
		this->setRiskLevel(MEDIUM);
	}
	~StartInjectPolicy() {}
	virtual void do_patch() override;
private:
	void setProvider();
};

