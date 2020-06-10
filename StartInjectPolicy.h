#pragma once
#include "PatchPolicy.h"

//��_start��ڵ㴦�������
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

