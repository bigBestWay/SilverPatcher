#pragma once
#include "PatchPolicy.h"

//在main函数插入代码
class MainInjectPolicy :
	public PatchPolicy
{
public:
	static const char * name()
	{
		return "MainInjectPolicy";
	}

	MainInjectPolicy()
	{
		this->setRiskLevel(MEDIUM);
	}
	~MainInjectPolicy() {}
	virtual void do_patch() override;
private:
	void setProvider();
	uint64_t findMainFunction()const;
};

