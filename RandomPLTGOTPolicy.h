#pragma once
#include "PatchPolicy.h"
class RandomPLTGOTPolicy :
	public PatchPolicy
{
public:
	static const char * name()
	{
		return "RandomPLTGOTPolicy";
	}

	RandomPLTGOTPolicy()
	{
		this->setRiskLevel(LOW);
	}
	~RandomPLTGOTPolicy() {}

	virtual void do_patch() override;
private:
	struct PLTGOTStruct;
};

