#pragma once
#include "PatchPolicy.h"
#include <vector>
struct cs_insn;
class RandomPLTGOTPolicy :
	public PatchPolicy
{
public:
	static const char * name()
	{
		return "RandomPLTGOTPolicy";
	}

	RandomPLTGOTPolicy():_text_insns(nullptr), _insn_count(0)
	{
		this->setRiskLevel(LOW);
	}
	~RandomPLTGOTPolicy();

	virtual void do_patch() override;
private:
	void getCallPoint(uint64_t pltstub, std::vector<uint64_t> & call_points);
	static void patch_call(uint64_t pltstub, const std::vector<uint64_t> & call_points);
private:
	cs_insn * _text_insns;
	size_t _insn_count;
};

