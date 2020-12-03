#pragma once
#include "PatchPolicy.h"
#include "cstddef"
#include <string>

//抬高栈，应对栈溢出和格式化字符串，对X32的支持有些不稳定。
class cs_insn;
class RiseStackPolicy :public PatchPolicy
{
public:
	static const char * name()
	{
		return "RiseStackPolicy";
	}
	virtual void do_patch() override;
	RiseStackPolicy();
	~RiseStackPolicy();
private:
	bool isGccFunction(const std::string & funcName);
};
