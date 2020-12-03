#pragma once
#include "PatchPolicy.h"
#include "cstddef"
#include <string>

//̧��ջ��Ӧ��ջ����͸�ʽ���ַ�������X32��֧����Щ���ȶ���
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
