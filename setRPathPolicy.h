#pragma once
#include "PatchPolicy.h"
class setRPathPolicy :
	public PatchPolicy
{
public:
	static const char * name()
	{
		return "setRPathPolicy";
	}
	setRPathPolicy()
	{
		//直接修改RPATH为/tmp，然后在/tmp目录下放置libc
		//使程序运行自己编译或其他版本的libc，使libc偏移计算失效
		//此方法极容易被检测，可能会增加两个Segment
		//该方式添加的段，剩余空间无法被利用
		setRiskLevel(VERYHIGH);
	}
	~setRPathPolicy() {};

	virtual void do_patch() override;
};

