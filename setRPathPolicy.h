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
		//ֱ���޸�RPATHΪ/tmp��Ȼ����/tmpĿ¼�·���libc
		//ʹ���������Լ�����������汾��libc��ʹlibcƫ�Ƽ���ʧЧ
		//�˷��������ױ���⣬���ܻ���������Segment
		//�÷�ʽ��ӵĶΣ�ʣ��ռ��޷�������
		setRiskLevel(VERYHIGH);
	}
	~setRPathPolicy() {};

	virtual void do_patch() override;
};

