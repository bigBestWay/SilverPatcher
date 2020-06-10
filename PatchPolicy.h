#pragma once
#include <iostream>

//�����޸����ȼ�
enum RiskLevel
{
	SECURE,
	LOW,
	MEDIUM,
	HIGH,
	VERYHIGH
};

class PatchPolicy
{
public:
	PatchPolicy() :_riskLevel(VERYHIGH), _executed(false) {}
	~PatchPolicy(){}

	virtual void do_patch() = 0;

	RiskLevel getRiskLevel()const
	{
		return _riskLevel;
	}

	bool Executed() const { return _executed; }
	void Executed(bool val) { _executed = val; }
	void setRiskLevel(RiskLevel level)
	{
		_riskLevel = level;
	}
protected:
	void label(const char * label)
	{
		std::cout << "\033[1m\033[32m" << label << ":\033[0m" << std::endl;
	}
private:
	//�Ķ�ԽС��Խ��ȷ��check�����ķ���Խ��
	RiskLevel _riskLevel;
	bool _executed;
};
