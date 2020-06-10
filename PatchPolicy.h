#pragma once
#include <iostream>

//代码修改量等级
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
	//改动越小，越精确，check不过的风险越低
	RiskLevel _riskLevel;
	bool _executed;
};
