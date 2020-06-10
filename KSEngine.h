#pragma once
#include <keystone/keystone.h>
#include <vector>
class KSEngine
{
public:
	static KSEngine * instance()
	{
		if (_instance == nullptr)
		{
			_instance = new KSEngine();
		}
		return _instance;
	}

	static void destroy()
	{
		delete _instance;
		_instance = nullptr;
	}

	void assemble(const char * assembly, uint64_t address, std::vector<uint8_t> & code);
private:
	static KSEngine * _instance;
	KSEngine();
	~KSEngine();
private:
	ks_engine * _ks;
};

