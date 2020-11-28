#pragma once
#include <vector>
#include <stdint.h>

class UnicornEngine
{
public:
	static UnicornEngine * instance()
	{
		if (_instance == nullptr)
		{
			_instance = new UnicornEngine();
		}
		return _instance;
	}

	static void destroy()
	{
		delete _instance;
		_instance = nullptr;
	}

	int simulate_start(const std::vector<uint8_t> & code, uint64_t & main_addr);
private:
	static UnicornEngine * _instance;
	UnicornEngine();
	~UnicornEngine();
};
