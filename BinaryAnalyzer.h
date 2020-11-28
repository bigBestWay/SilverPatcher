#pragma once
#include <vector>
#include <map>
#include <cstddef>
#include <cstdint>

enum FIND_BLOCK_RESULT
{
	SUCCESS,
	FUNCTION_NOT_ANALYSE,
	NO_RET_BLOCK
};

class BPatch_function;
class cs_insn;
class BinaryAnalyzer
{
public:
	static BinaryAnalyzer * instance()
	{
		if (_instance == nullptr)
		{
			_instance = new BinaryAnalyzer;
		}
		return _instance;
	}

	static void destroy()
	{
		delete _instance;
		_instance = nullptr;
	}

	bool init(const char * elfname);

	FIND_BLOCK_RESULT getReturnBlock(uint64_t func_address, uint64_t addressOffset_forDyninst, cs_insn *&insns, size_t & count);

	bool getSrcBlock(uint64_t block_address, uint64_t addressOffset_forDyninst, cs_insn *&insns, size_t & count);

	uint64_t getMainFunction();

private:
	static BinaryAnalyzer * _instance;
	BinaryAnalyzer() { _functions = nullptr; }
	~BinaryAnalyzer() {}
	BPatch_function * findFunction_i(uint64_t address)const;
private:
	std::vector<BPatch_function *> * _functions;
	std::map<uint64_t, void *>  _blocks;
};

