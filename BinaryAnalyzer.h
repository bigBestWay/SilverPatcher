#pragma once
#include <list>
#include <vector>
#include <map>
#include <cstddef>
#include <cstdint>

class cs_insn;
class BinaryAnalyzer
{
public:
	struct BasicBlock
	{
		uint64_t start;
		std::vector<const cs_insn *> insns;
		std::vector<BasicBlock *> upflow;
		std::vector<BasicBlock *> downflow;
	};

	BinaryAnalyzer(uint64_t address, const std::vector<uint8_t> & code);
	~BinaryAnalyzer();

	const BasicBlock * getSrcBlock(uint64_t block_address);

	static uint64_t getMainFunction();

	bool getReturnBlock(std::list<const cs_insn *> & insns)const;

private:
	BasicBlock * get_block(uint64_t address, bool new_not_found = true);
private:
	std::map<uint64_t, BasicBlock *> _blocksRel;
	cs_insn * _insns;
	size_t _insn_count;
	uint64_t _functionAddr;
};

