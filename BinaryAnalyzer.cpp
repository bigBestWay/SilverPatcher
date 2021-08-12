#include "BinaryAnalyzer.h"
#include "CSEngine.h"
#include "BinaryEditor.h"
#include "LibelfEditor.h"

BinaryAnalyzer::BasicBlock * BinaryAnalyzer::get_block(uint64_t address, bool new_not_found)
{
	auto ite = _blocksRel.find(address);
	if (ite != _blocksRel.end())
	{
		return ite->second;
	}
	else
	{
		if (!new_not_found)
		{
			return nullptr;
		}
		else
		{
			BasicBlock * bb = new BasicBlock;
			_blocksRel[address] = bb;
			bb->start = address;
			return bb;
		}
	}
}

BinaryAnalyzer::BinaryAnalyzer(uint64_t address, const std::vector<uint8_t> & code)
{
	_insns = nullptr;
	_functionAddr = address;

	_insn_count = CSEngine::instance()->disasm(code, address, &_insns);
	if (_insn_count <= 1)
	{
		//至少有一条ret
		return;
	}

	//为防止有do{}while(0)这种跳转在后的情况，再循环一遍补齐相关内容，第一遍block是找齐的了，补齐相关指令数据
	for (int x = 0; x < 2; ++x)
	{
		uint64_t currentBlock = address;
		for (size_t i = 0; i < _insn_count; ++i)
		{
			const cs_insn & insn = _insns[i];
			BasicBlock * cur = get_block(insn.address, false); //是否已存在block
			if (cur == nullptr)
			{
				cur = get_block(currentBlock);
			}
			else
			{
				currentBlock = insn.address;
			}

			//std::cout << "CUR BLOCK addr : " << std::hex << cur->start << std::endl;

			if (std::find(cur->insns.begin(), cur->insns.end(), &insn) == cur->insns.end())
				cur->insns.push_back(&insn);

			if (CSEngine::is_jmp_grp_type(insn))
			{
				//无条件跳转
				if (insn.id == X86_INS_JMP || insn.id == X86_INS_LJMP)
				{
					uint64_t dst = std::strtoul(insn.op_str, nullptr, 16);
					BasicBlock * bb = get_block(dst);
					if (std::find(bb->upflow.begin(), bb->upflow.end(), cur) == bb->upflow.end())
						bb->upflow.push_back(cur);
					if (std::find(cur->downflow.begin(), cur->downflow.end(), bb) == cur->downflow.end())
						cur->downflow.push_back(bb);
				}
				else
				{
					uint64_t dst = std::strtoul(insn.op_str, nullptr, 16);
					BasicBlock * bb1 = get_block(dst);
					BasicBlock * bb2 = get_block(insn.address + insn.size);
					if (std::find(bb1->upflow.begin(), bb1->upflow.end(), cur) == bb1->upflow.end())
						bb1->upflow.push_back(cur);
					if (std::find(bb2->upflow.begin(), bb2->upflow.end(), cur) == bb2->upflow.end())
						bb2->upflow.push_back(cur);
					if (std::find(cur->downflow.begin(), cur->downflow.end(), bb1) == cur->downflow.end())
						cur->downflow.push_back(bb1);
					if (std::find(cur->downflow.begin(), cur->downflow.end(), bb2) == cur->downflow.end())
						cur->downflow.push_back(bb2);
				}

				currentBlock = insn.address + insn.size;
			}
		}
	}
}

BinaryAnalyzer::~BinaryAnalyzer()
{
	cs_free(_insns, _insn_count);
	for (auto ite : _blocksRel)
	{
		delete ite.second;
	}
}

bool BinaryAnalyzer::getReturnBlock(std::list<const cs_insn *> & insns)const
{
	std::list<const BasicBlock *> bblist;
	for (const auto & i : _blocksRel)
	{
		const BasicBlock * bb = i.second;
		if (bb->downflow.empty())
		{
			const cs_insn * insn = *bb->insns.crbegin();
			if (CSEngine::is_ret_grp_type(*insn))
			{
				bblist.push_back(bb);
			}
		}
	}

	if (bblist.size() != 1)
	{
		std::cerr << "WTF. multi-return-block found " << bblist.size() << std::endl;
		return false;
	}

	const std::vector<const cs_insn *> & tmp = (*bblist.begin())->insns;
	insns.insert(insns.end(), tmp.begin(), tmp.end());

	return true;
}

//TODO
const BinaryAnalyzer::BasicBlock * BinaryAnalyzer::getSrcBlock(uint64_t block_address)
{
	return nullptr;
}

