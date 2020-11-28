#include "BinaryAnalyzer.h"
#include "BPatch.h"
#include "BPatch_basicBlock.h"
#include "BPatch_flowGraph.h"
#include "BPatch_function.h"
#include "BPatch_object.h"
#include "BPatch_point.h"
#include "BPatch_snippet.h"

#include "PatchMgr.h"
#include "PatchModifier.h"
#include "Point.h"
#include "Snippet.h"
#include "Buffer.h"

#include "CSEngine.h"
#include "BinaryEditor.h"
#include "UnicornEngine.h"

using namespace Dyninst;
using namespace Dyninst::InstructionAPI;
using namespace Dyninst::PatchAPI;

BinaryAnalyzer * BinaryAnalyzer::_instance = nullptr;

BPatch_function * BinaryAnalyzer::findFunction_i(uint64_t address) const
{
	if (_functions)
	{
		for (auto it = _functions->begin(); it != _functions->end(); ++it)
		{
			PatchFunction *func = convert(*it);
			if (func->addr() == address)
			{
				return *it;
			}
		}
	}
	return nullptr;
}

//API自带的只能返回一个，实际可以有多个源，WTF
static void findSource(PatchBlock * blk, ParseAPI::EdgeTypeEnum type, std::vector<PatchEdge *> & src)
{
	PatchBlock::edgelist edges = blk->sources();
	for (auto edge : edges)
	{
		if (edge->type() == type)
		{
			src.push_back(edge);
		}
	}
}

bool BinaryAnalyzer::init(const char * elfname)
{
	if(_functions != nullptr)
		return true;
		
	BPatch *bpatch = new BPatch;
	BPatch_addressSpace *app = bpatch->openBinary(elfname);
	if (app == NULL)
	{
		return false;
	}

	BPatch_image *appImage = app->getImage();
	std::vector<BPatch_module *> * modules = appImage->getModules();
	for (auto it = modules->begin(); it != modules->end(); ++it)
	{
		BPatch_module * module = *it;
		_functions = module->getProcedures();
	}
	return true;
}

//addressOffset_forDyninst 在PIE场景下LIEF添加段以后，它自己会调整正确的地址，而dyninst不会，需要通过此变量手动解决这个问题
FIND_BLOCK_RESULT BinaryAnalyzer::getReturnBlock(uint64_t address, uint64_t addressOffset_forDyninst, cs_insn *&insnsOut, size_t & count)
{
	insnsOut = nullptr;
	count = 0;
	BPatch_function * function = findFunction_i(address - addressOffset_forDyninst);
	if (function == nullptr)
	{
		return FUNCTION_NOT_ANALYSE;
	}

	PatchFunction * patchFunc = convert(function);
	const PatchFunction::Blockset &blks = patchFunc->exitBlocks();//dyninst有BUG，BLOCK可能不会被正确识别，导致有遗漏。
	for (auto it = blks.begin(); it != blks.end(); ++it)
	{
		PatchBlock * block = *it;
		//printf("getFunctionReturnBlock>>Block disas(%u):\n%s", block->size(), block->disassemble().c_str());
		PatchBlock::Insns dynInsns;
		block->getInsns(dynInsns);
		if (dynInsns.empty())
		{
			continue;
		}

		std::vector<uint8_t> codes;
		for (auto insn = dynInsns.begin(); insn != dynInsns.end(); insn++)
		{
			codes.insert(codes.end(), (uint8_t *)insn->second.ptr(), (uint8_t *)insn->second.ptr() + insn->second.size());
		}
		
		cs_insn * tmpinsn = nullptr;
		size_t n = CSEngine::instance()->disasm(codes, block->start() + addressOffset_forDyninst, &tmpinsn);
		if (n > 0)
		{
			switch(tmpinsn[n-1].id)
			{
			case X86_INS_RET:
			case X86_INS_RETF:
			case X86_INS_RETFQ:
			{
				insnsOut = tmpinsn;
				count = n;
				//std::cout << "getFunctionReturnBlock>>RET BLOCK:" << std::endl;
				//CSEngine::instance()->disasmShow(codes, block->start() + addressOffset_forDyninst);
				_blocks[block->start()] = block;
				return SUCCESS;
			}
			default:
				break;
			}
		}
	}
	return NO_RET_BLOCK;
}

//当前RET BLOCK空间不足时，向前查找一定能执行到此的前向BLOCK
bool BinaryAnalyzer::getSrcBlock(uint64_t block_address, uint64_t addressOffset_forDyninst, cs_insn *&insnsOut, size_t & count)
{
	insnsOut = nullptr;
	count = 0;
	std::map<uint64_t, void *>::const_iterator ite = _blocks.find(block_address - addressOffset_forDyninst);
	if (ite != _blocks.end())
	{
		PatchBlock * retBlock = (PatchBlock *)ite->second;
		PatchEdge * edge = retBlock->findSource(Dyninst::ParseAPI::EdgeTypeEnum::COND_TAKEN);
		if (edge)//有些写法是在cookie检查条件通过后leava;ret，因此这种情况下cookie校验可以直接干掉
		{
			PatchBlock * srcBlock = edge->src();
			if (srcBlock)
			{
				PatchBlock::Insns srcBlockInsns;
				srcBlock->getInsns(srcBlockInsns);
				auto insn = srcBlockInsns.rbegin();
				//std::cout << "getFunctionReturnBlock " << insn->second.format() << " " << insn->second.size() << std::endl;
				++insn;
				if (insn == srcBlockInsns.rend())
				{
					return false;
				}
				//std::cout << "getFunctionReturnBlock " << insn->second.format() << " " << insn->second.size() << std::endl;
				//有xor	rcx, qword ptr fs:[0x28]; xor	rax, qword ptr fs:[0x28]等形式，只有寄存器的1字节有变化
				#define REG_CODE_RESERVE 0
				#define REG_CODE_INDEX 3 
				//CSEngine::hexDump(insn->second.ptr(), insn->second.size());
				const uint8_t checkCookie[9] = { 0x64 ,0x48 ,0x33 ,REG_CODE_RESERVE ,0x25 ,0x28 ,00 ,00 ,00 };
				uint8_t insnBytes[9] = { 0 };
				std::memcpy(insnBytes, insn->second.ptr(), 9);
				insnBytes[REG_CODE_INDEX] = REG_CODE_RESERVE;
				if (std::memcmp(checkCookie, insnBytes, 9) == 0)
				{
					//9个NOP换掉checkCookie，外加LEAVE;RET
					const std::vector<uint8_t> hardcode = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC9, 0xC3 };
					//直接在这里将这条指令PATCH掉
					BinaryEditor::instance()->patch_address(insn->first + addressOffset_forDyninst, hardcode);
					cs_insn * tmpinsn = nullptr;
					count = CSEngine::instance()->disasm(hardcode, insn->first + addressOffset_forDyninst, &tmpinsn);
					insnsOut = tmpinsn;
					return true;
				}
			}
		}
		else
		{
			//0: xxxxx
			//1: jmp 2
			//2: leave
			//3: ret
			//对于以上场景的处理，地址1的指令无条件跳转到2
			//直接跳转的src可以有多个，如果patch就要都patch
			std::vector<PatchEdge *> edgeList;
			findSource(retBlock, Dyninst::ParseAPI::EdgeTypeEnum::DIRECT, edgeList);
			if (edgeList.empty() || edgeList.size() > 1)
			{
				//多个源的情况过于复杂，太难搞，不搞了
				return false;
			}

			PatchBlock * srcBlock = edgeList[0]->src();
			if (srcBlock)
			{
				//std::cout << srcBlock->disassemble() << std::endl;
				std::vector<uint8_t> codes;
				PatchBlock::Insns srcBlockInsns, retBlockInsns;
				srcBlock->getInsns(srcBlockInsns);
				//去掉结尾无用的JMP语句，之后将两个BLOCK代码合并
				srcBlockInsns.erase(srcBlockInsns.rbegin()->first);
				retBlock->getInsns(retBlockInsns);
				for (auto insn : srcBlockInsns)
				{
					codes.insert(codes.end(), (uint8_t *)insn.second.ptr(), (uint8_t *)insn.second.ptr() + insn.second.size());
				}

				for (auto insn : retBlockInsns)
				{
					codes.insert(codes.end(), (uint8_t *)insn.second.ptr(), (uint8_t *)insn.second.ptr() + insn.second.size());
				}

				cs_insn * tmpinsn = nullptr;
				count = CSEngine::instance()->disasm(codes, srcBlockInsns.begin()->first + addressOffset_forDyninst, &tmpinsn);
				insnsOut = tmpinsn;
				return true;
			}
		}
	}
	return false;
}

uint64_t BinaryAnalyzer::getMainFunction()
{
	uint64_t entrypoint = BinaryEditor::instance()->entryPoint();
	const std::vector<uint8_t> & code = BinaryEditor::instance()->get_content(entrypoint, 0x1000);
	cs_insn * tmpinsn = nullptr;
	size_t n = CSEngine::instance()->disasm(code, entrypoint, &tmpinsn);

	std::vector<uint8_t> simulate_code;
	size_t i = 0;
	for (; i < n; ++i)
	{
		const cs_insn & insn = tmpinsn[i];
		//CSEngine::instance()->disasmShow(insn);
		//start里就一个call函数
		if (insn.id == X86_INS_CALL)
		{
			break;
		}
		simulate_code.insert(simulate_code.end(), insn.bytes, insn.bytes + insn.size);
	}

	cs_free(tmpinsn, n);

	uint64_t mainaddr = 0;
	if (UnicornEngine::instance()->simulate_start(simulate_code, mainaddr) != 0)
	{
		std::cerr << "simulate_start fail.\n";
	}

	std::cout << "get main " << std::hex << mainaddr << std::endl;

	return mainaddr;
}

