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

//API�Դ���ֻ�ܷ���һ����ʵ�ʿ����ж��Դ��WTF
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

//addressOffset_forDyninst ��PIE������LIEF��Ӷ��Ժ����Լ��������ȷ�ĵ�ַ����dyninst���ᣬ��Ҫͨ���˱����ֶ�����������
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
	const PatchFunction::Blockset &blks = patchFunc->exitBlocks();//dyninst��BUG��BLOCK���ܲ��ᱻ��ȷʶ�𣬵�������©��
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

//��ǰRET BLOCK�ռ䲻��ʱ����ǰ����һ����ִ�е��˵�ǰ��BLOCK
bool BinaryAnalyzer::getSrcBlock(uint64_t block_address, uint64_t addressOffset_forDyninst, cs_insn *&insnsOut, size_t & count)
{
	insnsOut = nullptr;
	count = 0;
	std::map<uint64_t, void *>::const_iterator ite = _blocks.find(block_address - addressOffset_forDyninst);
	if (ite != _blocks.end())
	{
		PatchBlock * retBlock = (PatchBlock *)ite->second;
		PatchEdge * edge = retBlock->findSource(Dyninst::ParseAPI::EdgeTypeEnum::COND_TAKEN);
		if (edge)//��Щд������cookie�������ͨ����leava;ret��������������cookieУ�����ֱ�Ӹɵ�
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
				//��xor	rcx, qword ptr fs:[0x28]; xor	rax, qword ptr fs:[0x28]����ʽ��ֻ�мĴ�����1�ֽ��б仯
				#define REG_CODE_RESERVE 0
				#define REG_CODE_INDEX 3 
				//CSEngine::hexDump(insn->second.ptr(), insn->second.size());
				const uint8_t checkCookie[9] = { 0x64 ,0x48 ,0x33 ,REG_CODE_RESERVE ,0x25 ,0x28 ,00 ,00 ,00 };
				uint8_t insnBytes[9] = { 0 };
				std::memcpy(insnBytes, insn->second.ptr(), 9);
				insnBytes[REG_CODE_INDEX] = REG_CODE_RESERVE;
				if (std::memcmp(checkCookie, insnBytes, 9) == 0)
				{
					//9��NOP����checkCookie�����LEAVE;RET
					const std::vector<uint8_t> hardcode = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC9, 0xC3 };
					//ֱ�������ｫ����ָ��PATCH��
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
			//�������ϳ����Ĵ�����ַ1��ָ����������ת��2
			//ֱ����ת��src�����ж�������patch��Ҫ��patch
			std::vector<PatchEdge *> edgeList;
			findSource(retBlock, Dyninst::ParseAPI::EdgeTypeEnum::DIRECT, edgeList);
			if (edgeList.empty() || edgeList.size() > 1)
			{
				//���Դ��������ڸ��ӣ�̫�Ѹ㣬������
				return false;
			}

			PatchBlock * srcBlock = edgeList[0]->src();
			if (srcBlock)
			{
				//std::cout << srcBlock->disassemble() << std::endl;
				std::vector<uint8_t> codes;
				PatchBlock::Insns srcBlockInsns, retBlockInsns;
				srcBlock->getInsns(srcBlockInsns);
				//ȥ����β���õ�JMP��䣬֮������BLOCK����ϲ�
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
		//start���һ��call����
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

