#include "InstrumentManager.h"
#include "CSEngine.h"
#include "KSEngine.h"
#include "BinaryEditor.h"
#include "BinaryAnalyzer.h"

InstrumentManager * InstrumentManager::_instance = nullptr;

CodeCave InstrumentManager::getCodeCave(unsigned int size)
{
	CodeCave cave;
	for (std::list<CodeCave>::iterator ite = m_caves.begin(); ite != m_caves.end(); ++ite)
	{
		if (ite->size == size)
		{
			cave = *ite;
			m_caves.erase(ite);
			break;
		}
		else if (ite->size > size)
		{
			cave.virtual_addr = ite->virtual_addr;
			cave.size = size;
			ite->size -= size;
			ite->virtual_addr += size;
			break;
		}
	}

	//重新排序，按照地址从小到大排序
	m_caves.sort();

	return cave;
}

void InstrumentManager::rise_stack_patch(const cs_insn * insns, size_t count, const BinaryAnalyzer & analyzer, CodeCave * cave, std::vector<PatchUnit> & patchUnits)
{
	//printf("Cave: addr = 0x%x, size = %lu\n", cave->virtual_addr, cave->size);
	std::vector<uint8_t> jmpToUpCode;
	std::vector<uint8_t> dstCode;
	bool isX32 = BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS32;

	std::string jmpTo = "jmp " + std::to_string(cave->virtual_addr);
	const uint64_t jmpToUpCodeAddr = insns[0].address;
	KSEngine::instance()->assemble(jmpTo.c_str(), jmpToUpCodeAddr, jmpToUpCode);
	if (jmpToUpCode.empty())
	{
		throw 1;
	}

	size_t newInsnBytes = 0;
	//跳过去之后，第一件事就是抬高栈。抬高栈后要把原栈上的内容复制过来，保证参数正确
	/*
	lea rax,[rsp - height] #RAX是新栈顶
	mov rdi,rax
	mov rsi,rsp
	mov rcx,0x10
	rep movsq	qword ptr [rdi], qword ptr [rsi]
	mov rsp,rax
	*/
	//这个高度必须比0x10*DWORD_SIZE要大，否则溢出
	//这里写死拷贝16个栈帧，对于CTF来说应该足够
	uint64_t height = BinaryEditor::instance()->getRandomAligned(0x10, 100);
	std::string riseStack;
	if (isX32)
	{
		riseStack = "lea eax,[esp-" + std::to_string(height+3*4) + "];";//要把edi,esi,ecx的位置也算上，栈才能平衡
		//要将使用到的EDI,ESI,ECX先保存再恢复
		riseStack +=
			"push edi;"
			"push esi;"
			"push ecx;"
			"mov edi,eax;"
			"mov esi,esp;"
			"mov ecx,0x13;"//由于要拷贝EDI,ESI,ECX这3个栈帧，剩余16个才是函数原来的
			"rep movsd	dword ptr es:[edi], dword ptr [esi];"
			"mov esp,eax;"
			"pop ecx;"
			"pop esi;"
			"pop edi";
	}
	else
	{
		riseStack = "lea rax,[rsp-" + std::to_string(height+3*8) + "];";
		riseStack +=
			"push rdi;"
			"push rsi;"
			"push rcx;"
			"mov rdi,rax;"
			"mov rsi,rsp;"
			"mov rcx,0x13;"
			"rep movsq	qword ptr [rdi], qword ptr [rsi];"
			"mov rsp,rax;"
			"pop rcx;"
			"pop rsi;"
			"pop rdi";
	}

	std::vector<uint8_t> riseCode;
	KSEngine::instance()->assemble(riseStack.c_str(), cave->virtual_addr, riseCode);
	if (riseCode.empty())
	{
		throw 1;
	}
	newInsnBytes += riseCode.size();

	//该跳转指令需要占用原来几条指令的空间？
	uint64_t moveInsnBytes = 0;
	size_t insnIndex = 0;
	//std::cout << "getJmpCodeBegin Old insns:" << std::endl;
	std::vector<const cs_insn *> code2translate;
	for (; insnIndex < count; ++insnIndex)
	{
		const cs_insn & insn = insns[insnIndex];
		moveInsnBytes += insn.size;
		code2translate.push_back(&insn);
		if (moveInsnBytes >= jmpToUpCode.size())
		{
			break;
		}
	}

	//在新位置将原来的指令翻译一遍
	std::vector<uint8_t> insnsToMoveCodeNew;
	translate(cave->virtual_addr + newInsnBytes, code2translate, insnsToMoveCodeNew);
	if (insnsToMoveCodeNew.empty())
	{
		throw 1;
	}
	newInsnBytes += insnsToMoveCodeNew.size();

	std::string jmpBack = "jmp " + std::to_string(insns[insnIndex + 1].address);
	std::vector<uint8_t> jmpBackCode;
	KSEngine::instance()->assemble(jmpBack.c_str(), cave->virtual_addr + newInsnBytes, jmpBackCode);
	if (jmpBackCode.empty())
	{
		throw 1;
	}
	newInsnBytes += jmpBackCode.size();

	dstCode.insert(dstCode.end(), riseCode.begin(), riseCode.end());
	dstCode.insert(dstCode.end(), insnsToMoveCodeNew.begin(), insnsToMoveCodeNew.end());
	dstCode.insert(dstCode.end(), jmpBackCode.begin(), jmpBackCode.end());

	/*======================上半段完成=========================*/

	//PATCH代码已放好，现在就差在原函数RET所在BLOCK中插入跳转代码，在函数结尾恢复栈
	std::list<const cs_insn *> retBlockInsns;
	if (!analyzer.getReturnBlock(retBlockInsns) || retBlockInsns.empty())
	{
		//没找到RET BLOCK
		std::cerr << "Function " << std::hex << insns[0].address << " not found RET block." << std::endl;
		throw 1;
	}

	//从后到前为JUMP语句寻找空间
	size_t occupySize = 0;
	uint64_t jmpToLowCodeAddr = 0;
	std::vector<uint8_t> jmpToLowCode;

	code2translate.clear();
	insnsToMoveCodeNew.clear();
	std::cout << "RET-Block code:\n";
	for (auto ite = retBlockInsns.rbegin(); ite != retBlockInsns.rend(); ++ite)
	{
		const uint64_t lowStackAddr = cave->virtual_addr + newInsnBytes;
		const cs_insn * insn = *ite;
		CSEngine::instance()->disasmShow(*insn, false);

		occupySize += insn->size;
		if (insn->id != X86_INS_NOP //NOP直接占用就好了，不需要迁移
			&& insn->id != X86_INS_RET && insn->id != X86_INS_RETF && insn->id != X86_INS_RETFQ //RET放置在最后
			)
		{
			code2translate.push_back(insn);
		}

		std::string jmpLowStack = "jmp " + std::to_string(lowStackAddr);
		KSEngine::instance()->assemble(jmpLowStack.c_str(), insn->address, jmpToLowCode);
		if (jmpToLowCode.empty())
		{
			throw 1;
		}

		if (occupySize >= jmpToLowCode.size())
		{
			jmpToLowCodeAddr = insn->address;
			//std::cout << "*** GOT end-jump address " << std::hex << insn.address << std::endl;
			break;
		}
	}

	//RET BLOCK空间不足，无法插桩
	if (jmpToLowCodeAddr == 0)
	{
		std::cout << "RET block not have enough space to patch." << std::endl;
		//if (BinaryAnalyzer::instance()->getSrcBlock(retBlockInsns[0].address, addressOffset_forDyninst, retBlockInsns, retBlockInsnsCount))
		//{
		//	goto searchRetBlock;
		//}
		throw 1;
	}

	//判断函数头插桩代码与函数结尾插入代码不能重叠
	if (jmpToLowCodeAddr >= jmpToUpCodeAddr && jmpToLowCodeAddr <= jmpToUpCodeAddr + jmpToUpCode.size())
	{
		std::cerr << "!!! Tow jump patch overlaped." << std::endl;
		throw 1;
	}

	std::reverse(code2translate.begin(), code2translate.end());
	//迁移被占用的指令，不包括降栈指令
	translate(cave->virtual_addr + newInsnBytes, code2translate, insnsToMoveCodeNew);
	if (insnsToMoveCodeNew.empty())
	{
		throw 1;
	}
	dstCode.insert(dstCode.end(), insnsToMoveCodeNew.begin(), insnsToMoveCodeNew.end());
	newInsnBytes += insnsToMoveCodeNew.size();

	//降栈
	std::string lowStack = "add " + CSEngine::instance()->espName() + "," + std::to_string(height) + ";";
	lowStack += (*retBlockInsns.rbegin())->mnemonic;
	std::vector<uint8_t> lowstack_code;
	KSEngine::instance()->assemble(lowStack.c_str(), cave->virtual_addr + newInsnBytes, lowstack_code);
	if (lowstack_code.empty())
	{
		throw 1;
	}
	dstCode.insert(dstCode.end(), lowstack_code.begin(), lowstack_code.end());

	if (dstCode.size() > cave->size)
	{
		//空间不足
		return;
	}

	uint64_t patch_addr = cave->virtual_addr;
	cave->size -= dstCode.size();
	cave->virtual_addr += dstCode.size();

	//std::cout << "Patch code:" << std::endl;
	//CSEngine::instance()->disasmShow(jmpToCode, insns[0].address);
	//CSEngine::instance()->disasmShow(dstCode, patch_addr);

	patchUnits.push_back(PatchUnit(patch_addr, dstCode));
	patchUnits.push_back(PatchUnit(jmpToUpCodeAddr, jmpToUpCode));
	patchUnits.push_back(PatchUnit(jmpToLowCodeAddr, jmpToLowCode));
}

void InstrumentManager::rise_stack_patch(const cs_insn * insns, size_t count, const BinaryAnalyzer & analyzer, std::vector<PatchUnit> & patchUnits)
{
	for (std::list<CodeCave>::iterator ite = m_caves.begin(); ite != m_caves.end(); ++ite)
	{
		rise_stack_patch(insns, count, analyzer, &*ite, patchUnits);
		if (!patchUnits.empty())
		{
			return;
		}
	}
	//std::cout << "getJmpCodeCave not enough cave." << std::endl;
	//现有cave不能满足要求，添加新段
	CodeCave * cave = BinaryEditor::instance()->addSection();
	rise_stack_patch(insns, count, analyzer, cave, patchUnits);
	InstrumentManager::instance()->addCodeCave(*cave);
}

void InstrumentManager::insertCodeAtBegin_i(const cs_insn * insns, size_t count, CodeCave * cave, std::vector<PatchUnit> & patchUnits)
{
	std::vector<uint8_t> jmpToCode;
	std::vector<uint8_t> dstCode;
	bool isX32 = BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS32;

	std::string jmpInsn = "jmp " + std::to_string(cave->virtual_addr);
	const uint64_t functionBeginAddr = insns[0].address;
	KSEngine::instance()->assemble(jmpInsn.c_str(), functionBeginAddr, jmpToCode);
	if (jmpToCode.empty())
	{
		throw 1;
	}

	uint64_t jmpBackAddr = 0;
	uint64_t offset = 0;

	{
		//该跳转指令需要占用原来几条指令的空间？
		std::string insnsToMove;
		std::vector<const cs_insn *> code2translate;
		uint64_t moveInsnBytes = 0;
		size_t insnIndex = 0;
		//std::cout << "getJmpCodeBegin Old insns:" << std::endl;
		for (; insnIndex < count; ++insnIndex)
		{
			const cs_insn & insn = insns[insnIndex];
			moveInsnBytes += insn.size;
			code2translate.push_back(&insn);
			//printf("0x%" PRIx64 ":\t%s\t%s\n", insn.address, insn.mnemonic, insn.op_str);
			if (moveInsnBytes >= jmpToCode.size())
			{
				break;
			}
		}
		//在新位置将原来的指令翻译一遍
		std::vector<uint8_t> insnsToMoveCodeNew;
		translate(cave->virtual_addr + offset, code2translate, insnsToMoveCodeNew);
		if (insnsToMoveCodeNew.empty())
		{
			throw 1;
		}
		offset += insnsToMoveCodeNew.size();
		jmpBackAddr = functionBeginAddr + moveInsnBytes;
		dstCode.insert(dstCode.end(), insnsToMoveCodeNew.begin(), insnsToMoveCodeNew.end());
	}
	
	//设置返回地址，模拟call, 32/64代码完全一样
	if (BinaryEditor::instance()->isPIE())
	{
		std::vector<uint8_t> getRIPcode = {
			0xe8, 0,    0,    0,    0, //call 5
			0x5d, //pop rbp/ebp 获得RIP
		};
		//sub rax, 偏移常量 得到IMAGEBASE
		//add rax, got偏移量
		std::string insn;
		if (!isX32)
		{
			insn = "sub rbp, " + std::to_string(cave->virtual_addr + offset + 5);
			insn += ";add rbp," + std::to_string(jmpBackAddr);
			insn += ";push rbp";
			insn += ";sub rbp," + std::to_string(jmpBackAddr);
		}
		else
		{
			insn = "sub ebp, " + std::to_string(cave->virtual_addr + offset + 5);
			insn += ";add ebp," + std::to_string(jmpBackAddr);
			insn += ";push ebp";
			insn += ";sub ebp," + std::to_string(jmpBackAddr);
		}
		std::vector<uint8_t> getImageBaseCode;
		KSEngine::instance()->assemble(insn.c_str(), 0, getImageBaseCode);
		if (getImageBaseCode.empty())
		{
			return;
		}
		offset += getRIPcode.size() + getImageBaseCode.size();
		dstCode.insert(dstCode.end(), getRIPcode.begin(), getRIPcode.end());
		dstCode.insert(dstCode.end(), getImageBaseCode.begin(), getImageBaseCode.end());
	}
	else
	{
		//非PIE，代码是绝对地址，直接压栈就好了
		std::string insn = "push " + std::to_string(jmpBackAddr);
		std::vector<uint8_t> pushRet;
		KSEngine::instance()->assemble(insn.c_str(), 0, pushRet);
		if (pushRet.empty())
		{
			return;
		}
		offset += pushRet.size();
		dstCode.insert(dstCode.end(), pushRet.begin(), pushRet.end());
	}

	//保存寄存器
	if (isX32)
	{
		//pusha 0x60 popa 0x61
		dstCode.push_back(0x60);
		offset += 1;
	}
	else
	{
		//rAX rCX rDX rBX rSP rBP rSI rDI r8 r9
		std::vector<uint8_t> pushallREG = {
			0x50 ,0x51 ,0x52 ,0x53 ,0x54 ,0x55 ,0x56 ,0x57 ,0x41 ,0x50 ,0x41 ,0x51
		};

		dstCode.insert(dstCode.end(), pushallREG.begin(), pushallREG.end());
		offset += pushallREG.size();
	}
	
	//调用provider接口，获取载荷代码
	for (auto provider : _codeProviders)
	{
		std::cout << "+ " << provider->name() << std::endl;
		try
		{
			std::vector<uint8_t> payloadCode;
			provider->getCode(cave->virtual_addr + offset, payloadCode);
			offset += payloadCode.size();
			dstCode.insert(dstCode.end(), payloadCode.begin(), payloadCode.end());
		}
		catch (...)
		{

		}
	}

	//恢复寄存器，将用过的EBP/RBP清零+RET
	if (isX32)
	{
		//popa 0x61
		dstCode.push_back(0x61);
		//xor ebp,ebp
		dstCode.push_back(0x31);
		dstCode.push_back(0xed);
		//ret
		dstCode.push_back(0xc3);
		offset += 2;
	}
	else
	{
		//pop r9 r8 rdi rsi rbp rsp rbx rdx rcx rax ret
		std::vector<uint8_t> popallREG = {
			0x41 ,0x59 ,0x41 ,0x58 ,0x5f ,0x5e ,0x5d ,0x5c ,0x5b,0x5a,0x59 ,0x58, 
			0xC3
		};

		dstCode.insert(dstCode.end(), popallREG.begin(), popallREG.end());
		offset += popallREG.size();
	}

	if (dstCode.size() > cave->size)
	{
		//空间不足
		std::cout << "\e[1;33m""CAVE " << cave->virtual_addr << " has not enough space, try next.""\e[0m" << std::endl;
		return;
	}

	uint64_t patch_addr = cave->virtual_addr;
	cave->size -= dstCode.size();
	cave->virtual_addr += dstCode.size();

	//std::cout << "Patch code:" << std::endl;
	//CSEngine::instance()->disasmShow(jmpToCode, insns[0].address);
	//CSEngine::instance()->disasmShow(dstCode, patch_addr);

	patchUnits.push_back(PatchUnit(patch_addr, dstCode));
	patchUnits.push_back(PatchUnit(functionBeginAddr, jmpToCode));
}

void InstrumentManager::insertCodeAtHere_i(const cs_insn & callInsn, const std::string & asmInsn, CodeCave * cave, std::vector<PatchUnit> & patchUnits)
{
	std::vector<uint8_t> jmpToCode;
	std::vector<uint8_t> dstCode;
	const uint64_t virtual_addr = cave->virtual_addr;
	uint64_t offset = 0;
	const uint64_t jmpBackAddr = callInsn.address + callInsn.size;
	uint64_t jmpAddr = callInsn.address;

	std::string jmpInsn = "jmp " + std::to_string(cave->virtual_addr);
	KSEngine::instance()->assemble(jmpInsn.c_str(), callInsn.address, jmpToCode);
	if (jmpToCode.empty())
	{
		throw 1;
	}

	if (jmpToCode.size() > callInsn.size)
	{
		std::cerr << "Jmp insn bigger than call insn." << std::endl;
		throw 1;
	}

	std::vector<uint8_t> newPatchCode;
	KSEngine::instance()->assemble(asmInsn.c_str(), virtual_addr + offset, newPatchCode);
	if (newPatchCode.empty())
	{
		throw 1;
	}

	offset += newPatchCode.size();
	dstCode.insert(dstCode.end(), newPatchCode.begin(), newPatchCode.end());

	std::string jmpBack = "jmp " + std::to_string(jmpBackAddr);
	std::vector<uint8_t> jmpBackCode;
	KSEngine::instance()->assemble(jmpBack.c_str(), virtual_addr + offset, jmpBackCode);
	if (jmpBackCode.empty())
	{
		throw 1;
	}
	dstCode.insert(dstCode.end(), jmpBackCode.begin(), jmpBackCode.end());


	if (dstCode.size() > cave->size)
	{
		//空间不足
		return;
	}

	uint64_t patch_addr = cave->virtual_addr;
	cave->size -= dstCode.size();
	cave->virtual_addr += dstCode.size();

	patchUnits.push_back(PatchUnit(patch_addr, dstCode));
	patchUnits.push_back(PatchUnit(jmpAddr, jmpToCode));
}

void InstrumentManager::insertCodeAtBegin(const cs_insn * insns, size_t count, std::vector<PatchUnit> & patchUnits)
{
	for (std::list<CodeCave>::iterator ite = m_caves.begin(); ite != m_caves.end(); ++ite)
	{
		insertCodeAtBegin_i(insns, count, &*ite, patchUnits);
		if(!patchUnits.empty())
		{
			return;
		}
	}
	//std::cout << "getJmpCodeCave not enough cave." << std::endl;
	//现有cave不能满足要求，添加新段
	CodeCave * cave = BinaryEditor::instance()->addSection();
	insertCodeAtBegin_i(insns, count, cave, patchUnits);
	addCodeCave(*cave);
}

void InstrumentManager::insertCodeHere(const cs_insn & callInsn, const std::string & asmInsn, std::vector<PatchUnit> & patchUnits)
{
	for (std::list<CodeCave>::iterator ite = m_caves.begin(); ite != m_caves.end(); ++ite)
	{
		insertCodeAtHere_i(callInsn, asmInsn, &*ite, patchUnits);
		if (!patchUnits.empty())
		{
			return;
		}
	}
	//std::cout << "getJmpCodeCave not enough cave." << std::endl;
	//现有cave不能满足要求，添加新段
	CodeCave * cave = BinaryEditor::instance()->addSection();
	insertCodeAtHere_i(callInsn, asmInsn, cave, patchUnits);
	addCodeCave(*cave);
}

void InstrumentManager::translate(uint64_t newaddress, const std::vector<const cs_insn *> & insns, std::vector<uint8_t> & code)
{
	uint64_t offset = 0;
	//逐条指令翻译
	for (auto insn : insns)
	{
		std::vector<uint8_t> per_code;
		if (CSEngine::instance()->isInsnOphasRIP(*insn))
		{
			if (!calc_rip_addressing(*insn, newaddress + offset, per_code))
			{
				printf("0x%" PRIx64 ":\t%s\t%s\n", insn->address, insn->mnemonic, insn->op_str);
				//CSEngine::instance()->disasmShow(insn);
				std::cerr << "OP has EIP/RIP, break." << std::endl;
				throw 1;
			}
		}
		else
		{
			std::string insnsToMove = insn->mnemonic;
			insnsToMove += " ";
			insnsToMove += insn->op_str;
			KSEngine::instance()->assemble(insnsToMove.c_str(), newaddress + offset, per_code);
		}
		offset += per_code.size();
		code.insert(code.end(), per_code.begin(), per_code.end());
	}
}

bool InstrumentManager::calc_rip_addressing(const cs_insn & insn, uint64_t newaddress, std::vector<uint8_t> & outcode)
{
	cs_x86 * x86 = &insn.detail->x86;
	if (x86->op_count == 2)
	{
		cs_x86_op *op2 = &(x86->operands[1]);
		if(op2->mem.base == X86_REG_RIP && op2->mem.disp != 0)
		{
			//复制原指令
			outcode.insert(outcode.end(), insn.bytes, insn.bytes + insn.size);
			uint64_t dst = insn.address + insn.size + op2->mem.disp;
			uint32_t newdisp = dst - (newaddress + insn.size);
			//修改新偏移
			memcpy(outcode.data() + 3, &newdisp, 4);
			return true;
		}
		else
		{
			return false;
		}
	}
	else
	{
		return false;
	}
}

CodeCave * InstrumentManager::addCodeCave(const CodeCave & cave)
{
	m_caves.push_back(cave);
	return &*m_caves.rbegin();
}


