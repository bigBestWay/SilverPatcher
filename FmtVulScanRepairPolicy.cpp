#include "FmtVulScanRepairPolicy.h"
#include "BinaryEditor.h"
#include <map>
#include "CSEngine.h"
#include "Config.h"

static bool endsWith(const std::string & s, const std::string & sub) 
{
	if (s == sub)
	{
		return true;
	}

	if (s.size() < sub.size())
	{
		return false;
	}

	std::string::size_type pos = s.find(sub);
	if (pos == std::string::npos)
	{
		return false;
	}

	return s.size() - pos == sub.size();
}

FmtVulScanRepairPolicy::FmtVulScanRepairPolicy()
{
	setRiskLevel(MEDIUM);
}

void FmtVulScanRepairPolicy::do_patch()
{
	label("FmtVulScanRepairPolicy");

	scanVul();

	std::map<uint64_t, std::string> patchConfig;
	Config::instance()->getFmtPatchConfig(patchConfig);
	for (std::map<uint64_t, std::string>::const_iterator ite = patchConfig.begin(); ite != patchConfig.end(); ++ite)
	{
		int fmtParamIndex = getFmtParamIndex(ite->second);
		const std::vector<uint8_t> code = BinaryEditor::instance()->get_content(ite->first, 10);//10字节读取一个跳转指令足够
		cs_insn * insns = 0;
		size_t count = CSEngine::instance()->disasm(code, ite->first, &insns);
		if (count > 0)
		{
			if (insns[0].id != X86_INS_CALL)
			{
				std::cerr << "Config error, not call." << std::endl;
				continue;
			}

			uint64_t entry = insns[0].detail->x86.operands[0].imm;
			std::string insnStr = generateNewCode(fmtParamIndex, entry);
			std::vector<PatchUnit> patchUnits;
			InstrumentManager::instance()->insertCodeHere(insns[0], insnStr, patchUnits);
			for (auto u : patchUnits)
			{
				std::cout << "PATCH:" << std::endl;
				CSEngine::instance()->disasmShow(u.code, u.address);
				BinaryEditor::instance()->patch_address(u.address, u.code);
			}
		}
	}
}

const cs_x86_op * FmtVulScanRepairPolicy::findSrcOp(const cs_insn * insns, size_t & index, const cs_x86_op * op)
{
	cs_x86_op * result = nullptr;
	for (size_t i = index; (int64_t)i >= 0; --i)
	{
		const cs_insn & insn_back = insns[i];
		if (insn_back.id == X86_INS_RET || insn_back.id == X86_INS_RETF || insn_back.id == X86_INS_RETFQ || insn_back.id == X86_INS_JMP)
		{
			break;
		}

		if (insn_back.id == X86_INS_MOV || insn_back.id == X86_INS_LEA)
		{
			const cs_x86_op * op1 = &insn_back.detail->x86.operands[0];
			if (std::memcmp(op1, op, sizeof(cs_x86_op)) == 0)
			{
				//CSEngine::instance()->disasmShow(insn_back);
				result = &insn_back.detail->x86.operands[1];
				index = i;
				break;
			}
		}
	}
	return result;
}

std::string FmtVulScanRepairPolicy::generateNewCode(int fmtParamIndex, uint64_t entryPoint)
{
	//printf(x) --> printf("%s", x)
	bool isX32 = BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS32;
	if (isX32)
	{
		std::string insn = "lea eax,[esp-0x100];"
			"push edi;"
			"push esi;"
			"push ecx;"
			"mov edi,eax;"
			"mov esi,esp;";
		insn += "mov ecx,";
		insn += std::to_string(fmtParamIndex + 3);//加3是因为把push的edi,esi,ecx也一起复制了
		insn +=	";rep movsd	dword ptr es:[edi], dword ptr [esi];"
			"mov esp,eax;"
			"pop ecx;"
			"pop esi;"
			"pop edi";
		//在esp+0x90位置放置字符串"%s"
		insn += "lea eax,[esp+0x90];";
		insn += "mov dword ptr [eax], 0x7325;";//%s
		if (fmtParamIndex == 1)
		{
			//原格式化串下移
			insn += "xchg dword ptr [esp], eax;";
			insn += "mov dword ptr [esp+4],eax;";
		}
		else
		{
			insn += "xchg dword ptr [esp + " + std::to_string((fmtParamIndex - 1)*4) + "], eax;";
			insn += "mov dword ptr [esp + " + std::to_string(fmtParamIndex*4) + "],eax;";
		}

		insn += "call " + std::to_string(entryPoint);
		insn += ";add esp,0x100";//调用完成，降下栈
		return insn;
	}
	else
	{
		std::string insn = "push 0x7325;";//把%s压入栈顶
		switch (fmtParamIndex)
		{
		case 1:
			insn += "push rsi;push rdi;";
			insn += "lea rsi, [rsp+0x10];";
			insn += "xchg rsi,rdi;";
			break;
		case 2:
			insn += "push rsi;push rdx;";
			insn += "lea rdx,[rsp+0x10];";
			insn += "xchg rsi,rdx;";
			break;
		case 3:
			insn += "push rdx;push rcx;";
			insn += "lea rcx,[rsp+0x10];";
			insn += "xchg rcx,rdx;";
			break;
		case 4:
			insn += "push rcx;push r8;";
			insn += "lea r8, [rsp+0x10];";
			insn += "xchg r8, rcx;";
			break;
		case 5:
			insn += "push r8;push r9;";
			insn += "lea r9,[rsp+0x10];";
			insn += "xchg r8,r9;";
			break;
		default:
			return "";
		}
		insn += "call " + std::to_string(entryPoint) + ";";
		switch (fmtParamIndex)
		{
		case 1:
			insn += "pop rdi;pop rsi;";
			break;
		case 2:
			insn += "pop rdx;pop rsi;";
			break;
		case 3:
			insn += "pop rcx;pop rdx;";
			break;
		case 4:
			insn += "pop r8;pop rcx;";
			break;
		case 5:
			insn += "pop r9;pop r8;";
			break;
		default:
			return "";
		}
		insn += "sub rsp, 8";
		return insn;
	}
}

void FmtVulScanRepairPolicy::warn()
{

}

void FmtVulScanRepairPolicy::scanVul()
{
	std::map<uint64_t, std::string> stub2symbol;

	const char * fmtFunction[] = {
		"printf",
		"fprintf",
		"snprintf_chk",
		"sprintf_chk",
		"snprintf",
		"fnprintf",
		"sprintf",
		"fprintf",
		"dprintf",
		"printf_chk",
		nullptr
	};

	for (int i = 0; fmtFunction[i]; ++i)
	{
		try
		{
			Relocation * reloc = BinaryEditor::instance()->getRelocation(fmtFunction[i]);
			if (reloc == nullptr)
			{
				continue;
			}
			uint64_t addr = this->getCallEntryPoint(reloc);
			stub2symbol[addr] = fmtFunction[i];
		}
		catch (...)
		{
		}
	}

	if (stub2symbol.empty())
	{
		std::cout << "No fmt functions found." << std::endl;
		return;
	}

	bool isX32 = BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS32;

	const Section & textSec = BinaryEditor::instance()->textSection();
	cs_insn * insns = nullptr;
	size_t count = CSEngine::instance()->disasm(textSec.content(), textSec.virtual_address(), &insns);
	for (size_t index = 0; index < count; ++index)
	{
		const cs_insn & insn = insns[index];
		if (insn.id != X86_INS_CALL)
		{
			continue;
		}

		const cs_x86 & x86 = insn.detail->x86;
		if (x86.op_count != 1 || x86.operands[0].type != X86_OP_IMM)
		{
			continue;
		}

		const uint64_t callOp = x86.operands[0].imm;
		std::map<uint64_t, std::string>::const_iterator ite = stub2symbol.find(callOp);
		if (ite == stub2symbol.end())
		{
			continue;
		}

		//这个call就是调用格式化函数
		size_t back_index = index - 1;
		const std::string & sym_name = ite->second;
		const cs_x86_op * src = nullptr;
		int fmtParamIndex = 0;
		for (; (int64_t)back_index >= 0; --back_index)
		{
			const cs_insn & insn_back = insns[back_index];
			if (insn_back.id == X86_INS_RET || insn_back.id == X86_INS_RETF || insn_back.id == X86_INS_RETFQ || insn_back.id == X86_INS_JMP)
			{
				break;
			}

			if (insn_back.id != X86_INS_MOV && insn_back.id != X86_INS_LEA && insn_back.id != X86_INS_PUSH)
			{
				continue;
			}

			std::string op1str = insn_back.op_str;
			std::string::size_type pos = op1str.find(',');
			op1str = op1str.substr(0, pos);
			if (endsWith(sym_name, "snprintf_chk"))
			{
				if (endsWith(op1str, "r8") || endsWith(op1str, "r8d")
					|| (isX32 && endsWith(op1str, "[esp + 0x10]")))
				{
					src = &insn_back.detail->x86.operands[1];
					fmtParamIndex = 5;
					break;
				}
			}
			else if (endsWith(sym_name, "sprintf_chk"))
			{
				if (endsWith(op1str, "rcx") || (endsWith(op1str, "ecx") && !isX32)
					|| (isX32 && endsWith(op1str, "[esp + 0xc]")))
				{
					src = &insn_back.detail->x86.operands[1];
					fmtParamIndex = 4;
					break;
				}
			}
			else if (endsWith(sym_name, "snprintf") || endsWith(sym_name, "fnprintf"))
			{
				if (endsWith(op1str, "rdx") || (endsWith(op1str, "edx") && !isX32)
					|| (isX32 && endsWith(op1str, "[esp + 8]")))
				{
					src = &insn_back.detail->x86.operands[1];
					fmtParamIndex = 3;
					break;
				}
			}
			else if (endsWith(sym_name, "sprintf") || endsWith(sym_name, "fprintf")
				|| endsWith(sym_name, "dprintf") || endsWith(sym_name, "printf_chk"))
			{
				if (endsWith(op1str, "rsi") || (endsWith(op1str, "esi") && !isX32)
					|| (isX32 && endsWith(op1str, "[esp + 4]")))
				{
					fmtParamIndex = 2;
					src = &insn_back.detail->x86.operands[1];
					break;
				}
			}
			else if (endsWith(sym_name, "printf"))
			{
				if (endsWith(op1str, "rdi") || (endsWith(op1str, "edi") && !isX32)
					|| (isX32 && endsWith(op1str, "[esp]")))
				{
					fmtParamIndex = 1;
					src = &insn_back.detail->x86.operands[1];
					break;
				}
				else if (isX32 && insn_back.id == X86_INS_PUSH)
				{
					fmtParamIndex = 1;
					src = &insn_back.detail->x86.operands[0];
					break;
				}
			}
		}

		if (src == nullptr)
		{
			continue;
		}

		/*
		std::cout << "Find a " << sym_name << " call:" << std::endl;
		CSEngine::instance()->disasmShow(insn, false);
		std::cout << "Trace fmt param:" << std::endl;
		CSEngine::instance()->disasmShow(insns[back_index], false);
		*/

		do
		{
			//找到了对格式化参数的赋值指令，尝试再向上查找这个值的源
			if (src->type == X86_OP_IMM)
			{
				Segment * segment = nullptr;
				if (BinaryEditor::instance()->getSegment(src->imm, segment))
				{
					if (!segment->has(ELF_SEGMENT_FLAGS::PF_W))//段不可写，安全
					{
						break;
					}
					else
					{
						std::cout << sym_name << " fmt param is on segment with W:" << std::endl;
						CSEngine::instance()->disasmShow(insn, false);
						break;
					}
				}
			}
			else if (src->type == X86_OP_MEM)
			{
				unsigned int base = src->mem.base;
				if (base == X86_REG_EBP || base == X86_REG_RBP || base == X86_REG_ESP || base == X86_REG_RSP)//栈上的值作为格式化串
				{
					std::cout << sym_name << " fmt param is on stack:" << std::endl;
					CSEngine::instance()->disasmShow(insn, false);
					break;
				}
			}

			src = findSrcOp(insns, back_index, src);
		} while (src);
	}
	cs_free(insns, count);
}

int FmtVulScanRepairPolicy::getFmtParamIndex(const std::string & sym_name)
{
	int fmtParamIndex = 0;
	if (endsWith(sym_name, "snprintf_chk"))
	{
		fmtParamIndex = 5;
	}
	else if (endsWith(sym_name, "sprintf_chk"))
	{
		fmtParamIndex = 4;
	}
	else if (endsWith(sym_name, "snprintf") || endsWith(sym_name, "fnprintf"))
	{
		fmtParamIndex = 3;
	}
	else if (endsWith(sym_name, "sprintf") || endsWith(sym_name, "fprintf")
		|| endsWith(sym_name, "dprintf") || endsWith(sym_name, "printf_chk"))
	{
		fmtParamIndex = 2;
	}
	else if (endsWith(sym_name, "printf"))
	{
		fmtParamIndex = 1;
	}
	return fmtParamIndex;
}
