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
