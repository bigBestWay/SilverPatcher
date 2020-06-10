#include "RiseStackPolicy.h"
#include "BinaryEditor.h"
#include "CSEngine.h"
#include "KSEngine.h"

/*该策略还是存在一些不稳定因素，可能会导致程序运行不了*/
void RiseStackPolicy::do_patch()
{
	label("RiseStackPolicy");

	Binary::functions_t textFunctions;
	BinaryEditor::instance()->textFunctions(textFunctions);
	for (size_t i = 0; i < textFunctions.size(); ++i)
	{
		const LIEF::Function & func = textFunctions[i];
		if (isGccFunction(func.name()))
		{
			//std::cout << func << " not handle." << std::endl;
			continue;
		}

		std::cout << "**$$[" << func << "]$$**" << std::endl;

		uint64_t size = func.size();
		if (size == 0)
		{
			if (i + 1 < textFunctions.size())
			{
				size = textFunctions[i + 1].address() - func.address();
			}
			else
			{
				std::cerr << func << " last, size=0" << std::endl;
				continue;
			}
		}
		const std::vector<uint8_t> & code = BinaryEditor::instance()->get_content(func.address(), size);
		cs_insn * insn = nullptr;
		size_t count = CSEngine::instance()->disasm(code, func.address(), &insn);
		if (count <= 1)
		{
			//至少有一条ret
			continue;
		}

		try
		{
			patchFuncBegin(insn, count);
		}
		catch (int & e)
		{
			//终止跳转
			cs_free(insn, count);
			continue;
		}


		cs_free(insn, count);
	}
}

RiseStackPolicy::RiseStackPolicy()
{
	setRiskLevel(MEDIUM);
}

RiseStackPolicy::~RiseStackPolicy()
{

}

void RiseStackPolicy::patchFuncBegin(cs_insn * insns, size_t count)
{
	if (count > 0)
	{
		std::vector<PatchUnit> patchUnits;
		uint64_t addressOffset_forDyninst = 0;
		if (BinaryEditor::instance()->isPIE())//对PIE场景的特殊处理
		{
			addressOffset_forDyninst = DEFAULT_SECTION_SIZE;
		}

		InstrumentManager::instance()->generateJmpCode(insns, count, addressOffset_forDyninst, patchUnits);
		for (const PatchUnit & unit : patchUnits)
		{
		#if 1
			std::cout << "Patch code:" << std::endl;
			CSEngine::instance()->disasmShow(unit.code, unit.address);
		#endif
			BinaryEditor::instance()->patch_address(unit.address, unit.code);
		}
	}
}

bool RiseStackPolicy::isGccFunction(const std::string & funcName)
{
	const char * gccFunctions[] = {
		"register_tm_clones",
		"_start",
		"deregister_tm_clones",
		"frame_dummy",
		"__x86.get_pc_thunk.",
		"__do_global_dtors_aux",
		"__libc_csu_init",
		"__libc_csu_fini",
		"__dt_fini_array",
		"__dt_init_array",
		"__stack_chk_fail_local",
		"_fini",
		"__dt_fini",
		NULL
	};

	for (int i = 0; gccFunctions[i]; ++i)
	{
		if (funcName == gccFunctions[i])
		{
			return true;
		}
		else if (funcName.find(gccFunctions[i]) == 0 && i == 4)//对__x86.get_pc_thunk.特殊处理
		{
			return true;
		}
	}
	return false;
}

