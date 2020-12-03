#include "RiseStackPolicy.h"
#include "BinaryEditor.h"
#include "CSEngine.h"
#include "KSEngine.h"
#include "BinaryAnalyzer.h"
#include "Config.h"

/*该策略还是存在一些不稳定因素，可能会导致程序运行不了*/
void RiseStackPolicy::do_patch()
{
	label("RiseStackPolicy");

	Binary::functions_t textFunctions;
	BinaryEditor::instance()->textFunctions(textFunctions);

	std::set<uint64_t> config_funcs;
	Config::instance()->getRiseStackFunc(config_funcs);

	for (size_t i = 0; i < textFunctions.size(); ++i)
	{
		const LIEF::Function & func = textFunctions[i];
		if (isGccFunction(func.name()))
		{
			//std::cout << func << " not handle." << std::endl;
			continue;
		}

		//未配置
		if (!config_funcs.empty() && config_funcs.find(func.address()) == config_funcs.end())
		{
			continue;
		}

		#define NONE                 "\e[0m"
		#define BROWN                "\e[0;33m"
		std::cout << BROWN "**$$[" << func << "]$$**" NONE << std::endl;

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

		BinaryAnalyzer analyzer(func.address(), code);

		cs_insn * insn = nullptr;
		size_t count = CSEngine::instance()->disasm(code, func.address(), &insn);
		if (count <= 1)
		{
			//至少有一条ret
			continue;
		}

		try
		{
			if (count > 0)
			{
				std::vector<PatchUnit> patchUnits;
				InstrumentManager::instance()->rise_stack_patch(insn, count, analyzer, patchUnits);
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

