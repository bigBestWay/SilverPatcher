#include "MainInjectPolicy.h"
#include "InstrumentManager.h"
#include "CSEngine.h"
#include "BinaryEditor.h"
#include "ClearBackdoorCodeProvider.h"
#include "ModifyLibcCodeProvider.h"
#include "BindShellCodeProvider.h"
#include "Capture01CodeProvider.h"
#include "BinaryAnalyzer.h"
#include "Config.h"

void MainInjectPolicy::do_patch()
{
	label("MainInjectPolicy");
	setProvider();

	uint64_t mainaddr = BinaryAnalyzer::getMainFunction();
	const std::vector<uint8_t> & funcCode = BinaryEditor::instance()->get_content(mainaddr, 100);//100字节足够
	cs_insn * insn = nullptr;
	size_t count = CSEngine::instance()->disasm(funcCode, mainaddr, &insn);
	std::vector<PatchUnit> patchUnits;

	InstrumentManager::instance()->insertCodeAtBegin(insn, count, patchUnits);

	for (const PatchUnit & unit : patchUnits)
	{
#if 1
		std::cout << "Patch code:" << std::endl;
		CSEngine::instance()->disasmShow(unit.code, unit.address);
		std::cout << "Code size: " << unit.code.size() << std::endl;
#endif
		BinaryEditor::instance()->patch_address(unit.address, unit.code);
	}
}

void MainInjectPolicy::setProvider()
{
	if (Config::instance()->isProviderEnabled("ClearBackdoorCodeProvider"))
	{
		InstrumentManager::instance()->addCodeProvider(new ClearBackdoorCodeProvider);
	}
	if (Config::instance()->isProviderEnabled("ModifyLibcCodeProvider"))
	{
		InstrumentManager::instance()->addCodeProvider(new ModifyLibcCodeProvider);
	}
	if (Config::instance()->isProviderEnabled("BindShellCodeProvider"))
	{
		InstrumentManager::instance()->addCodeProvider(new BindShellCodeProvider);
	}
	if (Config::instance()->isProviderEnabled("Capture01CodeProvider"))
	{
		InstrumentManager::instance()->addCodeProvider(new Capture01CodeProvider);
	}
}

/* 使用UNICORN 虚拟执行 */
uint64_t MainInjectPolicy::findMainFunction()const
{
	uint64_t startAddr = BinaryEditor::instance()->entryPoint();
	const std::vector<uint8_t> & funcCode = BinaryEditor::instance()->get_content(startAddr, 100);//100
	cs_insn * insns = nullptr;
	size_t count = CSEngine::instance()->disasm(funcCode, startAddr, &insns);
	for (size_t i = 0; i < count; i++)
	{
		const cs_insn & insn = insns[i];
		//const char movrdi[3] = {0x48,0xc7,0xc7};
	}	
}
