#include "StartInjectPolicy.h"
#include "InstrumentManager.h"
#include "CSEngine.h"
#include "BinaryEditor.h"
#include "ClearBackdoorCodeProvider.h"
#include "ModifyLibcCodeProvider.h"
#include "BindShellCodeProvider.h"
#include "Capture01CodeProvider.h"
#include "Config.h"

void StartInjectPolicy::do_patch()
{
	label("StartInjectPolicy");
	setProvider();

	uint64_t startAddr = BinaryEditor::instance()->entryPoint();
	const std::vector<uint8_t> & funcCode = BinaryEditor::instance()->get_content(startAddr, 100);//100×Ö½Ú×ã¹»ÁË
	cs_insn * insn = nullptr;
	size_t count = CSEngine::instance()->disasm(funcCode, startAddr, &insn);
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

void StartInjectPolicy::setProvider()
{
	if (Config::instance()->isProviderEnabled(StartInjectPolicy::name(), "ClearBackdoorCodeProvider"))
	{
		InstrumentManager::instance()->addCodeProvider(new ClearBackdoorCodeProvider);
	}
	if (Config::instance()->isProviderEnabled(StartInjectPolicy::name(), "ModifyLibcCodeProvider"))
	{
		InstrumentManager::instance()->addCodeProvider(new ModifyLibcCodeProvider);
	}
	if (Config::instance()->isProviderEnabled(StartInjectPolicy::name(), "BindShellCodeProvider"))
	{
		InstrumentManager::instance()->addCodeProvider(new BindShellCodeProvider);
	}
	if (Config::instance()->isProviderEnabled(StartInjectPolicy::name(), "Capture01CodeProvider"))
	{
		InstrumentManager::instance()->addCodeProvider(new Capture01CodeProvider);
	}
}
