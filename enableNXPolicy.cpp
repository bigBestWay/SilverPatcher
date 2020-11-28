#include "enableNXPolicy.h"
#include "BinaryEditor.h"

enableNXPolicy::enableNXPolicy()
{
	setRiskLevel(SECURE);
}

void enableNXPolicy::do_patch()
{
	label("enableNXPolicy");
	if (BinaryEditor::instance()->hasNX())
	{
		std::cout << "NX already supported." << std::endl;
		return;
	}

	BinaryEditor::instance()->enableNX();
	std::cout << "Add NX support." << std::endl;
}
