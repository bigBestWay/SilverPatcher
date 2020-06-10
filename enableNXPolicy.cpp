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

	Segment * segment = nullptr;
	if (BinaryEditor::instance()->getSegment(SEGMENT_TYPES::PT_GNU_STACK, segment))
	{
		segment->remove(ELF_SEGMENT_FLAGS::PF_X);
		std::cout << "Add NX support." << std::endl;
	}
	else
	{
		std::cerr << "Segment GNU_STACK not found." << std::endl;
	}
}
