/*LIEF在x32 NO-PIE的情况下，添加segment会导致BUG：
  Inconsistency detected by ld.so: rtld.c: 1191: dl_main: Assertion `GL(dl_rtld_map).l_libname' failed!
  解决方法：
  在LIEF源码中添加section会添加一个Segment，添加完Segment后调用replace方法将此新段与PT_NOTE互换，即临时解决了此问题。

  src/ELF/Binary.tcc 631行:
  -Segment& segment_added = this->add(new_segment);
  +Segment * segment_added = nullptr;
  +if(this->type() == ELF_CLASS::ELFCLASS32 && this->header().file_type() != E_TYPE::ET_DYN)
  +{
  +  Segment & note = this->get(SEGMENT_TYPES::PT_NOTE);
  +  segment_added = &this->replace(new_segment,note);
  +}
  +else
  +{
  +  segment_added = &this->add(new_segment);
  +}
*/
#include "BinaryEditor.h"
#include "RiseStackPolicy.h"
#include "enableNXPolicy.h"
#include "setRPathPolicy.h"
#include <unistd.h>
#include <sys/stat.h>
#include "BinaryAnalyzer.h"
#include "BindNowPolicy.h"
#include "StartInjectPolicy.h"
#include "Config.h"
#include "DisableFreePolicy.h"
#include "FmtVulScanRepairPolicy.h"
#include "RandomPLTGOTPolicy.h"

static std::vector<PatchPolicy *> s_policys;

void loadPolicys()
{
	if (Config::instance()->isPolicyEnabled(enableNXPolicy::name()))
	{
			s_policys.push_back(new enableNXPolicy());
	}
	if (Config::instance()->isPolicyEnabled(BindNowPolicy::name()))
	{
			s_policys.push_back(new BindNowPolicy());
	}
	if (Config::instance()->isPolicyEnabled(RandomPLTGOTPolicy::name()))
	{
		s_policys.push_back(new RandomPLTGOTPolicy());
	}
	if (Config::instance()->isPolicyEnabled(StartInjectPolicy::name()))
	{
		s_policys.push_back(new StartInjectPolicy());
	}
	if (Config::instance()->isPolicyEnabled(setRPathPolicy::name()))
	{
		s_policys.push_back(new setRPathPolicy());
	}
	if (Config::instance()->isPolicyEnabled(RiseStackPolicy::name()))
	{
		s_policys.push_back(new RiseStackPolicy());
	}
	if (Config::instance()->isPolicyEnabled(DisableFreePolicy::name()))
	{
		s_policys.push_back(new DisableFreePolicy());
	}
	if (Config::instance()->isPolicyEnabled(FmtVulScanRepairPolicy::name()))
	{
		s_policys.push_back(new FmtVulScanRepairPolicy());
	}
}

void execPolicys()
{
	RiskLevel level = SECURE;
	for (size_t i = 0; i < s_policys.size(); ++i)
	{
		if (s_policys[i]->getRiskLevel() > level)
		{
			level = s_policys[i]->getRiskLevel();
		}
	}

	if (level >= MEDIUM)
	{
		if (BinaryEditor::instance()->isPIE())
		{
			//PIE情况下添加段，原来的地址也会变，因此先添加好
			BinaryEditor::instance()->addSection(DEFAULT_SECTION_SIZE);
		}
	}

	for (size_t i = 0; i < s_policys.size(); ++i)
	{
		if (!s_policys[i]->Executed() && s_policys[i]->getRiskLevel() <= level)
		{
			s_policys[i]->do_patch();
			s_policys[i]->Executed(true);
		}
	}
}

void usage(const char * programe)
{
	std::cerr << "Usage: " << programe << " <binary> [config]" << std::endl;
	std::cerr << "       [config]: json format, config.json by default." << std::endl;
}

int main(int argc, char *argv[]) {
	if (argc != 3 && argc != 2) {
		usage(argv[0]);
		return 1;
	}

	if (access(argv[1], R_OK) != 0)
	{
		std::cerr << "Cannot access " << argv[1] << std::endl;
		return 1;
	}

	std::string configName = "config.json";
	if (argc == 3)
	{
		configName = argv[2];
	}

	if (access(configName.c_str(), R_OK) != 0)
	{
		std::cerr << "Cannot access " << configName << std::endl;
		return 1;
	}

	std::string elfIn = argv[1];
	if (!BinaryEditor::instance()->init(elfIn))
	{
		std::cerr << "BinaryEditor parse failed" << std::endl;
		return 1;
	}

	Config::instance()->init(configName);

	loadPolicys();

	if (!BinaryAnalyzer::instance()->init(elfIn.c_str()))
	{
		std::cerr << "BinaryAnalyzer parse failed" << std::endl;
		return 1;
	}

	execPolicys();

	std::string elfout = elfIn + "_patched";
	unlink(elfout.c_str());
	BinaryEditor::instance()->writeFile(elfout);
	chmod(elfout.c_str(), S_IRWXU|S_IXGRP|S_IRGRP|S_IXOTH|S_IROTH);
	std::cout << "\033[1m\033[31m" << elfout << " generated." << "\033[0m" << std::endl;

	return 0;
}
