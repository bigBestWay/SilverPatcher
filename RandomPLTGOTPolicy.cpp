#include "RandomPLTGOTPolicy.h"
#include "BinaryEditor.h"
#include "CSEngine.h"
#include "KSEngine.h"
#include <map>
#include <string>
#include <algorithm>
#include <ctime>
#include <ostream>

struct RelocData
{
	Relocation * entry;
	uint64_t plt_stub;

	bool operator<(const RelocData & o)const
	{
		return this->entry->symbol().name() < o.entry->symbol().name();
	}

	void swap(RelocData & o)
	{
		BinaryEditor::instance()->symbol_swap(entry->symbol(), o.entry->symbol());
	}

	friend std::ostream & operator <<(std::ostream & out, const RelocData &m)
	{
		return std::cout << "PLTSTUB " << std::hex << m.plt_stub << " " << *m.entry;
	}
};

RandomPLTGOTPolicy::~RandomPLTGOTPolicy()
{
	cs_free(_text_insns, _insn_count);
	_text_insns = nullptr;
	_insn_count = 0;
}

void RandomPLTGOTPolicy::do_patch()
{
	label("RandomPLTGOTPolicy");
	srand(time(nullptr));

	//plt<-got
	std::map<uint64_t, uint64_t> got2plt;
	Section plt;
	if (BinaryEditor::instance()->isGotReadonly())
	{
		if (!BinaryEditor::instance()->getPLTGOTSection(plt))
		{
			std::cerr << "Not found .plt.got section" << std::endl;
			return;
		}
	}
	else
	{
		if (!BinaryEditor::instance()->getPLTSection(plt))
		{
			std::cerr << "Not found .plt section" << std::endl;
			return;
		}

	}

	const std::vector<uint8_t> & plt_data = plt.content();
	const uint32_t plt_entry_sz = BinaryEditor::instance()->getPLTEntrySize();
	for (size_t i = 0; i < plt.size() / plt_entry_sz; ++i)
	{
		const uint64_t pltStub = plt.virtual_address() + i * plt_entry_sz;
		const uint8_t * data = plt_data.data() + i * plt_entry_sz;
		uint64_t gotentry = 0;
		if (CSEngine::instance()->getGotEntryOfPltstub(data, plt_entry_sz, pltStub, gotentry))
		{
			got2plt[gotentry] = pltStub;
		}
	}

	std::vector<Relocation *> allrels;
	std::vector<RelocData> vecRelocData;
	std::map<std::string, std::vector<uint64_t> > sym2callpoints;
	BinaryEditor::instance()->getAllRelocations(allrels);
	for (auto entry : allrels)
	{
		if (entry->has_symbol())
		{
			/*对于__gmon_start__函数特殊处理，不参与重排列，否则_init函数中
				__int64 init_proc()
				{
				__int64 result; // rax

				result = (__int64)&printf;
				if ( &printf )
					result = __gmon_start__(); 会调用空指针
				return result;
				}
				*/
			const std::string & name = entry->symbol().name();
			if (name == "__gmon_start__")
				continue;

			std::map<uint64_t, uint64_t>::const_iterator ite = got2plt.find(entry->address());
			if (ite != got2plt.end())
			{
				RelocData e;
				e.plt_stub = ite->second;
				e.entry = entry;
				getCallPoint(e.plt_stub, sym2callpoints[name]);
				std::cout << e << std::endl;
				vecRelocData.push_back(e);
			}
		}
	}

	std::random_shuffle(vecRelocData.begin(), vecRelocData.end());
	//互换规则：
	//数量为2n+1，除第1个之外2n对换，第1个和2n+1换
	//数量为2n，对换(1<->4, 2<->3)
	size_t vecRelocDataSz = vecRelocData.size();
	if (vecRelocDataSz % 2 == 0)
	{
		for (size_t up = 0; up < vecRelocDataSz / 2; ++up)
		{
			size_t down = vecRelocDataSz - 1 - up;
			//swap info
			vecRelocData[up].swap(vecRelocData[down]);
		}
	}
	else
	{
		if (vecRelocDataSz > 1)
		{
			for (size_t up = 1; up < (vecRelocDataSz + 1) / 2; ++up)
			{
				size_t down = vecRelocDataSz - up;
				//swap info
				vecRelocData[up].swap(vecRelocData[down]);
			}
			vecRelocData[0].swap(vecRelocData[vecRelocDataSz - 1]);
		}
	}


	std::cout << "Patched: " << std::endl;
	//relaDyn.content(rela_data);
	for (const RelocData & reloc_data : vecRelocData)
	{
		std::cout << reloc_data << std::endl;
		patch_call(reloc_data.plt_stub, sym2callpoints[reloc_data.entry->symbol().name()]);
	}
}

void RandomPLTGOTPolicy::getCallPoint(uint64_t pltstub, std::vector<uint64_t> & call_points)
{
	if (_text_insns == nullptr)
	{
		const Section & text = BinaryEditor::instance()->textSection();
		const std::vector<uint8_t> & data = text.content();
		_insn_count = CSEngine::instance()->disasm(data, text.virtual_address(), &_text_insns);
	}
	
	if(_text_insns != nullptr)
	{
		for (size_t i = 0; i < _insn_count; ++i)
		{
			const cs_insn & insn = _text_insns[i];
			if (CSEngine::instance()->isCallMe(insn, pltstub))
			{
				//CSEngine::instance()->disasmShow(insn, false);
				call_points.push_back(insn.address);
			}
		}
	}
}

void RandomPLTGOTPolicy::patch_call(uint64_t pltstub, const std::vector<uint64_t> & call_points)
{
	for (uint64_t callpoint: call_points)
	{
		std::string asmText = "call ";
		asmText += std::to_string(pltstub);
		std::vector<uint8_t> data;
		KSEngine::instance()->assemble(asmText.c_str(), callpoint, data);
		BinaryEditor::instance()->patch_address(callpoint, data);
	}
}
