#include "ResortGotEntryPolicy.h"
#include "BinaryEditor.h"
#include "CSEngine.h"
#include "KSEngine.h"

struct ResortGotEntryPolicy::PLTGOTStruct
{
	PLTGOTStruct(int64_t addr):
		pltStubAddress(addr), gotSlotIndex(0),gotEntry(nullptr)
	{
	}

	uint64_t pltStubAddress;

	uint32_t gotSlotIndex;
	Relocation * gotEntry;

	void swap(PLTGOTStruct & other)
	{
		uint32_t tmpInt32 = this->gotSlotIndex;
		this->gotSlotIndex = other.gotSlotIndex;
		other.gotSlotIndex = tmpInt32;

		Relocation * tmpEntry = this->gotEntry;
		this->gotEntry = other.gotEntry;
		other.gotEntry = tmpEntry;

		this->gotEntry->symbol().swap(other.gotEntry->symbol());
	}

	PLTGOTStruct & operator=(const PLTGOTStruct & o)
	{
		if (*this == o)
		{
			return *this;
		}
		
		this->pltStubAddress = o.pltStubAddress;
		this->gotEntry = o.gotEntry;
		this->gotSlotIndex = o.gotSlotIndex;

		return *this;
	}

	bool operator==(const PLTGOTStruct & o)const
	{
		return this->pltStubAddress == o.pltStubAddress && this->gotEntry == o.gotEntry && this->gotSlotIndex == o.gotSlotIndex;
	}
};

void ResortGotEntryPolicy::patch_pltstub_gotslot(const PLTGOTStruct & stru)
{
	bool isX32 = BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS32;
	bool isPIE = BinaryEditor::instance()->isPIE();
	//x32 PLT STUB在PIE下变成使用ebx寻址
	std::vector<uint8_t> jmpCode;
	if (isPIE && isX32)
	{
		Section gotpltSection;
		if (!BinaryEditor::instance()->getGOTPLTSection(gotpltSection))
		{
			std::cerr << "Section .got.plt not found." << std::endl;
			return;
		}
		const uint64_t gotTabBaseAddress = gotpltSection.virtual_address();
		//ff a3 0c 00 00 00                      jmp	dword ptr [ebx + 0xc]，keystone无法生成6字节的跳转
		uint8_t code[6] = { 0xff, 0xa3, 0x0c, 0, 0, 0 };
		uint32_t offset = (uint32_t)(stru.gotEntry->address() - gotTabBaseAddress);
		std::memcpy(code + 2, &offset, sizeof(uint32_t));
		jmpCode.insert(jmpCode.end(), code, code + sizeof(code));
	}
	else
	{
		//x64 PLT STUB形式相同
		std::string jmp;
		if (!isPIE)
		{
			if (!isX32)
			{
				jmp = "jmp	qword ptr [rip +" + std::to_string(stru.gotEntry->address() - stru.pltStubAddress - 6) + "]";
			}
			else
			{
				jmp = "jmp	dword ptr [" + std::to_string(stru.gotEntry->address()) + "]";
			}
		}
		else
		{
			if (!isX32)
			{
				jmp = "jmp	qword ptr [rip +" + std::to_string(stru.gotEntry->address() - stru.pltStubAddress - 6) + "]";
			}
		}

		//plt stub要修改跳转的got slot地址以及对应的表项序号
		KSEngine::instance()->assemble(jmp.c_str(), stru.pltStubAddress, jmpCode);
	}

	//plt里的push使用的是push 68 01 00 00 00，而keystone无法生成
	uint8_t code[5] = { 0x68, 0, 0, 0, 0 };
	std::memcpy(code + 1, &stru.gotSlotIndex, sizeof(uint32_t));
	jmpCode.insert(jmpCode.end(), code, code + 5);
	BinaryEditor::instance()->patch_address(stru.pltStubAddress, jmpCode);

	//got slot要修改为对应的plt stub地址+6
	if (isX32)
	{
		//表项内容是4字节
		std::vector<uint8_t> gotslotValue = { 0,0,0,0 };
		uint32_t val = (uint32_t)(stru.pltStubAddress + 6);
		std::memcpy(gotslotValue.data(), &val, sizeof(val));
		BinaryEditor::instance()->patch_address(stru.gotEntry->address(), gotslotValue);
	}
	else
	{
		//表项内容是8字节
		std::vector<uint8_t> gotslotValue = { 0,0,0,0,0,0,0,0 };
		uint64_t val = stru.pltStubAddress + 6;
		std::memcpy(gotslotValue.data(), &val, sizeof(val));
		BinaryEditor::instance()->patch_address(stru.gotEntry->address(), gotslotValue);
	}

	std::cout << "PLT STUB " << std::hex << stru.pltStubAddress << " push " << stru.gotSlotIndex << "-->" << *stru.gotEntry;
	std::cout << " "<< std::hex << BinaryEditor::instance()->getGotSlotValue(stru.gotEntry->address()) << std::endl;
}

void ResortGotEntryPolicy::do_patch()
{
	label("ResortGotEntryPolicy");
	if (BinaryEditor::instance()->isGotReadonly())
	{
		std::cout << "GOT read-only already SUPPORT." << std::endl;
		return;
	}

	//增加DynamicEntry DT_BIND_NOW之后，立即绑定，增加PT_GNU_RELRO段会设置相应范围为只读
	//got[1]和got[0]都是0，这样ret2dl_resolve_runtime就不能用了
	//为了避免增加新代码段，这里将DT_DEBUG段修改为DT_BIND_NOW
	//而PT_GNU_RELRO段只读的方案改为，打乱GOT表项顺序重排列，让攻击者找不到对应的项（这里实现这一部分）
	Section plt_section;
	if (!BinaryEditor::instance()->getPLTSection(plt_section))
	{
		std::cerr << ".plt section not found." << std::endl;
		return;
	}

	std::vector<uint64_t> plt_stub_address;
	const uint32_t plt_entry_size = BinaryEditor::instance()->getPLTEntrySize();
	//第0个是dl_resolve，不处理
	for (size_t i = 1; i < plt_section.size()/ plt_entry_size; ++i)
	{
		uint64_t addr = plt_section.virtual_address() + plt_entry_size *i;
		//std::cout << "PLT Stub " << std::hex << addr << std::endl;
		plt_stub_address.push_back(addr);
	}

	std::vector<Relocation *> pltgotRelocations;
	BinaryEditor::instance()->getPLTGOTRelocations(pltgotRelocations);
	std::vector<PLTGOTStruct> pltgotStructs;
	for (size_t index = 0; index < pltgotRelocations.size(); ++index)
	{
		Relocation * reloc = pltgotRelocations[index];
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
		if(reloc->symbol().name() == "__gmon_start__")
			continue;
		const std::vector<uint8_t> & pltStubCode = BinaryEditor::instance()->get_content(plt_stub_address[index], plt_entry_size);
		uint64_t slotIndex = getGotslotIndex(pltStubCode);
		std::cout << "PLT STUB " << std::hex << plt_stub_address[index] <<" push " << slotIndex << "-->" << *reloc;
		std::cout << " " << std::hex << BinaryEditor::instance()->getGotSlotValue(reloc->address()) << std::endl;
		PLTGOTStruct stru( plt_stub_address[index]);
		stru.gotEntry = reloc;
		stru.gotSlotIndex = (uint32_t)slotIndex;
		pltgotStructs.push_back(stru);
	}

	std::random_shuffle(pltgotStructs.begin(), pltgotStructs.end());
	//互换规则：
	//数量为2n+1，除第1个之外2n对换，第1个和2n+1换
	//数量为2n，对换(1<->4, 2<->3)
	size_t pltgotStructsSize = pltgotStructs.size();
	if (pltgotStructsSize % 2 == 0)
	{
		for (size_t up = 0; up < pltgotStructsSize /2; ++up)
		{
			size_t down = pltgotStructsSize - 1 - up;
			//swap info
			pltgotStructs[up].swap(pltgotStructs[down]);
		}
	}
	else
	{
		if (pltgotStructsSize > 1)
		{
			for (size_t up = 1; up < (pltgotStructsSize + 1) / 2; ++up)
			{
				size_t down = pltgotStructsSize - up;
				//swap info
				pltgotStructs[up].swap(pltgotStructs[down]);
			}
			pltgotStructs[0].swap(pltgotStructs[pltgotStructsSize - 1]);
		}
	}

	std::cout << "PATCH:" << std::endl;
	for (const PLTGOTStruct & stru : pltgotStructs)
	{
		patch_pltstub_gotslot(stru);
	}
}

uint64_t ResortGotEntryPolicy::getGotslotIndex(const std::vector<uint8_t> & code)
{
	cs_insn * insn = nullptr;
	size_t count = CSEngine::instance()->disasm(code, 0, &insn);
	if (count == 3)
	{
		uint8_t op_count = insn[1].detail->x86.op_count;
		if (op_count == 1)
		{
			return insn[1].detail->x86.operands[0].imm;
		}
	}
	return 0;
}
