#pragma once
#include <capstone/platform.h>
#include <capstone/capstone.h>
#include <vector>
#include <string>
class CSEngine
{
public:
	static CSEngine * instance()
	{
		if (_instance == nullptr)
		{
			_instance = new CSEngine();
		}
		return _instance;
	}

	static void destroy()
	{
		delete _instance;
		_instance = nullptr;
	}

	size_t disasm(const std::vector<uint8_t> & code, uint64_t address, cs_insn ** insn);

	size_t disasm(const uint8_t * data, size_t size, uint64_t address, cs_insn ** insn);

	const char * reg_name(unsigned int reg_id)
	{
		return cs_reg_name(_handle, reg_id);
	}

	std::string espName()const
	{
		return _espname;
	}

	//指令操作数里是否有RIP, 比如RET或mov eax, [RIP + 8]
	bool isInsnOphasRIP(const cs_insn & insn);

	bool isCallMe(const cs_insn & insn, uint64_t me);

	bool getGotEntryOfPltstub(const uint8_t * data, size_t size, uint64_t address, uint64_t & gotentry);

	void disasmShow(const std::vector<uint8_t> & code, uint64_t address, bool showdetail = false);

	void disasmShow(const cs_insn & insn, bool showdetail = true);

	static bool is_jmp_grp_type(const cs_insn & insn);

	static bool is_ret_grp_type(const cs_insn & insn);

	static void hexDump(const std::vector<uint8_t> & code);

	static void hexDump(const void * ptr, int size);

private:
	static CSEngine * _instance;
	CSEngine();
	~CSEngine();
private:
	csh _handle;
	std::string _espname;
};

