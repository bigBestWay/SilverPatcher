#include "CSEngine.h"
#include "BinaryEditor.h"

CSEngine * CSEngine::_instance = nullptr;

CSEngine::CSEngine()
{
	cs_err err = CS_ERR_OK;
	if (ELF_CLASS::ELFCLASS32 == BinaryEditor::instance()->getPlatform())
	{
		err = cs_open(CS_ARCH_X86, CS_MODE_32, &_handle);
		_espname = "esp";
	}
	else
	{
		err = cs_open(CS_ARCH_X86, CS_MODE_64, &_handle);
		_espname = "rsp";
	}

	if (err) 
	{
		std::cerr<<"Failed on cs_open() with error returned: "<< err <<std::endl;
	}
	cs_option(_handle, CS_OPT_DETAIL, CS_OPT_ON);
}

CSEngine::~CSEngine()
{
	cs_close(&_handle);
}

size_t CSEngine::disasm(const std::vector<uint8_t> & code, uint64_t address, cs_insn **insn)
{
	return cs_disasm(_handle, code.data(), code.size(), address, 0, insn);
}

bool CSEngine::isInsnOphasRIP(const cs_insn & insn)
{
	const char * ripName = BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS32 ? "eip" : "rip";
	cs_x86 * x86 = &insn.detail->x86;
	for (size_t i = 0; i < x86->op_count; ++i)
	{
		cs_x86_op *op = &(x86->operands[i]);
		if (op->type == X86_OP_REG)
		{
			if (strcasecmp(cs_reg_name(_handle, op->reg), ripName) == 0)
			{
				return true;
			}
		}
		else if (op->type == X86_OP_MEM)
		{
			if (op->mem.segment != X86_REG_INVALID)
			{
				if (strcasecmp(cs_reg_name(_handle, op->mem.segment), ripName) == 0)
				{
					return true;
				}
			}

			if (op->mem.base != X86_REG_INVALID)
			{
				if (strcasecmp(cs_reg_name(_handle, op->mem.base), ripName) == 0)
				{
					return true;
				}
			}

			if (op->mem.index != X86_REG_INVALID)
			{
				if (strcasecmp(cs_reg_name(_handle, op->mem.index), ripName) == 0)
				{
					return true;
				}
			}
		}
	}
	return false;
}

void CSEngine::disasmShow(const std::vector<uint8_t> & code, uint64_t address, bool showdetail)
{
	cs_insn * insn = NULL;
	size_t count = cs_disasm(_handle, code.data(), code.size(), address, 0, &insn);
	for (size_t i = 0; i < count; ++i)
	{
		disasmShow(insn[i], showdetail);
	}
	cs_free(insn, count);
}

void CSEngine::disasmShow(const cs_insn & insn, bool showdetail /*= true*/)
{
	printf("0x%" PRIx64 ":\t%s\t%s\n", insn.address, insn.mnemonic, insn.op_str);
	if (showdetail)
	{
		cs_x86 * x86 = &(insn.detail->x86);
		if (x86->op_count)
			printf("\top_count: %u\n", x86->op_count);

		// Print out all operands
		for (int j = 0; j < x86->op_count; j++) {
			cs_x86_op *op = &(x86->operands[j]);

			switch ((int)op->type) {
			case X86_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", j, cs_reg_name(_handle, op->reg));
				break;
			case X86_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", j, op->imm);
				break;
			case X86_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", j);
				if (op->mem.segment != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.segment: REG = %s\n", j, cs_reg_name(_handle, op->mem.segment));
				if (op->mem.base != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n", j, cs_reg_name(_handle, op->mem.base));
				if (op->mem.index != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.index: REG = %s\n", j, cs_reg_name(_handle, op->mem.index));
				if (op->mem.scale != 1)
					printf("\t\t\toperands[%u].mem.scale: %u\n", j, op->mem.scale);
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", j, op->mem.disp);
				break;
			default:
				break;
			}
		}
	}
}

void CSEngine::hexDump(const std::vector<uint8_t> & code)
{
	for (size_t i = 0; i < code.size(); ++i)
	{
		printf("%02x ", code[i]);
	}
	printf("\n");
}

void CSEngine::hexDump(const void * ptr, int size)
{
	for (int i = 0; i < size; ++i)
	{
		printf("%02x ", ((uint8_t *)ptr)[i]);
	}
	printf("\n");
}

