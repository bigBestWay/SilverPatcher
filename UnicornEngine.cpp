#include "UnicornEngine.h"
#include <unicorn/unicorn.h>
#include "BinaryEditor.h"

#define ADDRESS 0x1000000
#define STACK_ADDR 0x8000000
#define STACK_SIZE 1024 * 1024 /* 1M */

// callback for tracing basic blocks
static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

// callback for tracing instruction
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	int eflags;
	printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);

	uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
	printf(">>> --- EFLAGS is 0x%x\n", eflags);

	// Uncomment below code to stop the emulation using uc_emu_stop()
	// if (address == 0x1000009)
	//    uc_emu_stop(uc);
}

UnicornEngine * UnicornEngine::_instance = nullptr;

int UnicornEngine::simulate_start(const std::vector<uint8_t> & code, uint64_t & main_addr)
{
	uc_engine *uc;
	uc_err err;
	uc_hook trace1, trace2;

	bool isX32 = BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS32;
	if (isX32)
	{
		err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
	}
	else
	{
		err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
	}
	
	if (err) {
		printf("Failed on uc_open() with error returned: %u\n", err);
		return 1;
	}

	// map 2MB memory for this emulation
	uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);
	uc_mem_map(uc, STACK_ADDR, STACK_SIZE, UC_PROT_ALL);

	// write machine code to be emulated to memory
	if (uc_mem_write(uc, ADDRESS, code.data(), code.size())) 
	{
		printf("Failed to write emulation code to memory, quit!\n");
		return 1;
	}

	// tracing all basic blocks with customized callback
	//uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, (void *)hook_block, NULL, 1, 0);

	// tracing all instruction by having @begin > @end
	//uc_hook_add(uc, &trace2, UC_HOOK_CODE, (void *)hook_code, NULL, 1, 0);
	if (isX32)
	{
		uint32_t esp_value = STACK_ADDR + STACK_SIZE/2;
		uc_reg_write(uc, UC_X86_REG_ESP, &esp_value);
	}
	else
	{
		uint64_t rsp_value = STACK_ADDR + STACK_SIZE / 2;
		uc_reg_write(uc, UC_X86_REG_RSP, &rsp_value);
	}

	// emulate machine code in infinite time
	err = uc_emu_start(uc, ADDRESS, ADDRESS + code.size(), 0, 0);
	if (err) {
		printf("Failed on uc_emu_start() with error returned %u: %s\n",	err, uc_strerror(err));
		return 1;
	}

	// now print out some registers
	printf(">>> Emulation done. Below is the CPU context\n");

	if (!isX32)
	{
		uc_reg_read(uc, UC_X86_REG_RDI, &main_addr);
	}
	else
	{
		uint32_t esp_value = 0;
		uint32_t tmp = 0;
		uc_reg_read(uc, UC_X86_REG_ESP, &esp_value);
		uc_mem_read(uc, esp_value, &tmp, sizeof(tmp));
		main_addr = tmp;
	}

	uc_close(uc);

	return 0;
}

UnicornEngine::UnicornEngine()
{

}

UnicornEngine::~UnicornEngine()
{

}


