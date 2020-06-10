#include "KSEngine.h"
#include "BinaryEditor.h"

void KSEngine::assemble(const char * assembly, uint64_t address, std::vector<uint8_t> & code)
{
	unsigned char * encode = nullptr;
	size_t count = 0;
	size_t size = 0;
	code.clear();
	if (ks_asm(_ks, assembly, address, &encode, &size, &count))
	{
		printf("%s ", assembly);
		printf("ERROR: failed on ks_asm() with count = %lu, error code = %u\n", count, ks_errno(_ks));
	}
	else 
	{
		code.insert(code.end(), encode, encode + size);
		ks_free(encode);
	}
}

KSEngine * KSEngine::_instance = nullptr;

KSEngine::KSEngine()
{
	ks_err err;
	if (ELF_CLASS::ELFCLASS32 == BinaryEditor::instance()->getPlatform())
	{
		err = ks_open(KS_ARCH_X86, KS_MODE_32, &_ks);
	}
	else
	{
		err = ks_open(KS_ARCH_X86, KS_MODE_64, &_ks);
	}

	if (err != KS_ERR_OK) {
		std::cerr << "Failed on ks_open() with error returned: " << err << std::endl;
	}
}

KSEngine::~KSEngine()
{
	ks_close(_ks);
}
