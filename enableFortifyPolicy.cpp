#include "enableFortifyPolicy.h"
#include "BinaryEditor.h"

/*
���������
__printf_chk��printf�ĺ���ԭ�Ͳ�ͬ��
printf(const char *fmt, ...);
__printf_chk(int flag, const char *fmt);
��Ҫ���Ӳ������ɱ�̫�ߡ�
*/

enableFortifyPolicy::enableFortifyPolicy()
{
	setRiskLevel(MEDIUM);
}

//��__printf_chk�滻printf
//gcc -O2���룬���Զ�����_chk����
void enableFortifyPolicy::do_patch()
{
	const char * unsafe_table[] = {
		"vswprintf",
		"printf",
		//"fgetws",
		"vfwprintf",
		//"stpcpy",
		//"wcpcpy",
		"swprintf",
		"vwprintf",
		"fwprintf",
		//"mempcpy",
		//"read",
		"vsprintf",
		//"wcsncpy",
		//"wmemset",
		"vprintf",
		"fprintf",
		//"wmemcpy",
		//"wcscpy",
		"dprintf",
		//"wmempcpy",
		//"memmove",
		"vsnprintf",
		"fgets",
		"strncpy",
		//"wcscat",
		"snprintf",
		//"memset",
		"strncat",
		//"recv",
		//"memcpy",
		"stpncpy",
		//"fread",
		"wprintf",
		"vfprintf",
		"strcpy",
		"vdprintf",
		"vasprintf",
		//"wcpncpy",
		//"wmemmove",
		"sprintf",
		"strcat",
		"asprintf",
		//"recvfrom",
		"gets",
		NULL
	};

	std::cout << "enableFortifyPolicy:" << std::endl;
	for (int i = 0; unsafe_table[i]; ++i)
	{
		do_patch(unsafe_table[i]);
	}
}

void enableFortifyPolicy::do_patch(const char * symbolName)
{
	Relocation * reloc = BinaryEditor::instance()->getRelocation(symbolName);
	if (reloc)
	{
		std::cout << *reloc << std::endl;
		Symbol & sym = reloc->symbol();
		std::string chkName = "__";
		chkName += symbolName;
		chkName += "_chk";
		//sym.name("__printf_chk");
		sym.name(chkName);
		sym.symbol_version() = SymbolVersion::global();
		std::cout << "Change PLTGOT " << symbolName << " to " << chkName << std::endl;
	}
}
