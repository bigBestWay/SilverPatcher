#include "LibelfEditor.h"
#include <libelf.h>
#include <gelf.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <iostream>
#include <map>
#include "InstrumentManager.h"

static Elf * _binary = nullptr;
static size_t _shstrndx = 0;
static int _fd = -1;
static std::map<int, GElf_Shdr> _sections;
static std::map<int, GElf_Phdr> _segments;

static int section_from_virtual_address(uint64_t address, GElf_Shdr & shdr)
{
	for (auto & section : _sections)
	{
		uint64_t start = section.second.sh_addr;
		uint64_t end = start + section.second.sh_size;
		if (address >= start && address < end)
		{
			shdr = section.second;
			return section.first;
		}
	}

	return -1;
}

static int segment_from_virtual_address(uint64_t address, GElf_Phdr & phdr)
{
	for (auto & segment : _segments)
	{
		int id = segment.first;
		uint64_t start = segment.second.p_vaddr;
		uint64_t end = start + segment.second.p_memsz;
		if (address >= start && address < end)
		{
			phdr = segment.second;
			return id;
		}
	}

	return -1;
}

static int find_section(uint32_t type, GElf_Shdr * & shdr)
{
	for (auto & section : _sections)
	{
		int section_ndx = section.first;
		if (section.second.sh_type == type)
		{
			shdr = &section.second;
			return section.first;
		}
	}

	return -1;
}

bool LibelfEditor::copy_file(const std::string & infile, const std::string & outfile)
{
	FILE * in = fopen(infile.c_str(), "r");
	FILE * out = fopen(outfile.c_str(), "w");
	if (in == nullptr || out == nullptr)
	{
		std::cerr << "Error occurred." << std::endl;
		return false;
	}

	fseek(in, 0, SEEK_END);
	long filesize = ftell(in);
	fseek(in, 0, SEEK_SET);
	char * content = new char[filesize];
	fread(content, filesize, 1, in);
	fclose(in);

	fwrite(content, filesize, 1, out);
	fclose(out);
	delete[] content;
	return true;
}

bool LibelfEditor::enable_nx()
{
	for (auto & segment : _segments)
	{
		GElf_Phdr & phdr = segment.second;
		if (phdr.p_type == GNU_PROPERTY_STACK_SIZE)
		{
			phdr.p_flags &= ~PF_X; //去掉可执行权限

			gelf_update_phdr(_binary, segment.first, &phdr);
			return true;
		}
	}
	return false;
}

bool LibelfEditor::enable_bindnow()
{
	for (auto & section : _sections)
	{
		int section_ndx = section.first;
		if (section.second.sh_type == SHT_DYNAMIC)
		{
			Elf_Scn * scn = elf_getscn(_binary, section_ndx);
			Elf_Data * data = elf_getdata(scn, nullptr);
			for (int dyn_idx = 0; ; ++dyn_idx)
			{
				GElf_Dyn dyn_storage;
				GElf_Dyn *dyn = gelf_getdyn(data, dyn_idx, &dyn_storage);
				if (dyn == NULL)
					return false;

				if (dyn->d_tag == DT_DEBUG)
				{
					dyn->d_tag = DT_BIND_NOW;
					dyn->d_un.d_val = 0;
					if (gelf_update_dyn(data, dyn_idx, dyn) == 0)
					{
						std::cerr << "gelf_update_dyn fail: " << elf_errmsg(-1) << std::endl;
						return false;
					}

					elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
					elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
					return true;
				}
			}
		}
	}

	return false;
}

void LibelfEditor::symbol_swap(const std::string & name1, const std::string & name2)
{
	GElf_Sym sym1,sym2;
	int sym_ndx1 = -1, sym_ndx2 = -1;
	GElf_Shdr * dynsym_shdr = nullptr, * versym_shdr = nullptr;
	int dynsym_ndx = find_section(SHT_DYNSYM, dynsym_shdr);
	int versym_ndx = find_section(SHT_GNU_versym, versym_shdr);

	Elf_Scn * dynsym_scn = elf_getscn(_binary, dynsym_ndx);
	Elf_Data * dynsym_data = elf_getdata(dynsym_scn, nullptr);

	int ndx_sym = 0;
	GElf_Sym sym;
	while (gelf_getsym(dynsym_data, ndx_sym, &sym) == &sym) {
		const std::string & sym_name = elf_strptr(_binary, dynsym_shdr->sh_link, sym.st_name);
		if (sym_name == name1)
		{
			sym_ndx1 = ndx_sym;
			std::memcpy(&sym1, &sym, sizeof(sym));
		}
		else if (sym_name == name2)
		{
			sym_ndx2 = ndx_sym;
			std::memcpy(&sym2, &sym, sizeof(sym));
		}
		++ndx_sym;
	}

	//get symver
	GElf_Versym versym1, versym2;
	Elf_Scn * versym_scn = elf_getscn(_binary, versym_ndx);
	Elf_Data * versym_data = elf_getdata(versym_scn, nullptr);
	gelf_getversym(versym_data, sym_ndx1, &versym1);
	gelf_getversym(versym_data, sym_ndx2, &versym2);

	gelf_update_sym(dynsym_data, sym_ndx1, &sym2);
	gelf_update_sym(dynsym_data, sym_ndx2, &sym1);

	gelf_update_versym(versym_data, sym_ndx1, &versym2);
	gelf_update_versym(versym_data, sym_ndx2, &versym1);

	elf_flagdata(dynsym_data, ELF_C_SET, ELF_F_DIRTY);
	elf_flagscn(dynsym_scn, ELF_C_SET, ELF_F_DIRTY);
	elf_flagdata(versym_data, ELF_C_SET, ELF_F_DIRTY);
	elf_flagscn(versym_scn, ELF_C_SET, ELF_F_DIRTY);
}

bool LibelfEditor::init(const char * elfname)
{
    if (elf_version(EV_CURRENT) == EV_NONE)
		return false;

	_fd = open(elfname, O_RDWR);
	if (_fd < 0)
	{
		return false;
	}

	_binary = elf_begin(_fd, ELF_C_RDWR, (Elf *)0);
	if (_binary == nullptr)
	{
		return false;
	}

	if (elf_kind(_binary) != ELF_K_ELF)
	{
		std::cerr << "Not a ELF file." << std::endl;
		return false;
	}

	if (elf_getshstrndx(_binary, &_shstrndx) < 0)
	{
		std::cerr << "cannot get section header string table index." << std::endl;
		return false;
	}

	size_t segment_total_num = 0;
	if (elf_getphdrnum(_binary, &segment_total_num) < 0)
	{
		std::cerr << "cannot determine number of program header." << std::endl;
		return false;
	}

	size_t section_total_num = 0;
	if (elf_getshdrnum(_binary, &section_total_num) < 0)
	{
		std::cerr << "cannot get section total number." << std::endl;
		return false;
	}

	/* load all segments */
	for (size_t i = 0; i < segment_total_num; ++i)
	{
		GElf_Phdr phdr;
		if(gelf_getphdr(_binary, i, &phdr) == nullptr)
			continue;

		_segments[i] = phdr;
	}

	/* load all sections */
	for (size_t i  = 1; i < section_total_num; ++i)
	{
		Elf_Scn * scn = elf_getscn(_binary, i);
		GElf_Shdr shdr;
		if (gelf_getshdr(scn, &shdr) == nullptr)
		{
			std::cerr << elf_errmsg(elf_errno()) << std::endl;
			continue;
		}

		//const char * name = elf_strptr(_binary, _shstrndx, shdr.sh_name);
		//std::cout << name << " virtual_address = " << std::hex << shdr.sh_addr << " size = " << shdr.sh_size << std::endl;

		_sections[i] = shdr;
	}

	loadCodeDefaultCaves();

	return true;
}


/*一个ELF文件加载到进程中的只看Segment，section是链接使用的。
因此寻找code cave可以使用加载进内存中但又没什么用的Segement。
比如PT_NOTE、PT_GNU_EH_FRAME，并修改标志位使该段可执行。
函数间的空隙太小，多为10字节以下，暂不考虑使用。
*/
void LibelfEditor::loadCodeDefaultCaves()
{
	for (auto & section : _sections)
	{
		const std::string & name = elf_strptr(_binary, _shstrndx, section.second.sh_name);
		if (name == ".eh_frame" || name == ".eh_frame_hdr")
		{
			CodeCave cave;
			cave.virtual_addr = section.second.sh_addr;
			cave.size = section.second.sh_size;
			InstrumentManager::instance()->addCodeCave(cave);
			std::cout << "LOAD cave " << name << " size: " << cave.size << std::endl;

			GElf_Phdr phdr;
			int id = segment_from_virtual_address(cave.virtual_addr, phdr);
			if (id >= 0 && !(phdr.p_flags & PF_X))
			{
				phdr.p_flags |= PF_X;
				gelf_update_phdr(_binary, id, &phdr);
				std::cout << "Segment " << std::hex << phdr.p_vaddr << " add X flag. " << std::endl;
			}
		}
	}
}

void LibelfEditor::patch_address(uint64_t address, const std::vector<uint8_t> & code)
{
	GElf_Shdr shdr;
	int id = section_from_virtual_address(address, shdr);
	if (id >= 0)
	{
		//std::cout << "SectionName=" << get_section_name(shdr) << " virtualAddr = " << std::hex << shdr.sh_addr << " size = " << shdr.sh_size << std::endl;
		uint64_t offset = address - shdr.sh_addr;
		if (code.size() > shdr.sh_size - offset)
		{
			std::cerr << "write data out of section bound." << std::endl;
			return;
		}

		Elf_Scn * scn = elf_getscn(_binary, id);
		Elf_Data * data = elf_getdata(scn, nullptr);
		std::memcpy(data->d_buf + offset, code.data(), code.size());
		elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
		elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
	}
}

void LibelfEditor::writeFile()
{
	elf_flagelf(_binary, ELF_C_SET, ELF_F_LAYOUT);
	elf_update(_binary, ELF_C_WRITE);
	elf_end(_binary);
	close(_fd);
}

void LibelfEditor::abort()
{
    close(_fd);
}
