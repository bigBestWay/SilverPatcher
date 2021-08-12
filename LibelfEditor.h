#pragma once
#include<vector>
#include<string>
#include<stdint.h>

class LibelfEditor
{
public:
    static bool init(const char * filename);
    static void patch_address(uint64_t address, const std::vector<uint8_t> & code);
    static std::vector<uint8_t> get_content_from_virtual_address(uint64_t address, uint64_t size);
    static void writeFile();
    static void abort();
    static bool copy_file(const std::string & infile, const std::string & outfile);
	static bool enable_nx();
	static bool enable_bindnow();
	static void symbol_swap(const std::string & name1, const std::string & name2);
    static uint64_t entryPoint();
private:
    static void loadCodeDefaultCaves();
};
