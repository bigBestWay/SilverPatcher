#pragma once
#include <string>
#include <cstdint>
#include <map>

#define GLOBAL_MAX_FAST "global_max_fast"
#define LIBC_START_MAIN "__libc_start_main"
#define MALLOC "malloc"
#define FREE   "free"
#define TCACHE_COUNT "tcache_count"
#define STDOUT "_IO_2_1_stdout_"
#define BINSH "str_bin_sh"

class JsonWrapper;
class Config
{
public:
	static Config * instance();
	static void destroy();
	void init(const std::string & filename);
	std::string getLibcAttrString(const std::string & k)const;
	uint64_t getLibcAttrInt(const std::string & k)const;
	bool isPolicyEnabled(const std::string & name)const;
	bool isProviderEnabled(const std::string & providerName)const;
	bool isProviderActionEnabled(const std::string & providerName, const std::string & action)const;
	std::string getGlobalMaxFastValue()const;
	void getFmtPatchConfig(std::map<uint64_t, std::string> & patchConfig);
	uint16_t getBindShellPort()const;
	std::string getBindShellPasswd()const;
	std::string getCaptureForwardHost()const;
	std::string getCaptureForwardPort()const;
private:
	Config();
	~Config();
private:
	static Config * _instance;
	JsonWrapper * _json;
	std::string _platform;
};

