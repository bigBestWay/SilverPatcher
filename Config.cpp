#include "Config.h"
#include "CJsonObject.hpp"
#include <iostream>
#include "BinaryEditor.h"

using namespace neb;

class JsonWrapper
{
public:
	JsonWrapper(const std::string & str):_obj(str)
	{
	}

	~JsonWrapper() 
	{
	}

	CJsonObject & get()
	{
		return _obj;
	}

private:
	CJsonObject _obj;
};

Config::Config():_json(0)
{

}

Config::~Config()
{
	delete _json;
	_json = nullptr;
}

std::string Config::getLibcAttrString(const std::string & k) const
{
	std::string str;
	_json->get()["libcdb"][_libc_version][_platform].Get(k, str);
	return str;
}

uint64_t Config::getLibcAttrInt(const std::string & k) const
{
	uint64 val = 0;
	_json->get()["libcdb"][_libc_version][_platform].Get(k, val);
	return val;
}

bool Config::isPolicyEnabled(const std::string & name) const
{
	int val = 0;
	_json->get()["policys"][name].Get("enable", val);
	return val != 0;
}

bool Config::isProviderEnabled(const std::string & policyName, const std::string & providerName) const
{
	int val = 0;
	_json->get()["policys"][policyName]["codeProvider"][providerName].Get("enable", val);
	return val != 0;
}

bool Config::isProviderActionEnabled(const std::string & policyName, const std::string & providerName, const std::string & action) const
{
	int val = 0;
	_json->get()["policys"][policyName]["codeProvider"][providerName][action].Get("enable", val);
	return val != 0;
}

std::string Config::getGlobalMaxFastValue() const
{
	std::string val;
	_json->get()["policys"]["StartInjectPolicy"]["codeProvider"]["ModifyLibcCodeProvider"]["modifyGlobalMaxFast"].Get("value", val);
	return val;
}

void Config::getFmtPatchConfig(std::map<uint64_t, std::string> & patchConfig)
{
	CJsonObject & fmtPolicy = _json->get()["policys"]["FmtVulScanRepairPolicy"]["patch"];
	int size = fmtPolicy.GetArraySize();
	for (int i = 0; i < size; ++i)
	{
		CJsonObject obj;
		if (fmtPolicy.Get(i, obj))
		{
			std::string function, addr;
			obj.Get("function", function);
			obj.Get("callAddress", addr);
			if (addr.empty() || function.empty())
			{
				continue;
			}

			uint64_t hexAddr = std::stoul(addr, nullptr, 16);
			patchConfig[hexAddr] = function;
		}
	}
}

Config * Config::_instance = nullptr;

Config * Config::instance()
{
	if (_instance == nullptr)
	{
		_instance = new Config;
	}
	return _instance;
}

void Config::destroy()
{
	delete _instance;
	_instance = nullptr;
}

void Config::init(const std::string & filename)
{
	FILE * fp = fopen(filename.c_str(), "r");
	if (fp)
	{
		fseek(fp, 0, SEEK_END);
		long length = ftell(fp);
		char * buff = new char[length];
		fseek(fp, 0, SEEK_SET);
		fread(buff, length, 1, fp);
		fclose(fp);

		_json = new JsonWrapper(buff);
		if (BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS64)
		{
			_platform = "x64";
		}
		else
		{
			_platform = "x32";
		}
		_json->get()["pwn_property"].Get("libc_version", _libc_version);
	}
	else
	{
		std::cerr << "config.ini not found" << std::endl;
	}
}
