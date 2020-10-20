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

uint16_t Config::getBindShellPort()const
{
	uint32_t val;
	_json->get()["policys"]["StartInjectPolicy"]["codeProvider"]["BindShellCodeProvider"].Get("port", val);
	return (uint16_t)val;
}

std::string Config::getCaptureForwardPort()const
{
	uint32_t port;
	_json->get()["policys"]["StartInjectPolicy"]["codeProvider"]["Capture01CodeProvider"].Get("forward_port", port);
	char buf[255] = {0};
	uint8_t s1 = (port & 0x0000ff00)>>8;
	uint8_t s2 = (port & 0xff);
	snprintf(buf, sizeof(buf), "%02x%02x", s2, s1);
	return buf;
}

std::string Config::getCaptureForwardHost()const
{
	std::string val;
	_json->get()["policys"]["StartInjectPolicy"]["codeProvider"]["Capture01CodeProvider"].Get("forward_host", val);

	std::string::size_type pos1 = val.find('.');
	uint8_t s1 = (uint8_t)std::stoul(val.substr(0, pos1));
	std::string::size_type pos2 = val.find('.', pos1 + 1);
	uint8_t s2 = (uint8_t)std::stoul(val.substr(pos1 + 1, pos2 - pos1));
	pos1 = pos2;
	pos2 = val.find('.', pos1 + 1);
	uint8_t s3 = (uint8_t)std::stoul(val.substr(pos1 + 1, pos2 - pos1));
	pos1 = pos2;
	pos2 = val.find('.', pos1 + 1);
	uint8_t s4 = (uint8_t)std::stoul(val.substr(pos1 + 1, pos2 - pos1));
	
	char buf[255] = {0};
	snprintf(buf, sizeof(buf), "%02x%02x%02x%02x", s4,s3,s2,s1);
	return buf;
}
