# SilverPatcher  
一款CTF AWD二进制通用防御补丁工具，目前仅支持x32/x64。  
## 编译安装  
Ubuntu 16.04 x64，使用cmake编译：
```
cmake .
make
```
## 依赖组件  
### CMake  
```
apt install cmake
```
### libelf
```
apt install libelf-dev
```
### LIEF 0.10.1  
https://github.com/lief-project/LIEF  
下载源码，编译安装  
```
wget https://github.com/lief-project/LIEF/archive/0.10.1.tar.gz
tar xvf 0.10.1.tar.gz
cd LIEF-0.10.1
```
LIEF在x32 NO-PIE的情况下，添加segment会导致BUG：
```
Inconsistency detected by ld.so: rtld.c: 1191: dl_main: Assertion `GL(dl_rtld_map).l_libname' failed!
```
解决方法：
在LIEF源码中添加section会添加一个Segment，添加完Segment后调用replace方法将此新段与PT_NOTE互换，即临时解决了此问题。
```
src/ELF/Binary.tcc 631行:
-Segment& segment_added = this->add(new_segment);
+Segment * p_segment_added = nullptr;
+if(this->type() == ELF_CLASS::ELFCLASS32 && this->header().file_type() != E_TYPE::ET_DYN)
+{
+  Segment & note = this->get(SEGMENT_TYPES::PT_NOTE);
+  p_segment_added = &this->replace(new_segment,note);
+}
+else
+{
+  p_segment_added = &this->add(new_segment);
+}
+Segment& segment_added = *p_segment_added;
```
打完补丁后
```
cmake .
make -j4
make install
```
### keystone  
https://github.com/keystone-engine/keystone  
下载源码，编译安装
```
wget https://github.com/keystone-engine/keystone/archive/0.9.2.tar.gz
tar xvf 0.9.2.tar.gz
cd keystone-0.9.2
cmake .
make -j4
make install
```
### capstone  
https://github.com/aquynh/capstone  
```
apt install libcapstone3 libcapstone-dev
```
或者下载源码，编译安装
```
wget https://github.com/aquynh/capstone/archive/4.0.2.tar.gz
tar xvf 4.0.2.tar.gz
cd capstone-4.0.2
./make.sh
```
### CJsonObject  
https://github.com/Bwar/CJsonObject  
这个工程稍微比较麻烦，因为开发者只提供了代码没有想发布链接库的意思，需要我们手工编译生成。
```
git clone https://github.com/Bwar/CJsonObject.git
cd demo
make
cd ..
ar crv libCJsonObject.a cJSON.o CJsonObject.o
cp CJsonObject.hpp /usr/local/include
cp cJSON.h /usr/local/include
cp libCJsonObject.a /usr/local/lib
```
## 使用
<https://github.com/bigBestWay/SilverPatcher/wiki>  
通过修改config.json配置文件，更新libc相关偏移量以及选择想要使用的策略。
```json
{
    "policys":
        {
            "enableNXPolicy":{
                "comment":"开启NX。",
                "level":"SECURE",
                "enable":1
            },
            "BindNowPolicy":{
                "comment":"修改PLTGOT懒加载为立即绑定，抵抗_dl_runtime_solve攻击。",
                "level":"SECURE",
                "enable":1
            },
            "RandomPLTGOTPolicy":{
                "comment":"重新排列PLT/GOT表项。ELF文件大小不变，但变动较大。",
                "level":"LOW",
                "enable":0
            },
            "DisableFreePolicy":{
                "comment":"禁用free达到通防。",
                "level":"SECURE",
                "enable":0
            },
            "RiseStackPolicy":{
                "comment":"在函数的开头抬高栈，抵抗栈溢出攻击，可能要新加代码段。因有些函数代码限制，可能无法自动插入代码。如function列表中可填写函数地址，修改指定地址函数；如果不填写，会尝试修改所有函数。",
                "level":"HIGH",
                "enable":1,
                "functions":[
                    "0x4008B0"
                ]
            },
            "setRPathPolicy":{
                "comment":"修改ELF链接到指定目录下的libc.so.6（可以放置eglibc），需要添加段，这个策略过于UGLY。如果checker检查通过，理论上开启它就可以通防。它与ModifyLibcCodeProvider冲突。",
                "level":"VERYHIGH",
                "enable":0
            },
            "StartInjectPolicy":{
                "comment":"start函数开头代码注入，代码来自下文的CodeProvider",
                "level":"MEDIUM",
                "enable":1
            },
            "FmtVulScanRepairPolicy":{
                "comment":"该策略扫描格式串漏洞，如果配置了patch，则会打补丁。比如有指令0x40086c call printf存在格式化串漏洞，那么就在patch加一个元素：function=printf, callAddress=0x40086c",
                "level":"MEDIUM",
                "enable":0,
                "patch":[
                    {
                        "function":"printf",
                        "callAddress":""
                    },
                    {
                        "function":"printf",
                        "callAddress":""
                    }
                ]
            }
        }
        ,
    "codeProvider":{
        "ModifyLibcCodeProvider":{
            "comment":"对libc中的数据进行修改。它与setRPathPolicy冲突。",
            "enable":0,
            "modifyGlobalMaxFast":{
                "comment":"修改global_max_fast，令malloc关闭或只使用fastbin。value取值范围[1,0x7fffffff]。为1，关闭；为超大值，就会只使用fastbin。",
                "enable":0,
                "value":"0"
            },
            "closeTcache":{
                "comment":"修改mp_.tcache_count，令malloc关闭tcache或改变tcache的最大数量（默认是7）。",
                "enable":0
            },
            "setNoBufStdout":{
                "comment":"设置STDOUT为不缓冲，这个是配合Capture01CodeProvider使用的。",
                "enable":0
            },
            "nopbinsh":{
                "comment":"nop掉libc中的binsh字符串，使system/oneshot失效",
                "enable":1
            }
        },
        "ClearBackdoorCodeProvider":{
            "comment":"当需要清理后门的时候打上一轮即可，下一轮去掉。",
            "enable":0
        },
        "BindShellCodeProvider":{
            "comment":"fork子进程，提供bindtcp_shell，密码固定是8字节。",
            "enable":1,
            "port":56789,
            "password":"abcdefgh"
        },
        "Capture01CodeProvider":{
            "comment":"fork子进程，抓取输入输出并保存到文件。",
            "enable":0,
            "forward_host":"117.78.9.13",
            "forward_port":56789
        }
    },
    "libcdb":{
        "comment":"libcdb内容需要根据比赛环境即时修改",
        "x64":{
            "global_max_fast":"0x3ed940",
            "malloc":"0x40c4b0",
            "__libc_start_main":"0x20750",
            "free":"0x40c620",
            "_IO_2_1_stdout_":"0x3ec760",
            "tcache_count":"0x3eb2e0",
            "str_bin_sh":"0x18CE17"
        },
        "x32":{
            "global_max_fast":"0x1d9904",
            "malloc":"0x2067f0",
            "__libc_start_main":"0x18d90",
            "free":"0x206940",
            "_IO_2_1_stdout_":"0x1d8d80",
            "tcache_count":"0x1d8158",
            "str_bin_sh":""
        }
    }
}
```
## Contact
bigbestway@163.com
