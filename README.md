#SilverPatcher  
一款CTF AWD二进制防御补丁工具  
##编译安装  
Ubuntu 16.04 x64，使用cmake编译：
```
cmake .
make
```
##依赖组件  
###CMake  
```
apt install cmake
```
###LIEF 0.10.1  
https://github.com/lief-project/LIEF  
直接下载已编译好的SDK包(x86_64)  
```
wget https://github.com/lief-project/LIEF/releases/download/0.10.1/LIEF-0.10.1-Linux.tar.gz
tar xvf LIEF-0.10.1-Linux.tar.gz
cd LIEF-0.10.1-Linux
cp -r include/ /usr/local/
cp -r lib/ /usr/local/
```
或者下载源码，编译安装（推荐）  
LIEF在x32 NO-PIE的情况下，添加segment会导致BUG：
```
Inconsistency detected by ld.so: rtld.c: 1191: dl_main: Assertion `GL(dl_rtld_map).l_libname' failed!
```
解决方法：
在LIEF源码中添加section会添加一个Segment，添加完Segment后调用replace方法将此新段与PT_NOTE互换，即临时解决了此问题。
```
src/ELF/Binary.tcc 631行:
-Segment& segment_added = this->add(new_segment);
+Segment * segment_added = nullptr;
+if(this->type() == ELF_CLASS::ELFCLASS32 && this->header().file_type() != E_TYPE::ET_DYN)
+{
+  Segment & note = this->get(SEGMENT_TYPES::PT_NOTE);
+  segment_added = &this->replace(new_segment,note);
+}
+else
+{
+  segment_added = &this->add(new_segment);
+}
```
打完补丁后
```
cmake .
make -j4
make install
```
###dyninst 10.1.0  
https://github.com/dyninst/dyninst/archive/v10.1.0.tar.gz  
一个非常庞大、复杂、历史悠久的库，安装起来可能比较麻烦...  
首先装一些基础库
```
apt-get install cmake libblkid-dev e2fslibs-dev libboost-all-dev libaudit-dev texlive-latex-base libelf-dev libdwarf-dev libiberty-dev
```
make过程中会主动下载TBB、ElfUtils等源码进行编译
```
cmake .
make -j4
make install
```
###keystone  
https://github.com/keystone-engine/keystone  
下载源码，编译安装
```
cmake .
make -j4
make install
```
###capstone  
https://github.com/aquynh/capstone  
```
apt install libcapstone3 libcapstone-dev
```
或者下载源码，编译安装
```
./make.sh
```
###CJsonObject  
https://github.com/Bwar/CJsonObject  
这个工程稍微比较麻烦，因为开发者只提供了代码没有想发布链接库的意思，需要我们手工编译生成。
```
cd demo
make
cd ..
ar crv libCJsonObject.a cJSON.o CJsonObject.o
cp CJsonObject.hpp /usr/local/include
cp cJSON.h /usr/local/include
cp libCJsonObject.a /usr/local/lib
```
##使用
通过修改config.json配置文件，更新libc相关偏移量以及选择想要使用的策略。
```
{
    "pwn_property":{
        "libc_version":"2.23"
    },
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
                "enable":1
            },
            "DisableFreePolicy":{
                "comment":"比较UGLY，禁用free达到通防。",
                "level":"SECURE",
                "enable":0
            },
            "RiseStackPolicy":{
                "comment":"在函数的开头抬高栈，抵抗栈溢出攻击，需要新加代码段。因有些函数代码限制，可能无法自动插入代码。",
                "level":"HIGH",
                "enable":0
            },
            "setRPathPolicy":{
                "comment":"修改ELF链接到指定目录下的libc.so.6（可以放置eglibc），需要添加段，这个策略过于UGLY。如果checker检查通过，理论上开启它就可以通防。它与ModifyLibcCodeProvider冲突。",
                "level":"VERYHIGH",
                "enable":0
            },
            "StartInjectPolicy":{
                "comment":"该策略在start()开头插入代码执行想要的功能。",
                "level":"MEDIUM",
                "enable":1,
                "codeProvider":{
                    "ModifyLibcCodeProvider":{
                        "comment":"对libc中的数据进行修改。它与setRPathPolicy冲突。",
                        "enable":1,
                        "modifyGlobalMaxFast":{
                            "comment":"修改global_max_fast，令malloc关闭或只使用fastbin。value取值范围[1,0x7fffffff]。为1，关闭；为超大值，就会只使用fastbin。",
                            "enable":0,
                            "value":"1"
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
                        "enable":0,
                        "port":56789,
                        "password":"abcdefgh"
                    },
                    "Capture01CodeProvider":{
                        "comment":"fork子进程，抓取输入输出并保存到文件。",
                        "enable":0,
                        "forward_host":"117.78.9.13",
                        "forward_port":56789
                    }
                }
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
    "libcdb":{
        "comment":"libcdb内容需要根据比赛环境即时修改",
        "2.23":{
            "x64":{
                "global_max_fast":"0x3c67f8",
                "malloc":"0x84130",
                "__libc_start_main":"0x20750",
                "free":"0x844f0",
                "_IO_2_1_stdout_":"0x3c5620",
                "str_bin_sh":"0x18ce17"
            },
            "x32":{
                "global_max_fast":"0x1b38e0",
                "malloc":"0x1f5110",
                "__libc_start_main":"0x18550",
                "free":"0x1f5180",
                "_IO_2_1_stdout_":"0x1b2d60",
                "str_bin_sh":"0x15bb0b"
            }
        },
        "2.27": {
            "X64":{
                "global_max_fast":"0x3ed940",
                "malloc":"0x40c4b0",
                "__libc_start_main":"0x21ab0",
                "free":"0x40c620",
                "_IO_2_1_stdout_":"0x3ec760",
                "tcache_count":"0x3eb2e0",
                "str_bin_sh":""
            },
            "X32":{
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
}
```
##Contact
nu00string@gmail.com
