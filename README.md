#SilverPatcher
一款CTF AWD二进制防御补丁工具  
##编译安装
Ubuntu 16.04 x64，IDE使用VS2017远程编译。
##依赖组件
###LIEF
https://github.com/lief-project/LIEF
###dyninst
https://github.com/dyninst/dyninst  
###keystone
https://github.com/keystone-engine/keystone
###capstone
https://github.com/aquynh/capstone
###CJsonObject
https://github.com/Bwar/CJsonObject
##使用
通过修改config.json配置文件，选择想要使用的策略。
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
            "ResortGotEntryPolicy":{
                "comment":"重新排列GOT表项，抵抗GOT劫持。ELF文件大小不变，但变动较大。",
                "level":"LOW",
                "enable":1
            },
            "DisableFreePolicy":{
                "comment":"比较UGLY，禁用free达到通防。",
                "level":"SECURE",
                "enable":1
            },
            "RiseStackPolicy":{
                "comment":"在函数的开头抬高栈，抵抗栈溢出攻击，需要新加代码段。因有些函数代码限制，可能无法自动插入代码。",
                "level":"HIGH",
                "enable":1
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
                            "enable":1,
                            "value":"1"
                        },
                        "closeTcache":{
                            "comment":"修改mp_.tcache_count，令malloc关闭tcache或改变tcache的最大数量（默认是7）。",
                            "enable":1
                        },
                        "setNoBufStdout":{
                            "comment":"设置STDOUT为不缓冲，这个是配合Capture01CodeProvider使用的。",
                            "enable":1
                        }
                    },
                    "BindShellCodeProvider":{
                        "comment":"fork子进程，提供bindtcp_shell，密码XXXXXXXX。",
                        "enable":1,
                        "port":56789
                    },
                    "Capture01CodeProvider":{
                        "comment":"fork子进程，抓取输入输出并保存到文件。",
                        "enable":1
                    }
                }
            },
            "FmtVulScanRepairPolicy":{
                "comment":"该策略扫描格式串漏洞，如果配置了patch，则会打补丁。比如有指令0x40086c call printf存在格式化串漏洞，那么就在patch加一个元素：function=printf, callAddress=0x40086c",
                "level":"MEDIUM",
                "enable":1,
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
        "comment":"libcdb内容不需要修改。",
        "2.23":{
            "x64":{
                "global_max_fast":"0x3c67f8",
                "malloc":"0x84130",
                "__libc_start_main":"0x20740",
                "free":"0x844f0",
                "stdout":"0x3c5620"
            },
            "x32":{
                "global_max_fast":"0x1b38e0",
                "malloc":"0x1f5110",
                "__libc_start_main":"0x18540",
                "free":"0x1f5180",
                "stdout":"0x1b2d60"
            }
        },
        "2.27": {
            "X64":{
                "global_max_fast":"0x3ed940",
                "malloc":"0x40c4b0",
                "__libc_start_main":"0x21ab0",
                "free":"0x40c620",
                "stdout":"0x3ec760",
                "tcache_count":"0x3eb2e0"
            },
            "X32":{
                "global_max_fast":"0x1d9904",
                "malloc":"0x2067f0",
                "__libc_start_main":"0x18d90",
                "free":"0x206940",
                "stdout":"0x1d8d80",
                "tcache_count":"0x1d8158"
            }
        }
    }
}
```