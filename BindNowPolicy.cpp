#include "BindNowPolicy.h"
#include "BinaryEditor.h"

/*RELRO是个很有意思的东西，其实包含了两个方面：
1、立即绑定
2、绑定后获取的动态地址表项（GOT）只读
GNU在实现时，这两个是完全独立的特性。
可以有如下编译选项：
-z now -z norelro，立即绑定，但不添加PT_GNU_RELRO段，.got.plt和.got都可写
-z relro，延时绑定，添加PT_GNU_RELRO段，只有.got只读，.got.plt依然可写
-z now，  立即绑定，添加PT_GNU_RELRO段，.got只读，.got.plt节取消（plt直接调用.got节地址了）
PT_GNU_RELRO中虚拟地址和size，指定了要设置为只读的区域，可通过readelf -l 查看包含哪些节，这个范围必须是页对齐的，即结束地址必须是0x1000整数倍
所以强制添加GOT表项为只读是不可能的，只能换一种曲折的方案，那就是策略ResortGotEntryPolicy，打乱GOT表顺序来延缓攻击。
*/
void BindNowPolicy::do_patch()
{
	label("BindNowPolicy");
	if (BinaryEditor::instance()->isBindNow())
	{
		std::cout << "Got BindNow already SUPPORT." << std::endl;
		return;
	}

	//增加DynamicEntry DT_BIND_NOW之后，立即绑定，增加PT_GNU_RELRO段会设置相应范围为只读
	//got[1]和got[0]都是0，这样ret2dl_resolve_runtime就不能用了
	//为了避免增加新代码段，这里将DT_DEBUG段修改为DT_BIND_NOW （本策略只实现此步骤）
	if (BinaryEditor::instance()->enableBindnow())
	{
		std::cout << "Modify DT_DEBUG to DT_BIND_NOW." << std::endl;
	}
	else
	{
		std::cout << "Not found DT_DEBUG." << std::endl;
	}
}
