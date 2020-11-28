#include "BindNowPolicy.h"
#include "BinaryEditor.h"

/*RELRO�Ǹ�������˼�Ķ�������ʵ�������������棺
1��������
2���󶨺��ȡ�Ķ�̬��ַ���GOT��ֻ��
GNU��ʵ��ʱ������������ȫ���������ԡ�
���������±���ѡ�
-z now -z norelro�������󶨣��������PT_GNU_RELRO�Σ�.got.plt��.got����д
-z relro����ʱ�󶨣����PT_GNU_RELRO�Σ�ֻ��.gotֻ����.got.plt��Ȼ��д
-z now��  �����󶨣����PT_GNU_RELRO�Σ�.gotֻ����.got.plt��ȡ����pltֱ�ӵ���.got�ڵ�ַ�ˣ�
PT_GNU_RELRO�������ַ��size��ָ����Ҫ����Ϊֻ�������򣬿�ͨ��readelf -l �鿴������Щ�ڣ������Χ������ҳ����ģ���������ַ������0x1000������
����ǿ�����GOT����Ϊֻ���ǲ����ܵģ�ֻ�ܻ�һ�����۵ķ������Ǿ��ǲ���ResortGotEntryPolicy������GOT��˳�����ӻ�������
*/
void BindNowPolicy::do_patch()
{
	label("BindNowPolicy");
	if (BinaryEditor::instance()->isBindNow())
	{
		std::cout << "Got BindNow already SUPPORT." << std::endl;
		return;
	}

	//����DynamicEntry DT_BIND_NOW֮�������󶨣�����PT_GNU_RELRO�λ�������Ӧ��ΧΪֻ��
	//got[1]��got[0]����0������ret2dl_resolve_runtime�Ͳ�������
	//Ϊ�˱��������´���Σ����ｫDT_DEBUG���޸�ΪDT_BIND_NOW ��������ֻʵ�ִ˲��裩
	if (BinaryEditor::instance()->enableBindnow())
	{
		std::cout << "Modify DT_DEBUG to DT_BIND_NOW." << std::endl;
	}
	else
	{
		std::cout << "Not found DT_DEBUG." << std::endl;
	}
}
