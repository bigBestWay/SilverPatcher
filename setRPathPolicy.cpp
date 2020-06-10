#include "setRPathPolicy.h"
#include "BinaryEditor.h"

//��RPATHĿ¼�·���libc.so.6��ʹӦ�ü����Լ������libc������eglibc����glibc��ȫ���ݵ�Ƕ��ʽlibc��
#define MY_RPATH "/tmp"

void setRPathPolicy::do_patch()
{
	label("setRPathPolicy");
	DynamicEntry * entry = nullptr;
	DynamicEntryRpath * rpathEntry = nullptr;
	if (BinaryEditor::instance()->getDynamicEntrysByTag(DYNAMIC_TAGS::DT_RPATH, entry))
	{
		rpathEntry = dynamic_cast<DynamicEntryRpath *>(entry);
		if (rpathEntry == nullptr)
		{
			std::cerr << "RPATH entry cast error." << std::endl;
			return;
		}
		rpathEntry->insert(0, MY_RPATH);
		std::cout << "Insert RPATH[0] " << MY_RPATH << std::endl;
	}
	else
	{
		rpathEntry = new DynamicEntryRpath();
		rpathEntry->append(MY_RPATH);
		rpathEntry = dynamic_cast<DynamicEntryRpath *>(&BinaryEditor::instance()->add(*rpathEntry));
		std::cout << "Add RPATH entry " << MY_RPATH << std::endl;
	}

}
