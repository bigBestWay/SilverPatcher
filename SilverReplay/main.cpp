#include <cstdio>
#include <cstdint>
#include <cstring>

struct TlvHead
{
	uint32_t tag;
	uint32_t len;
};

bool is_printable(uint8_t c)
{
	return (c >= 0x20 && c <= 128) || c == '\t' || c == '\r' || c == '\n';
}

bool is_printable(uint8_t  * buf)
{
	for (int i = 0; i < 6; ++i)
	{
		if (!is_printable(buf[i]))
		{
			return false;
		}
	}
	return true;
}

uint64_t findLeakAddress(uint8_t * buff)
{
	//libcй¶0x00007ffff7475000��ͨ������6�ֽڣ�û��ǰ��2��0
	const int64_t libcPattern =  0x0000700000000000;
	const int64_t imagePattern = 0x0000500000000000;
	const int64_t maxRange =     0x00000fffffffffff;

	int64_t val = 0;
	std::memcpy(&val, buff, 6);
	if (val - libcPattern > 0 && val - libcPattern < maxRange)
	{
		return val;
	}

	if (val - imagePattern > 0 && val - imagePattern < maxRange)
	{
		return val;
	}
	return 0;
}

void dump(uint8_t * buff, int len)
{
	for (int i = 0; i < len; ++i)
	{
		if (len - i > 6)
		{
			//6���ַ����ǿɴ�ӡ�ַ����Ͳ��ǵ�ַ
			uint64_t addr = findLeakAddress(buff + i);
			if (addr && !is_printable(buff + i))
			{
				printf("FOUND LEAKADDRESS 0x%lx\n", addr);
			}
		}

		if (is_printable(buff[i]))
		{
			printf("%c", buff[i]);
		}
		else
		{
			printf("%02x", buff[i]);
		}
	}
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		printf("%s <path>\n", argv[0]);
		return 1;
	}

	const uint32_t tag_in = 0x12345678;
	const uint32_t tag_out = 0x87654321;
	FILE * fp = fopen(argv[1], "r");
	if (fp)
	{
		do 
		{
			TlvHead tlv;
			fread(&tlv, sizeof(tlv), 1, fp);
			uint8_t * buf = new uint8_t[tlv.len];
			fread(buf, tlv.len, 1, fp);
			if (tlv.tag == tag_in)
			{
				printf("\nINPUT:\n");
				dump(buf, tlv.len);
			}
			else if(tlv.tag == tag_out)
			{
				printf("\nOUT:\n");
				dump(buf, tlv.len);
			}
			else
			{
				printf("error %d\n", tlv.tag);
				return 1;
			}
			delete[] buf;
		} while (!feof(fp));
		fclose(fp);
	}
	return 0;
}
