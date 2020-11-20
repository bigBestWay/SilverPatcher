#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define NONE                 "\e[0m"
#define BLACK                "\e[0;30m"
#define L_BLACK              "\e[1;30m"
#define RED                  "\e[0;31m"
#define L_RED                "\e[1;31m"
#define GREEN                "\e[0;32m"
#define L_GREEN              "\e[1;32m"
#define BROWN                "\e[0;33m"
#define YELLOW               "\e[1;33m"
#define BLUE                 "\e[0;34m"
#define L_BLUE               "\e[1;34m"
#define PURPLE               "\e[0;35m"
#define L_PURPLE             "\e[1;35m"
#define CYAN                 "\e[0;36m"
#define L_CYAN               "\e[1;36m"
#define GRAY                 "\e[0;37m"
#define WHITE                "\e[1;37m"

#define BOLD                 "\e[1m"
#define UNDERLINE            "\e[4m"
#define BLINK                "\e[5m"
#define REVERSE              "\e[7m"
#define HIDE                 "\e[8m"
#define CLEAR                "\e[2J"
#define CLRLINE              "\r\e[K" //or "\e[1K\r"

typedef struct
{
	uint32_t tag;
	uint32_t len;
}TlvHead;

int is_printable(uint8_t c)
{
    if(c == 0 || c == 10)
        return 2;
    //堆或者栈、libc地址
    if(c == 0x7f || c == 0x55 || c == 0x56)
        return 3;
	if(c >= 0x20 && c <= 0x7e)
        return 1;
    return 0;
}

void printChar(const uint8_t * line, int size)
{
    for(int i = 0; i < size; ++i)
    {
        if(i % 4 == 0)
            printf("|");
        if(is_printable(line[i]) == 1)
            printf("%c", line[i]);
        else
            printf(".");
    }
    printf("\n");
}

void printHex(uint8_t c)
{
    int result = is_printable(c);
    if(result == 1)
        printf(BLUE"%02x "NONE, c);
    else if(result == 2)
        printf(RED"%02x "NONE, c);
    else if(result == 3)
        printf(YELLOW"%02x "NONE, c);
    else
        printf("%02x ", c);  
}

void dump(const uint8_t * buff, int len)
{
    int linenum = len / 16;
    int rest = len % 16;

	for (int i = 0; i < linenum; ++i)
	{
        const uint8_t * line = buff + i*16;  
        for(int j = 0; j < 16; ++j)
        {
            if(j % 4 == 0)
                printf(" ");
            
            printHex(line[j]);            
        }
        printChar(line, 16);
	}
    
    const uint8_t * line = buff + linenum*16; 
    for(int j = 0; j < 16; ++j)
    {
        if(j % 4 == 0)
            printf(" ");
            
        if(j >= rest)
            printf("   ");
        else
        {
            printHex(line[j]);
        }
    }
    printChar(line, rest);
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
    
    printf(GREEN"+++++ Begin +++++"NONE);
    
	int fd = open(argv[1], 0);
	if (fd > 0)
	{
		do 
		{
			TlvHead tlv;
			int len = read(fd, &tlv, sizeof(tlv));
            if(len <= 0)
                break;
			uint8_t * buf = malloc(tlv.len);
			len = read(fd, buf, tlv.len);
            if(len <= 0)
                break;
			if (tlv.tag == tag_in)
			{
				printf(BOLD"\nSENT %d bytes:\n"NONE, tlv.len);
				dump(buf, tlv.len);
			}
			else if(tlv.tag == tag_out)
			{
				printf(BOLD"\nRECV %d bytes:\n"NONE, tlv.len);
				dump(buf, tlv.len);
			}
			else
			{
				printf("error %d\n", tlv.tag);
				return 1;
			}
			free(buf);
		} while (1);
		close(fd);
	}
    
    printf(GREEN"\n+++++ End +++++\n"NONE);
	return 0;
}
