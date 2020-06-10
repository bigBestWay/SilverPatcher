#include "Capture01CodeProvider.h"
#include "BinaryEditor.h"
#include "KSEngine.h"

/*
#include<stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <poll.h>
#include<sys/ioctl.h>

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		printf("%s execute.\n", argv[0]);
		return 1;
	}

	int fd[2];
	socketpair(AF_LOCAL, SOCK_STREAM, 0, fd);
	int parent = fd[0];
	int child = fd[1];
	if (fork() > 0)
	{
		close(child);
		//ioctl(0, FIONBIO, NULL);
		while (1)
		{
			struct pollfd key_fds[2];
			key_fds[0].fd = parent;
			key_fds[0].events = POLLIN | POLLPRI;
			key_fds[1].fd = 0;
			key_fds[1].events = POLLIN | POLLPRI;
			int result = poll(&key_fds, 2, -1);
			if (result == -1)
			{
				exit(1);
			}

			if (key_fds[0].revents & POLLIN || key_fds[0].revents & POLLPRI)
			{
				char buf[256] = { 0 };
				int len = read(parent, buf, 256);
				write(1, buf, len);
			}

			if (key_fds[1].revents & POLLIN || key_fds[1].revents & POLLPRI)
			{
				char buf[256] = { 0 };
				int len = read(0, buf, 256);
				write(parent, buf, len);
			}
		}
	}
	else
	{
		close(parent);
		dup2(child, 0);
		dup2(child, 1);
		dup2(child, 2);
		close(child);
		execve(argv[1], NULL, NULL);
	}

	return 0;
}


*/

void Capture01CodeProvider::getCode(uint64_t virtualAddress, std::vector<uint8_t> & allcode)
{
	//位置无关
	/*保存在文件中的报文，按照如下TLV格式
		TAG: 4bytes, 0x12345678 表示输入
		     4bytes, 0x87654321 表示输出
		LEN: 4bytes
		VALUE: len字节
	*/
	if (BinaryEditor::instance()->getPlatform() == ELF_CLASS::ELFCLASS64)
	{
		std::string asmCode = "\
			sub rsp,0x200;\
			xor rsi,rsi;\
			mov rdx,rsi;\
			inc rsi;\
			mov rdi,rsi;\
			lea r10,[rsp];"//int fd[2] 8bytes offset 0, fd[0] [rsp] child, fd[1] parent rsp+4
			"call socketpair;\
			call fork;\
			test eax,eax;\
			jz child;\
			mov edi, dword ptr [rsp];\
			call close;"//关闭child fd
			"lea rdi,[rsp+8];"//filename offset 8, size 0x18
			"call getRandom;\
			lea rax,[rsp+0x18];\
			mov qword ptr [rax],0x7061632E;\
			lea rdi,[rsp+8];"//;filename offset 8, size 0x18
			"push 0x41;\
			pop rsi;\
			call open;"//;open(pcap, O_CREATE|O_WRONLY)
			"mov dword ptr [rsp + 0x20], eax ;"//filefd offset 0x20, size 4
			"mov eax,dword ptr [rsp+4];"//parent fd
			"mov dword ptr [rsp + 0x28], eax;"//struct pollfd[0]:fd  size 4. struct pollfd有两个元素，共16字节，偏移量0x28
			"mov word ptr [rsp + 0x2c],3;"//struct pollfd[0]:events
			"mov dword ptr [rsp + 0x30], 0;"//struct pollfd[1]:fd
			"mov word ptr [rsp + 0x34],3;"//struct pollfd[1]:events POLLIN 1|POLLRI 2
			"\
		pollloop:\n\
			lea rdi,[rsp+0x28];\
			push 2;\
			pop rsi;\
			movq rdx,0xffffffffffffffff;\
			call poll;\
			cmp eax,0xffffffff;\
			jz pollloop;\
			mov ax,word ptr [rsp+0x2e];\
			and ax,1;\
			test ax,ax;\
			jnz dataComeChild;\
			mov ax,word ptr [rsp+0x2e];\
			and ax,2;\
			test ax,ax;\
			jz nextFdCheck;\
		dataComeChild:\n\
			mov edi,dword ptr [rsp+4];"//child fd
			"lea rsi,[rsp+0x100];"//rsp+0x100 buff
			"push 0x100;\
			pop rdx;\
			call read;"//int len = read(childfd, buff, 0x100)
			"xchg eax,edx;\
			mov edi,1;\
			call write;"//write(1, buff, len)
			"mov edi,dword ptr [rsp + 0x20];"//filefd
			"lea rsi, [rsp+0x40];\
			mov dword ptr [rsi], 0x87654321;"//OUT TAG 0x87654321
			"mov dword ptr[rsi+4], edx;"//OUT LEN
			"push rdx;"//save len
			"push 0x8;\
			pop rdx;\
			call write;\
			pop rdx;"//restore read len
			"lea rsi,[rsp+0x100];"//rsp+0x100 buff
			"call write;"//write(filefd, buff, readlen);
		"nextFdCheck:\n"
			"mov ax,word ptr [rsp+0x36];\
			and ax,1;\
			test ax,ax;\
			jnz dataComeStdin;\
			mov ax, word ptr[rsp + 0x36]; \
			and ax,2;\
			test ax,ax;\
			jz pollloop;\
		dataComeStdin:\n\
			xor rdi,rdi;\
			lea rsi,[rsp+0x100];"//rsp+0x100 buff
			"push 0x100;\
			pop rdx;\
			call read;"//read(0,buff,0x100)
			"xchg eax,edx;\
			mov edi,dword ptr [rsp+4];"//childfd
			"call write;"//write(childfd, buf, len)
			"mov edi,dword ptr [rsp + 0x20];"//filefd
			"lea rsi, [rsp+0x40];\
			mov dword ptr[rsi], 0x12345678;"//IN TAG 0x12345678
			"mov dword ptr [rsi+4], edx;"//TAG LEN
			"push rdx;"//save read len
			"push 0x8;\;\
			pop rdx;\
			call write;\
			pop rdx;"//restore len
			"lea rsi,[rsp+0x100];"//rsp+0x100 buff
			"call write;\
			jmp pollloop;\
		getRandom:\n\
			push rdi;\
			sub rsp,0x10;\
			mov rax, 0x6172752f7665642f;\
			mov qword ptr [rsp],rax;\
			mov qword ptr [rsp+8], 0x6d6f646e;\
			mov rdi,rsp;\
			xor rsi,rsi;\
			call open;\
			xchg rax,rdi;\
			lea rsi,[rsp];\
			push 0x8;\
			pop rdx;\
			call read;\
			call close;\
			mov rdi,rsi;\
			add rsp,0x10;\
			pop rsi;\
			call hex2str;\
			ret;\
		hex2str:\n\
			xor     edx, edx;\
			loop1:\n\
			movzx   eax, byte ptr[rdi + rdx];\
			mov     r9d, eax;\
			and     eax, 0Fh;\
			shr     r9b, 4;\
			lea     ecx, [r9 + 30h];\
			lea     r8d, [r9 + 57h];\
			cmp     r9b, 0Ah;\
			lea     r9d, [rax + 57h];\
			cmovb   r8d, ecx;\
			lea     ecx, [rax + 30h];\
			cmp     al, 0Ah;\
			mov     eax, r9d;\
			mov[rsi + rdx * 2], r8b;\
			cmovb   eax, ecx;\
			mov[rsi + rdx * 2 + 1], al;\
			add     rdx, 1;\
			cmp     rdx, 8;\
			jnz     loop1;\
			ret;\
		socketpair:\n\
			push 0x35;\
			pop rax;\
			syscall;\
			ret;\
		fork:\n\
			push 0x39;\
			pop rax;\
			syscall;\
			ret;\
		open:\n\
			push 0x2;\
			pop rax;\
			syscall;\
			ret;\
		read:\n\
			xor rax,rax;\
			syscall;\
			ret;\
		close:\n\
			push 0x3;\
			pop rax;\
			syscall;\
			ret;\
		write:\n\
			push 0x1;\
			pop rax;\
			syscall;\
			ret;\
		dup2:\n\
			push 0x21;\
			pop rax;\
			syscall;\
			ret;\
		poll:\n\
			push 0x7;\
			pop rax;\
			syscall;\
			ret;\
		child:\n\
			xor rdi,rdi;\
			mov edi, dword ptr [rsp+4];\
			call close;\
			mov edi, dword ptr [rsp];\
			xor rsi,rsi;\
			call dup2;\
			inc rsi;\
			call dup2;\
			inc rsi;\
			call dup2;\
			call close;\
			add rsp, 0x200\
			";
		std::vector<uint8_t> codeX64;
		KSEngine::instance()->assemble(asmCode.c_str(), 0, codeX64);
		allcode.insert(allcode.end(), codeX64.begin(), codeX64.end());
	}
	else
	{
		//32位系统调用参数: ebx,ecx,edx,esi,edi
		std::string x32asm = "\
			sub esp,0x200;\
			xor edx,edx;\
			mov ebx,edx;\
			inc ebx;\
			mov ecx,ebx;\
			lea esi,[esp];"//int fd[2] 8bytes offset 0, fd[0] [esp] child, fd[1] parent esp+4
			"call socketpair;\
			call fork;\
			test eax,eax;\
			jz child;\
			mov ebx, dword ptr [esp];\
			call close;"//关闭child fd
			"lea ebx,[esp+8];"//filename offset 8, size 0x18
			"call getRandom;\
			mov dword ptr [esp+0x18],0x7061632E;\
			mov byte ptr [esp+0x1c],0;\
			lea ebx,[esp+8];"//;filename offset 8, size 0x18
			"push 0x41;\
			pop ecx;\
			call open;"//;open(pcap, O_CREATE|O_WRONLY)
			"mov dword ptr [esp + 0x20], eax ;"//filefd offset 0x20, size 4 两个元素，1个parentfd，1个stdin
			"mov eax,dword ptr [esp+4];"//parent fd
			"mov dword ptr [esp + 0x28], eax;"//struct pollfd[0]:fd  size 4. 
			"mov word ptr [esp + 0x2c], 3;"//struct pollfd[0]:events
			"mov dword ptr [esp + 0x30], 0;"//struct pollfd[1]:fd stdin
			"mov word ptr [esp + 0x34], 3;"//struct pollfd[1]:events
			"\
		pollloop:\n\
			lea ebx,[esp+0x28];\
			push 2;\
			pop ecx;\
			mov edx,0xffffffff;\
			call poll;\
			cmp eax,0xffffffff;\
			jz pollloop;\
			mov ax,word ptr [esp+0x2e];\
			and ax,1;\
			test ax,ax;\
			jnz childDataIn;\
			mov ax,word ptr [esp+0x2e];\
			and ax,2;\
			test ax,ax;\
			jz nextFdCheck;\
		childDataIn:\n\
			mov ebx,dword ptr [esp+4];"//parent fd
			"lea ecx,[esp+0x100];"//esp+0x100 buff
			"push 0x100;\
			pop edx;\
			call read;"//int len = read(parentfd, buff, 0x100)
			"xchg eax,edx;\
			mov ebx,1;\
			call write;"//write(1, buff, len)
			"mov ebx,dword ptr [esp + 0x20];"//filefd
			"lea ecx, [esp+0x40];\
			mov dword ptr [ecx], 0x87654321;"//OUT TAG
			"mov dword ptr [ecx+4],edx;"//OUT LEN
			"push edx;"//save len
			"push 0x8;\
			pop edx;\
			call write;\
			pop edx;"//restore read len
			"lea ecx,[esp+0x100];"//esp+0x100 buff
			"call write;\
		nextFdCheck:\n\
			mov ax,word ptr [esp+0x36];\
			and ax,1;\
			test ax,ax;\
			jnz stdinDataCome;\
			mov ax,word ptr [esp+0x36];\
			and ax,2;\
			test ax,ax;\
			jz pollloop;\
		stdinDataCome:\n\
			xor ebx,ebx;\
			lea ecx,[esp+0x100];"//esp+0x100 buff
			"push 0x100;\
			pop edx;\
			call read;"//read(0,buff,0x100)
			"xchg eax,edx;\
			mov ebx,dword ptr [esp+4];"//childfd
			"call write;"//write(childfd, buf, len)
			"mov ebx,dword ptr [esp + 0x20];"//filefd
			"lea ecx, [esp+0x40];\
			mov dword ptr[ecx], 0x12345678;"//IN TAG
			"mov dword ptr [ecx+4],edx;"//TAG LEN
			"push edx;"//save read len
			"push 0x8;\;\
			pop edx;\
			call write;\
			pop edx;"//restore len
			"lea ecx,[esp+0x100];"//esp+0x100 buff
			"call write;\
			jmp pollloop;\
		getRandom:\n\
			push ebx;\
			sub esp,0x10;\
			mov dword ptr [esp],0x7665642f;\
			mov dword ptr [esp+4], 0x6172752f;\
			mov dword ptr [esp+8], 0x6d6f646e;\
			mov ebx,esp;\
			xor ecx,ecx;\
			call open;\
			xchg eax,ebx;\
			lea ecx,[esp];\
			push 0x8;\
			pop edx;\
			call read;\
			call close;\
			mov ebx,ecx;\
			add esp,0x10;\
			pop ecx;\
			call hex2str;\
			ret;\
		hex2str:\n\
			mov    edi,ebx;\
			mov    esi, ecx;\
			xor    ebx, ebx;\
			xchg   ax, ax;\
		loop1:\n\
			movzx  ecx, BYTE PTR[edi + ebx * 1];\
			mov    eax, ecx;\
			and    ecx, 0xf;\
			shr    al, 0x4;\
			lea    ebp, [eax + 0x30];\
			lea    edx, [eax + 0x57];\
			cmp    al, 0xa;\
			lea    eax, [ecx + 0x30];\
			cmovb  edx, ebp;\
			lea    ebp, [ecx + 0x57];\
			cmp    cl, 0xa;\
			mov    BYTE PTR[esi + ebx * 2], dl;\
			cmovae eax, ebp;\
			mov    BYTE PTR[esi + ebx * 2 + 0x1], al;\
			add    ebx, 0x1;\
			cmp    ebx, 0x8;\
			jne    loop1;\
			ret;\
		socketpair:\n\
			sub esp,0x10;\
			mov [esp],ebx;\
			mov [esp+4],ecx;\
			mov [esp+8],edx;\
			mov [esp+0xc],esi;\
			lea ecx,[esp];\
			mov ebx,8;\
			push 0x66;\
			pop eax;\
			int 0x80;\
			add esp,0x10;\
			ret;\
		fork:\n\
			push 0x2;\
			pop eax;\
			int 0x80;\
			ret;\
		open:\n\
			push 0x5;\
			pop eax;\
			int 0x80;\
			ret;\
		read:\n\
			push 0x3;\
			pop eax;\
			int 0x80;\
			ret;\
		close:\n\
			push 0x6;\
			pop eax;\
			int 0x80;\
			ret;\
		write:\n\
			push 0x4;\
			pop eax;\
			int 0x80;\
			ret;\
		dup2:\n\
			push 0x3f;\
			pop eax;\
			int 0x80;\
			ret;\
		poll:\n\
			push 0xa8;\
			pop eax;\
			int 0x80;\
			ret;\
		child:\n\
			mov ebx, dword ptr [esp+4];\
			call close;\
			mov ebx, dword ptr [esp];\
			xor ecx,ecx;\
			call dup2;\
			inc ecx;\
			call dup2;\
			inc ecx;\
			call dup2;\
			call close;\
			add esp, 0x200\
			";
		std::vector<uint8_t> codeX32;
		KSEngine::instance()->assemble(x32asm.c_str(), 0, codeX32);
		allcode.insert(allcode.end(), codeX32.begin(), codeX32.end());
	}
}
