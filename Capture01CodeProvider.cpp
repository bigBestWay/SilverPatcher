#include "Capture01CodeProvider.h"
#include "BinaryEditor.h"
#include "KSEngine.h"
#include "Config.h"

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
	//λ���޹�
	/*�������ļ��еı��ģ���������TLV��ʽ
		TAG: 4bytes, 0x12345678 ��ʾ����
		     4bytes, 0x87654321 ��ʾ���
		LEN: 4bytes
		VALUE: len�ֽ�
	*/
	std::string host = Config::instance()->getCaptureForwardHost();
	std::string port = Config::instance()->getCaptureForwardPort();
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
			call close;"//�ر�child fd
			//����socket��connect
			"push 0x29;"\
			"pop rax;"\
			"cdq ;"\
			"push 2;"\
			"pop rdi;"\
			"push 1;"\
			"pop rsi;"\
			"syscall ;"\
			"mov dword ptr [rsp + 0x20], eax ;"//sockfd offset 0x20, size 4
			//connect
			"xchg rax, rdi;"\
			"movabs rcx, ";
		asmCode += "0x" + host + port + "0002;";
		asmCode += "push rcx;"\
			"mov rsi, rsp;"\
			"push 0x10;"\
			"pop rdx;"\
			"push 0x2a;"\
			"pop rax;"\
			"syscall;"\
			//ջƽ��
			"pop rcx;"
			"mov eax,dword ptr [rsp+4];"//parent fd
			"mov dword ptr [rsp + 0x28], eax;"//struct pollfd[0]:fd  size 4. struct pollfd������Ԫ�أ���16�ֽڣ�ƫ����0x28
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
			jz exit;\
			mov ax,word ptr [rsp+0x2e];\
			and ax,0x10;\
			test ax,ax;\
			jnz exit;\
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
			and ax,0x10;\
			test ax,ax;\
			jnz exit;\
			mov ax,word ptr [rsp+0x36];\
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
			"push 0x8;\
			pop rdx;\
			call write;\
			pop rdx;"//restore len
			"lea rsi,[rsp+0x100];"//rsp+0x100 buff
			"call write;\
			jmp pollloop;\
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
		exit:\n\
			xor rax,rax;\
			mov al,0x3c;\
			syscall;\
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
		//32λϵͳ���ò���: ebx,ecx,edx,esi,edi
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
			call close;"//�ر�child fd
			//socket
			"xor ebx, ebx;"\
			"mul ebx;"\
			"push ebx;"\
			"inc ebx;"\
			"push ebx;"\
			"push 2;"\
			"mov ecx, esp;"\
			"mov al, 0x66;"\
			"int 0x80;"\
			"mov dword ptr [esp + 0x20], eax ;"//filefd offset 0x20, size 4
			//connect
			"xchg eax, ebx;"\
			"pop ecx;"\
			"cond1:\n"\
			"mov al, 0x3f;"\
			"int 0x80;"\
			"dec ecx;"\
			"jns cond1;";
		x32asm += "push 0x" + host + ";";
		x32asm += "push 0x" + port + "0002;";
		x32asm += "mov ecx, esp;"\
			"mov al, 0x66;"\
			"push eax;"\
			"push ecx;"\
			"push ebx;"\
			"mov bl, 3;"\
			"mov ecx, esp;"\
			"int 0x80;"\
			//ջƽ��
			"pop eax;"
			"pop eax;"
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
			jz exit;\
			mov ax,word ptr [esp+0x2e];\
			and ax,0x10;\
			test ax,ax;\
			jnz exit;\
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
			and ax,0x10;\
			test ax,ax;\
			jnz exit;\
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
			"push 0x8;\
			pop edx;\
			call write;\
			pop edx;"//restore len
			"lea ecx,[esp+0x100];"//esp+0x100 buff
			"call write;\
			jmp pollloop;\
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
		exit:\n\
			xor eax,eax;\
			mov al,1;\
			int 0x80;\
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
