#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
/* According to earlier standards */
#include <sys/time.h>
#include <unistd.h>
#include <poll.h>
#include <sys/ioctl.h>

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
			int result = poll((struct pollfd *)&key_fds, 2, -1);
			if (result == -1)
			{
				break;
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

