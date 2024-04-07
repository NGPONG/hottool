#include "hook.h"
#include "find_sym_addr.h"
#include "crossprocess.h"
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <stdint.h>
#include <sys/user.h>
#include <string.h>
#include <sys/mman.h>
#include <map>
#include <limits.h>
#include <stdlib.h>
#include <dlfcn.h>

const char *libcprefix = "libc";
char *gpcalladdr = NULL;
//unsigned long glibcstartaddr;
uint64_t gbackupcode = 0;
char *gpcallstack = 0;
const int callstack_len = 8 * 1024 * 1024;
std::map<uint64_t, int> gallocmem;

const int syscall_sys_mmap = 9;
const int syscall_sys_mprotect = 10;
const int syscall_sys_munmap = 11;

bool cross_free_string_mem(int pid, void *targetaddr, int targetlen);

int syscall_fun(pid_t pid, uint64_t &retval, uint64_t syscallno, uint64_t arg1 = 0, uint64_t arg2 = 0, uint64_t arg3 = 0, uint64_t arg4 = 0, uint64_t arg5 = 0, uint64_t arg6 = 0)
{
	struct user_regs_struct oldregs;
	int ret = ptrace(PTRACE_GETREGS, pid, 0, &oldregs);
	if (ret < 0)
	{
		fprintf(stderr, "%s %d getregs error\n", __FUNCTION__, __LINE__);
		return -1;
	}

	char code[8] = {0};
	// 0f 05 : syscall
	code[0] = 0x0f;
	code[1] = 0x05;
	// cc : int3
	code[2] = 0xcc;
	// nop
	memset(&code[3], 0x90, sizeof(code) - 3);

	//setup registers
	struct user_regs_struct regs = oldregs;
	regs.rip = (uint64_t)gpcalladdr;
	regs.rax = syscallno;
	regs.rdi = arg1;
	regs.rsi = arg2;
	regs.rdx = arg3;
	regs.r10 = arg4;
	regs.r8 = arg5;
	regs.r9 = arg6;

	ret = cross_proc_write(pid, gpcalladdr, code, sizeof(code));
	if (ret != 0)
	{
		fprintf(stderr, "%s %d write code error\n", __FUNCTION__, __LINE__);
		return -1;
	}
	ret = ptrace(PTRACE_SETREGS, pid, 0, &regs);
	if (ret < 0)
	{
		fprintf(stderr, "%s %d set regs error\n", __FUNCTION__, __LINE__);
		return -1;
	}
	ret = ptrace(PTRACE_CONT, pid, 0, 0);
	if (ret < 0)
	{
		fprintf(stderr, "%s %d cont error %s\n", __FUNCTION__, __LINE__, strerror(errno));
		return -1;
	}
	int errsv = 0;
	int status = 0;
	while (1)
	{
		ret = waitpid(pid, &status, 0);
		if (ret == -1)
		{
			if (errno == EINTR)
			{
				continue;
			}
			fprintf(stderr, "%s %d waitpid error\n", __FUNCTION__, __LINE__);
			errsv = errno;
			break;
		}
		if (WIFSTOPPED(status))
		{
			if (WSTOPSIG(status) == SIGTRAP)
			{
				//ok
				break;
			}
			else
			{
				fprintf(stderr, "%s %d target process unexpectedly stopped by signal %d\n", __FUNCTION__, __LINE__, WSTOPSIG(status));
				errsv = -1;
				break;
			}
		}
		else if (WIFEXITED(status))
		{
			fprintf(stderr, "%s %d target process unexpectedly terminated with exit code %d\n", __FUNCTION__, __LINE__, WEXITSTATUS(status));
			errsv = -1;
			break;
		}
		else if (WIFSIGNALED(status))
		{
			fprintf(stderr, "%s %d target process unexpectedly stopped by signal %d\n", __FUNCTION__, __LINE__, WTERMSIG(status));
			errsv = -1;
			break;
		}
		else
		{
			fprintf(stderr, "%s %d unexpected waitpid status 0x%x\n", __FUNCTION__, __LINE__, status);
			errsv = -1;
			break;
		}
	}

	if (!errsv)
	{
		ret = ptrace(PTRACE_GETREGS, pid, 0, &regs);
		if (ret < 0)
		{
			fprintf(stderr, "%s %d getregs return error %d\n", __FUNCTION__, __LINE__, ret);
			return -1;
		}
		fprintf(stderr, "%s %d get rax to retval %lx\n", __FUNCTION__, __LINE__, regs.rax);
		retval = regs.rax;
	}
	else
	{
		retval = -1;
	}

	ret = ptrace(PTRACE_SETREGS, pid, 0, &oldregs);
	if (ret < 0)
	{
		fprintf(stderr, "%s %d setregs return error %d\n", __FUNCTION__, __LINE__, ret);
		return -1;
	}

	ret = cross_proc_write(pid, (char *)gpcalladdr, (char *)&gbackupcode, sizeof(gbackupcode));
	if (ret < 0)
	{
		fprintf(stderr, "%s %d write code error %d\n", __FUNCTION__, __LINE__, ret);
		return -1;
	}

	return 0;
}

bool init_hook_env(pid_t pid)
{
  fprintf(stderr, "%s %d start\n", __FUNCTION__, __LINE__);
	int ret = ptrace(PTRACE_ATTACH, pid, 0, 0);
	if (ret < 0)
	{
		fprintf(stderr, "%s %d ptrace error %d\n", __FUNCTION__, __LINE__, errno);
	}
	ret = waitpid(pid, NULL, 0);
	if (ret < 0)
	{
		fprintf(stderr, "%s %d waitpid error %d\n", __FUNCTION__, __LINE__, errno);
		return false;
	}

	unsigned long libcstartaddr;
	unsigned long libcendaddr;
	if (!find_elf_addr(pid, libcprefix, "r-xp", libcstartaddr, libcendaddr))
	{
		fprintf(stderr, "%s %d find libc addr error\n", __FUNCTION__, __LINE__);
		return false;
	}
	uint64_t code;
	ret = cross_proc_read(pid, (char *)(libcstartaddr + 8), (char *)&code, sizeof(code));
	if (ret != 0)
  {
    fprintf(stderr, "%s %d read libc code error %d\n", __FUNCTION__, __LINE__, errno);
		return false;
	}
  // glibcstartaddr = libcstartaddr;
	gpcalladdr = (char *)(libcstartaddr + 8);	// 指向libc库开始偏移8byte后的指针
	gbackupcode = code; // libc库前8byte的数据
	fprintf(stderr, "%s %d ----- %p %p %lx\n", __FUNCTION__, __LINE__, libcstartaddr, gpcalladdr,  gbackupcode);
	uint64_t retval = 0;

  // 此处的逻辑就是远程控制进程去调用 mmap 创建一块内存空间，即创建一块调用栈，实现逻辑：
  // 1. 找到一块合适的内存段(可写的、相对安全且没有其它依赖的，比如一些安全控制的问题)，作者这里选择的是 libc 内存段往后偏移八个字节的位置
  // 2. 为什么要偏移八个字节，这么做的目的可能是为了避开写坏了elf文件头部的一些声明。
  // 3. 在找到合适的内存段后则写入一个 syscall 的指令用于调用 mmap 创建一块内存区域，并设置 IP 寄存器为写入内存开始的代码，然后 ptrace 恢复进程的执行
  // 3. 当远程进程开始执行后，使用 waitpid 开始新的一轮等待，等待进程执行完毕后检查错误码和特殊信号查看是否有异常返回
  // 4. 当一切结束后，恢复在写入内存那一刻开始时寄存器快照，并且恢复修改的内存数据为原来的数据，避免一些未定义的行为
  // 5. 写入的内存区域可能是像充当一个调用栈，目的是为了远程调用进程的某些函数时不破坏进程当前的栈
  ret = syscall_fun(pid, retval, syscall_sys_mmap, 0, callstack_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
	if (ret != 0)
	{
		fprintf(stderr, "%s %d syscall error %d\n", __FUNCTION__, __LINE__, ret);
		return false;
	}

	gpcallstack = (char *)retval;

	fprintf(stderr, "%s %d succ gpcalladdr=%p, backupcode=%lu, stack=%p\n", __FUNCTION__, __LINE__, gpcalladdr, gbackupcode, gpcallstack);

	return true;
}

bool fini_hook_env(int pid)
{
	std::map<uint64_t, int>::iterator it = gallocmem.begin();
	for (; it != gallocmem.end(); ++it)
	{
		cross_free_string_mem(pid, (void *) it->first, it->second);
	}

	uint64_t retval = 0;
	syscall_fun(pid, retval, syscall_sys_munmap, (uint64_t)gpcallstack, (uint64_t)callstack_len);
	ptrace(PTRACE_DETACH, pid, 0, 0);

	fprintf(stderr, "%s %d fini\n", __FUNCTION__, __LINE__);
	return true;
}

bool funcall_fun(int pid, uint64_t &retval, void *funcaddr, uint64_t arg1 = 0, uint64_t arg2 = 0, uint64_t arg3 = 0, uint64_t arg4 = 0, uint64_t arg5 = 0, uint64_t arg6 = 0)
{
	struct user_regs_struct oldregs;
	int ret = ptrace(PTRACE_GETREGS, pid, 0, &oldregs);
	if (ret < 0)
	{
		fprintf(stderr, "%s %d ptrace %d getregs error %d\n", __FUNCTION__, __LINE__, pid, errno);
		return false;
	}

	char code[8] = {0};
	//ff d0 : callq *%rax
	code[0] = 0xff;
	code[1] = 0xd0;
	//cc : int 3
	code[2] = 0xcc;
	//nop
	memset(&code[3], 0x90, sizeof(code) -3);

	struct user_regs_struct regs = oldregs;
	regs.rip = (uint64_t)gpcalladdr;
	regs.rbp = (uint64_t)(gpcallstack + callstack_len - 16);
	//rsp must be aligned to a 16-byte boundary
	regs.rsp = (uint64_t)(gpcallstack + callstack_len - (2 * 16));

	regs.rax = (uint64_t) funcaddr;
	regs.rdi = arg1;
	regs.rsi = arg2;
	regs.rdx = arg3;
	regs.rcx = arg4;
	regs.r8 = arg5;
	regs.r9 = arg6;

	ret = cross_proc_write(pid, gpcalladdr, code, sizeof(code));
	if (ret < 0)
	{
		fprintf(stderr, "%s %d cross_proc_write %d error %d\n", __FUNCTION__, __LINE__, pid, errno);
		return false;
	}

	ret = ptrace(PTRACE_SETREGS, pid, 0, &regs);
	if (ret < 0)
	{
		fprintf(stderr, "%s %d ptrace %d setregs error %d\n", __FUNCTION__, __LINE__, pid, errno);
		return false;
	}

	ret = ptrace(PTRACE_CONT, pid, 0, 0);
	if (ret < 0)
	{
		fprintf(stderr, "%s %d ptrace %d PTRACE_CONT error %d\n", __FUNCTION__, __LINE__, pid, errno);
		return false;
	}

	int errsv = 0;
	int status = 0;

	while(1)
	{
		ret = waitpid(pid, &status, 0);
		if (-1 == ret)
		{
			if (errno == EINTR)
			{
				continue;
			}

			fprintf(stderr, "%s %d waitpid %d error %d %s\n", __FUNCTION__, __LINE__, pid, errno, strerror(errno));
			errsv = errno;
			break;
		}

		if (WIFSTOPPED(status))
		{
			if (WSTOPSIG(status) == SIGTRAP)
			{
				break;
			}
			else
			{
				fprintf(stderr, "%s %d target process %d unexpectedly stopped by signal %d\n", __FUNCTION__, __LINE__, pid, WSTOPSIG(status));
				errsv = -1;
				break;
			}
		}
		else if (WIFEXITED(status))
		{
			fprintf(stderr, "%s %d target process %d unexpectedly terminated with exit code %d\n", __FUNCTION__, __LINE__, pid, WEXITSTATUS(status));
			errsv = -1;
			break;
		}
		else if (WIFSIGNALED(status))
		{
			fprintf(stderr, "%s %d target process %s unexpectedly terminated by signal %d\n", __FUNCTION__, __LINE__, pid, WTERMSIG(status));
			errsv = -1;
			break;
		}
		else
		{
			fprintf(stderr, "%s %d target process %s unexpected status %d\n", __FUNCTION__, __LINE__, pid, status);
			errsv = -1;
			break;
		}
	}

	if (!errsv)
	{
		int ret = ptrace(PTRACE_GETREGS, pid, 0, &regs);
		if (ret < 0)
		{
			fprintf(stderr, "%s %d ptrace %d getregs error %d\n", __FUNCTION__, __LINE__, pid, errno);
			return false;
		}
		retval = regs.rax;
	}
	else
	{
		retval = -1;
	}

	ret = ptrace(PTRACE_SETREGS, pid, 0, &oldregs);
	if (ret < 0)
	{
		fprintf(stderr, "%s %d ptrace %d setregs error %d\n", __FUNCTION__, __LINE__, pid, errno);
		return false;
	}

	ret = cross_proc_write(pid, gpcalladdr, (char *)&gbackupcode, sizeof(gbackupcode));
	if (ret < 0)
	{
		fprintf(stderr, "%s %d target process %d cross_proc_write error %d\n", __FUNCTION__, __LINE__, pid, errno);
		return false;
	}
	return true;
}

bool cross_alloc_string_mem(int pid, const std::string &str, void *&targetaddr, int &targetlen)
{
  int slen = str.length() + 1;
  int pagesize = sysconf(_SC_PAGESIZE);
  int len = ((slen + pagesize - 1) / pagesize) * pagesize;
	fprintf(stderr, "%s %d start call mmap %d %d\n", __FUNCTION__, __LINE__, str.length(), len);
	uint64_t retval = 0;
	int ret = syscall_fun(pid, retval, syscall_sys_mmap, 0, len, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
	if (ret != 0)
	{
		fprintf(stderr, "%s %d call mmap error %d %d\n", __FUNCTION__, __LINE__);
		return false;
	}

	if (retval == (uint64_t)(-1))
	{
		fprintf(stderr, "%s %d call mmap return error %d %d\n", __FUNCTION__, __LINE__);
		return false;
	}
	gallocmem[retval] = len;

	fprintf(stderr, "%s %d syscall_sys_mmap succ %lx %s %d\n", __FUNCTION__, __LINE__, retval, (char *)str.c_str(), str.length());
	ret = cross_proc_write(pid, (char *)retval, (char *)str.c_str(), str.length());
	if (0 != ret)
	{
		fprintf(stderr, "%s %d cross_proc_write error %d %d\n", __FUNCTION__, __LINE__);
		return false;
	}

	targetaddr = (void *)retval;
	targetlen = len;

	fprintf(stderr, "%s %d succ %s %d %p\n", __FUNCTION__, __LINE__, str.c_str(), targetlen, targetaddr);
	return true;
}

bool cross_free_string_mem(int pid, void *targetaddr, int targetlen)
{
	fprintf(stderr, "%s %d start call unmmap %p %d\n", __FUNCTION__, __LINE__, targetaddr, targetlen);
	uint64_t retval = 0;

	int ret = syscall_fun(pid, retval, syscall_sys_munmap, (uint64_t) targetaddr, (uint64_t) targetlen);
	if (ret != 0)
	{
		fprintf(stderr, "%s %d call unmmap error %p %d\n", __FUNCTION__, __LINE__, targetaddr, targetlen);
		return false;
	}
	gallocmem.erase((uint64_t) targetaddr);

	fprintf(stderr, "%s %d call unmmap succ %p %d\n", __FUNCTION__, __LINE__, targetaddr, targetlen);
	return true;
}

bool inject_so(int pid, const std::string &sopath, uint64_t &handle)
{
	char abspath[PATH_MAX];
	if (realpath(sopath.c_str(), abspath) == NULL)
	{
		fprintf(stderr, "%s %d failed to get the full path of %s : %s\n", __FUNCTION__, __LINE__, sopath.c_str(), strerror(errno));
		return false;
	}

	fprintf(stderr, "%s %d start inject so %s\n", __FUNCTION__, __LINE__, abspath);

  // 查询远程进程虚拟地址空间中，dlopen函数的地址，意味着远程进程至少需要使用 ldl 的编译选项
	void *libc_dlopen_mode_funcaddr_plt = 0;
	void *libc_dlopen_mode_funcaddr = 0;
	if (!find_so_func_addr_by_mem(pid, libcprefix, "__libc_dlopen_mode", libc_dlopen_mode_funcaddr_plt, libc_dlopen_mode_funcaddr))
	{
		fprintf(stderr, "%s %d failed to find libc dlopen addr %s : %s\n", __FUNCTION__, __LINE__, sopath.c_str(), strerror(errno));
		return false;
	}

	void *dlopen_straddr = 0;
	int dlopen_strlen = 0;

  // 此处远程调用进程的 mmap 函数构建一个匿名映射空间，并将 abspath 写入并返回 dlopen_straddr
	if (!cross_alloc_string_mem(pid, abspath, dlopen_straddr, dlopen_strlen))
	{
		fprintf(stderr, "%s %d failed to cross_alloc_string_mem %s\n", __FUNCTION__, __LINE__, abspath);
		return false;
	}

	uint64_t retval = 0;
	if (!funcall_fun(pid, retval, libc_dlopen_mode_funcaddr, (uint64_t) dlopen_straddr, RTLD_LAZY))
	{
		fprintf(stderr, "%s %d failed to funcall_fun dlopen\n", __FUNCTION__, __LINE__);
		return false;
	}

	if (retval == (uint64_t)(-1))
	{
		fprintf(stderr, "%s %d funcall_fun dlopen return error\n", __FUNCTION__, __LINE__);
		return false;
	}

	if (!cross_free_string_mem(pid, dlopen_straddr, dlopen_strlen))
	{
		fprintf(stderr, "%s %d cross_free_string_mem error\n", __FUNCTION__, __LINE__);
		return false;
	}

	handle = retval;

	if (handle == 0)
	{
		fprintf(stderr, "%s %d dlopen handle == 0, sopath=%s\n", __FUNCTION__, __LINE__, sopath.c_str());
		return false;
	}

	fprintf(stderr, "%s %d inject ok sopath=%s, handle = %lu\n", __FUNCTION__, __LINE__, sopath.c_str(), retval);

	return true;
}

bool cross_dlopen(pid_t pid, const std::string &sopath, uint64_t &handle)
{
	fprintf(stderr, "%s %d start call cross_dlopen sopath=%s \n", __FUNCTION__, __LINE__, sopath.c_str());
	if (!inject_so(pid, sopath, handle))
	{
		fprintf(stderr, "%s %d inject_so failed sopath=%s \n", __FUNCTION__, __LINE__, sopath.c_str());
		return false;
	}
	fprintf(stderr, "%s %d succ sopath=%s, handle = %lu\n", __FUNCTION__, __LINE__, sopath.c_str(), handle);
	return true;
}

bool close_so(int pid, const std::string &sopath, uint64_t handle)
{
	fprintf(stderr, "%s %d start sopath=%s, handle = %lu\n", __FUNCTION__, __LINE__, sopath.c_str(), handle);

	void *libc_dlclose_funcaddr_plt = 0;
	void *libc_dlclose_funcaddr = 0;

	if (!find_so_func_addr_by_mem(pid, libcprefix, "__libc_dlclose", libc_dlclose_funcaddr_plt, libc_dlclose_funcaddr))
	{
		fprintf(stderr, "%s %d find dlclose addr failed sopath=%s, handle = %lu\n", __FUNCTION__, __LINE__, sopath.c_str(), handle);
		return false;
	}

	fprintf(stderr, "%s %d find dlclose addr succ sopath=%s, handle = %lu, %p %p\n", __FUNCTION__, __LINE__, sopath.c_str(), handle, libc_dlclose_funcaddr_plt, libc_dlclose_funcaddr);

	uint64_t retval = 0;
	if (!funcall_fun(pid, retval, libc_dlclose_funcaddr, handle))
	{
		fprintf(stderr, "%s %d call dlclose failed sopath=%s, handle = %lu\n", __FUNCTION__, __LINE__, sopath.c_str(), handle);
		return false;
	}

	fprintf(stderr, "%s %d succ sopath=%s, handle = %lu\n", __FUNCTION__, __LINE__, sopath.c_str(), handle);
	return true;

}

bool cross_dlclose(pid_t pid, const std::string &sopath, uint64_t handle)
{
	fprintf(stderr, "%s %d start call cross_dlclose sopath=%s \n", __FUNCTION__, __LINE__, sopath.c_str());
	if (!close_so(pid, sopath, handle))
	{
		fprintf(stderr, "%s %d close_so failed sopath=%s \n", __FUNCTION__, __LINE__, sopath.c_str());
		return false;
	}

	fprintf(stderr, "%s %d succ sopath=%s, handle = %lu\n", __FUNCTION__, __LINE__, sopath.c_str(), handle);
	return true;
}

bool hotfix_func(pid_t pid, void *old_funcaddr, void *new_funcaddr, uint64_t &backupcode)
{
	fprintf(stderr, "%s %d start %p %p\n", __FUNCTION__, __LINE__, old_funcaddr, new_funcaddr);
	int ret = cross_proc_read(pid, (char *)old_funcaddr, (char *)&backupcode, sizeof(backupcode));
	if (ret != 0)
	{
		fprintf(stderr, "%s %d cross_proc_read failed %p %p\n", __FUNCTION__, __LINE__, old_funcaddr, new_funcaddr);
		return false;
	}

	int offset = (int)((uint64_t)new_funcaddr - ((uint64_t) old_funcaddr + 5));

	char code[8] = {0x90};	//nop
	code[0] = 0xE9;
	memcpy(&code[1], &offset, sizeof(offset));

	ret = cross_proc_write(pid, (char *)old_funcaddr, code, sizeof(code));
	if (ret != 0)
	{
		fprintf(stderr, "%s %d cross_proc_write failed %p %p\n", __FUNCTION__, __LINE__, old_funcaddr, new_funcaddr);
		return false;
	}

	fprintf(stderr, "%s %d succ %p %p %x\n", __FUNCTION__, __LINE__, old_funcaddr, new_funcaddr, offset);
	return true;

}

bool hotfix_func64(pid_t pid, void *old_funcaddr, void *new_funcaddr, char *backupcode, int len)
{
	fprintf(stderr, "%s %d start %p %p\n", __FUNCTION__, __LINE__, old_funcaddr, new_funcaddr);
	int ret = cross_proc_read(pid, (char *)old_funcaddr, backupcode, len);
	if (ret != 0)
	{
		fprintf(stderr, "%s %d cross_proc_read failed %p %p\n", __FUNCTION__, __LINE__, old_funcaddr, new_funcaddr);
		return false;
	}

	char code[16] = {0x90};	//nop
	//jmpq *
	code[0] = 0xFF;
	code[1] = 0x25;
	int offset = 0;
	memcpy(&code[2], &offset, sizeof(offset));
	memcpy(&code[6], &new_funcaddr, sizeof(new_funcaddr));

	ret = cross_proc_write(pid, (char *)old_funcaddr, code, sizeof(code));
	if (ret != 0)
	{
		fprintf(stderr, "%s %d cross_proc_write failed %p %p\n", __FUNCTION__, __LINE__, old_funcaddr, new_funcaddr);
		return false;
	}

	fprintf(stderr, "%s %d succ %p %p %x\n", __FUNCTION__, __LINE__, old_funcaddr, new_funcaddr, offset);
	return true;
}

bool hotfix_gotplt(pid_t pid, void *gotplt, void *new_funcaddr, uint64_t &backupcode)
{
	fprintf(stderr, "%s %d start %p %p\n", __FUNCTION__, __LINE__, gotplt, new_funcaddr);

	int ret = cross_proc_read(pid, (char *)gotplt, (char *)&backupcode, sizeof(backupcode));
	if (ret != 0)
	{
		fprintf(stderr, "%s %d cross_proc_read failed %p %p\n", __FUNCTION__, __LINE__, gotplt, new_funcaddr);
		return false;
	}

	ret = cross_proc_write(pid, (char *)gotplt, (char *)&new_funcaddr, sizeof(new_funcaddr));
	if (ret != 0)
	{
		fprintf(stderr, "%s %d cross_proc_write failed %p %p\n", __FUNCTION__, __LINE__, gotplt, new_funcaddr);
		return false;
	}

	fprintf(stderr, "%s %d succ %p %p %lx\n", __FUNCTION__, __LINE__, gotplt, new_funcaddr, backupcode);
	return true;
}
