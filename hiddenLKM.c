#include <stdio.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>

int main()
{
    // The syscall number of hidepid
    int syscall_num = __NR_hidepid;

    // The pid of the process that will be hidden
    int pid = getpid();

    // The syscall
    long int res = syscall(syscall_num, pid);

    // Check the return value
    if (res == 0)
        printf("Process successfully hidden!\n");
    else
        printf("Error hiding process!\n");

    return 0;
}
