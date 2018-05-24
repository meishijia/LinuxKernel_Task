#include <stdio.h>
#include <stdlib.h>
#include <linux/unistd.h>
#include <syscall.h>

#include "result_struct.h"

int main()
{
	
    struct result_struct *result = (struct result_struct *)malloc(sizeof(struct result_struct));
	pid_t pid = getpid();
	syscall(366, pid, result);
  
    printf("+++++++++++++++++++++++++++++++++++++++\n");
    printf("+      The information of process     +\n");
    printf("+++++++++++++++++++++++++++++++++++++++\n");
    printf("@mysyscall  pid:%d\n\n",pid);
    printf(" code: 0x%lx - 0x%lx, size: %lu\n",result->start_code,result->end_code,result->end_code - result->start_code);
    printf(" data: 0x%lx - 0x%lx, size: %lu\n",result->start_data,result->end_data,result->end_data - result->start_data);
    printf("  bss: 0x%lx - 0x%lx, size: %lu\n",result->start_bss,result->end_bss,result->end_bss - result->start_bss);
    printf("stack: 0x%lx - 0x%lx, size: %lu\n",result->start_stack,result->end_stack,result->end_stack - result->start_stack);
    printf("  brk: 0x%lx - 0x%lx, size: %lu\n",result->start_brk,result->end_brk,result->end_brk - result->start_brk);  
    printf("@mysyscall  vma_conter: %d\n",result->count_vma);
    printf("the attributes of vma:\n %s\n",result->vma_attr);
    printf("The address of pagetable: 0x%lx\n",result->pte);
    printf("the size of memery taked: %lu\n",result->rss);
    printf("+++++++++++++++++++++++++++++++++++++++\n");
    printf("+                The end              +\n");
    printf("+++++++++++++++++++++++++++++++++++++++\n");

	printf("syscall finished");
} 
