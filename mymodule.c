#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/kmod.h>
#include <linux/times.h>
#include <linux/posix-timers.h>
#include <linux/security.h>
#include <linux/signal.h>
#include <linux/getcpu.h>
#include <linux/cpu.h>
#include <linux/ctype.h>
#include <linux/syscalls.h>
#include <linux/user_namespace.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>

//定义了result_struct结构体，用于将内核态数据传回用户态
#include "result_struct.h"
//在源码文件夹的arch/x86/entyr/syscalls/syscall_64.tbl文件中选择一个未使用的系统调用号
#define __NR_syscall 366   
//每次编译该模块之前都应确认系统调用表的地址 cat /proc/kallsyms
#define SYS_CALL_TABLE_ADDRESS 0xffffffff89e00180 

/*
 *通过内核模块增加系统调用
 *即通过模块加载时，
 *将系统调用表里面的那个系统调用号的那个系统调用号对应的系统调用服务例程改为我们自己实现的系统历程函数地址。
 *但是sys_call_table符号对应的内存区域是只读的，如果要修改它，必须对它进行清除写保护
*/

/*
 *控制寄存器cr0的第16位是写保护位，cr0的第16位置为了禁止超级权限，
 *若清零了则允许超级权限往内核中写入数据，
 *因此我们可以再写入之前，将那一位清零，使我们可以写入，
 *然后写完后，再将那一位复原。
*/

unsigned int clear_and_return_cr0(void);
void setback_cr0(unsigned int val);
int orig_cr0;                             //用来存储cr0寄存器原来的值
unsigned long *sys_call_table = 0;
static int (*anything_saved)(void);       //定义一个函数指针，用来保存一个系统调用

/*
 *使cr0寄存器的第16位设置为0(即是内核空间可写)
 *因为是64位系统，所以汇编语言 movl 变为 movq，eax 变为 rax
 */

unsigned int clear_and_return_cr0(void)
{
    unsigned int cr0 = 0;
    unsigned int ret;
    asm volatile ("movq %%cr0, %%rax":"=a"(cr0)); //将cr0寄存器的值移动到rax的寄存器中，同时输出到cr0变量中
    ret = cr0;
    cr0 &= 0xfffeffff;          //将cr0变量的值中的第16位清0,一会将修改后的值写入cr0寄存器
    asm volatile ("movq %%rax, %%cr0": :"a"(cr0));  //将cr0变量的值做为输入，输入到寄存器eax中，同时移动到寄存器cr0中
    return ret;
}

//恢复cr0第十六位
void setback_cr0(unsigned int val)
{
    asm volatile ("movq %%rax, %%cr0": :"a"(val));
}
//这些是内核源码，我也不知道是干啥的
static int is_stack(struct vm_area_struct *vma)
{
        /*
         * We make no effort to guess what a given thread considers to be
         * its "stack".  It's not even well-defined for programs written
         * languages like Go.
         */
        return vma->vm_start <= vma->vm_mm->start_stack &&
                vma->vm_end >= vma->vm_mm->start_stack;
}

/*
 *根据内核源码有所改动，为了得到进程实际占用的物理内存
 *进程使用的所有物理内存（file_rss＋anon_rss），即Anonymous pages＋Mapped apges（包含共享内存）
 *文件映射页（指定文件的mmap以及IPC共享内存）和匿名映射页
*/
static unsigned long get_task_mem(struct mm_struct *mm)
{
        unsigned long  anon, file, shmem;
        unsigned long  total_rss;
   
        anon = get_mm_counter(mm, MM_ANONPAGES);
        file = get_mm_counter(mm, MM_FILEPAGES);
        shmem = get_mm_counter(mm, MM_SHMEMPAGES);
   
        total_rss = anon + file + shmem;
        return total_rss;
   
} 

//判断该vma指向的是否是mpx区域（我也不知道这个区域是什么）
const char *arch_vma_name(struct vm_area_struct *vma)
{
        if (vma->vm_flags & VM_MPX)
                return "[mpx]";
        return NULL;
}


//获得vma的的信息
static void get_vma_attr(struct vm_area_struct * vma,char * vma_attr){
	    struct mm_struct * mm;  
	    struct file *file;
		// 此段虚拟地址空间的属性。每种属性用一个字段表示，r表示可读，w表示可写，x表示可执行
		// p和s共用一个字段，互斥关系，p表示私有段，s表示共享段，如果没有相应权限，则用’-’代替
	    vm_flags_t flags;    
		//映射文件所属节点号。对匿名映射来说，因为没有文件在磁盘上，所以没有节点号，始终为00:00。
		//对有名映射来说，是映射的文件的节点号
        unsigned long ino = 0;
        unsigned long long pgoff = 0; //对有名映射，表示此段虚拟内存起始地址在文件中以页为单位的偏移。对匿名映射，它等于0或者vm_start/PAGE_SIZE
        unsigned long start, end;  // 此段虚拟地址空间起始地址,结束地址
    	struct inode * inode; // 内核使用inode结构体在内核内部表示一个文件
        // 映射文件所属设备号。对匿名映射来说，因为没有文件在磁盘上，所以没有设备号，始终为00:00。
		//对有名映射来说，是映射的文件所在设备的设备号 
		dev_t dev = 0;
	    const char * name = NULL;

        char str[1024] = {0};

	    mm = vma->vm_mm;
	    file = vma->vm_file;
	    flags = vma->vm_flags;
		//如果是有名映射
	    if (file) {  
            	inode = file_inode(vma->vm_file);
            	dev = inode->i_sb->s_dev;
        	    ino = inode->i_ino;  
        	    pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
	    }
	    start = vma->vm_start;  
        end = vma->vm_end;	 
		//如果是匿名映射，判断该段虚拟内存在进程中的角色[heap]为堆，[stack]为栈
	    if (!file) {
		    if (vma->vm_ops && vma->vm_ops->name) {name = vma->vm_ops->name(vma);}
		    if (!name){
			    name = arch_vma_name(vma);
			    if(!name){
				    if (!mm) {name = "[vdso]";}
                		    else if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk) {name = "[heap]";}
                		    else if (is_stack(vma)){name = "[stack]";}
			    }   
		    }
		    //printk(KERN_INFO "%s", name);
            }else { name = "[filename]";}
		//将字符串格式化存入str中
        sprintf(str, "0x%08lx-0x%08lx %c%c%c%c %08llx %02x:%02x %lu      %s\n",
                start,
                end,
                flags & VM_READ ? 'r' : '-',    // 这些是内存区域的读写执行权限以及共享还是私有的属性
                flags & VM_WRITE ? 'w' : '-',
                flags & VM_EXEC ? 'x' : '-',
                flags & VM_MAYSHARE ? 's' : 'p',  // s表示共享，p表示私有
                pgoff,
                MAJOR(dev), 
                MINOR(dev), 
                ino,
                name
                );
		//再将str拼接到vma_attr中
        strcat(vma_attr, str);
}

//定义自己实现的系统调用
asmlinkage long sys_mycall(pid_t pid1,struct result_struct * result1)
{
	struct pid * mypid;
	struct task_struct * mytask;
	struct mm_struct * mm;

	struct vm_area_struct * vma;
	//给result分配空间
	//内核态没有malloc操作
	//分配一个result_struct结构体大小的内存空间
	struct result_struct *result = (struct result_struct *)kmalloc(sizeof(struct result_struct), GFP_ATOMIC);

	struct vm_area_struct * tmp_vma;
	
	
	pud_t *pud;   //页上级目录      
    pmd_t *pmd;   //页中级目录
    pgd_t *pgd;   //页全局目录
    p4d_t *p4d;   //不知道这是个啥，但是内核14.15版本确实又需要它
	pte_t *pte;   //页表	
	const char * pgtable = NULL;

    // 通过pid得到 pid_t 结构体
	mypid = find_get_pid(pid1);
	// 通过pid得到相应的task_struct结构体
	mytask = pid_task(find_vpid(pid1), PIDTYPE_PID);
	//mm是进程内存管理的结构体
	mm = mytask->mm;
	//vma是一个链表，它由许多vma结构体构成
	vma = mm->mmap;
	
    /*
	 *代码段
	 *数据段
	 *BSS段
	 *堆
	 *栈等区域的位置和大小
	 *包含多少个虚拟内存区VMA、每个VMA的属性
	 *该进程页表的地址
	 *已映射的物理内存大小
	 */
	result->start_code = mm->start_code;
	result->end_code = mm->end_code;
	result->start_data = mm->start_data;
	result->end_data = mm->end_data;
	result->start_bss = mm->end_data;
	result->end_bss = mm->start_brk;
	result->start_brk = mm->start_brk;
	result->end_brk = mm->brk;
	result->start_stack = mm->start_stack;
	//其它信息都可以直接得到，只有这个需要计算stack_vm是栈区所占的页数，每页大小4KB
	result->end_stack = mm->start_stack + mm->stack_vm * 4096;
	result->count_vma = mm->map_count;

    //////////////  找到页表地址  /////////////
	// mm_struct中有一个成员变量pgd_t * pgd 存放的是全局页目录基地址
	// 也会放在cr3寄存器中，当我们有一个线性地址就可以根据线性地址算出各种偏移量，找到页表项
	// 1.全局页目录基址加上偏移量得到页上级目录基址
	// 2.页上级目录基址加上偏移量得到页中级目录基址
	// 3.页中级目录基址加上偏移量得到页表基地址
	// 4.页表基地址加上偏移量得到页表项
	// 下面代码改自内核源码，p4d不知道是代表什么，没有找到相关资料
	pgd = pgd_offset(mm,result->start_stack);	
	if(pgd_none(*pgd)||unlikely(pgd_bad(*pgd)))
		pgtable = "null";
    else{
        p4d = p4d_offset(pgd,result->start_stack);
        if(p4d_none(*p4d)||unlikely(p4d_bad(*p4d)))
            pgtable = "null";
        else{
            pud=pud_offset(p4d,result->start_stack);
            if(pud_none(*pud)||unlikely(pud_bad(*pud)))
                pgtable = "null";
            else{
                pmd=pmd_offset(pud,result->start_stack);
                if(pmd_none(*pmd)||unlikely(pmd_bad(*pmd)))
                    pgtable = "null";
                else{
                    pgtable = "No-null";
                    pte =  pte_offset_kernel(pmd, result->start_stack);
                }
            }
        }
    }
	// pte_t 是封装的 unsigned long 类型，为了更好的可读性和类型检查
	// 在这里强制转换是为了打印方便
    result->pte = (unsigned long)pte;
	///////////// 找到页表地址 ////////////////////

    //vma结构体的数量
    result->count_vma = mm->map_count;
    //遍历vma链表，把属性取出来
    for(tmp_vma = vma; tmp_vma != NULL; tmp_vma = tmp_vma->vm_next){
         get_vma_attr(tmp_vma, result->vma_attr);
    }
    //获取进程实际占用的物理内存大小
    result->rss = get_task_mem(mm);

	/*
	unsigned long copy_to_user(void *to, const void *from, unsigned long n)
	to:目标地址（用户空间）
	from:源地址（内核空间）
	n:将要拷贝数据的字节数
	返回：成功返回0，失败返回没有拷贝成功的数据字节数
	*/
	copy_to_user((struct result_struct *)result1, result, sizeof(struct result_struct));
	kfree(result);

	return 0;
}



static int __init init_addsyscall(void)
{
	printk("IN IN IN....\n");
    sys_call_table = (unsigned long *)SYS_CALL_TABLE_ADDRESS;
    anything_saved = (int(*)(void))(sys_call_table[__NR_syscall]);  //保存系统调用表中的__NR_syscall位置上的系统调用
    orig_cr0 = clear_and_return_cr0();  //使内核地址空间可写
    sys_call_table[__NR_syscall] = (unsigned long)&sys_mycall;    //用自己的系统调用替换__NR_syscall位置上的系统调用
    setback_cr0(orig_cr0);   //使内核地址空间不可写
    return 0;
}

static void __exit exit_addsyscall(void)
{
    orig_cr0 = clear_and_return_cr0();  //使内核地址空间可写
    sys_call_table[__NR_syscall] = (unsigned long)anything_saved; //将系统调用恢复
    setback_cr0(orig_cr0);   //使内核地址空间不可写
    printk("call exit....\n");
}

//模块构造函数：执行insmod指令加载内核模块时会调用的初始化函数
module_init(init_addsyscall);
//模块析构函数：执行rmmod指令卸载模块时调用的函数。
module_exit(exit_addsyscall);

MODULE_AUTHOR("Meishijia");
MODULE_LICENSE("GPL");

