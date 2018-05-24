struct result_struct
{  
    unsigned long start_code;
    unsigned long end_code;
    unsigned long start_data;
    unsigned long end_data;
    unsigned long start_bss;
    unsigned long end_bss;
    unsigned long start_brk;
    unsigned long end_brk;
    unsigned long start_stack;
    unsigned long end_stack;  
    unsigned long count_vma; //vma的个数
    char vma_attr[1024 * 3]; //所有vma的属性
    unsigned long pte;       //页表地址
    unsigned long rss;       //进程所占实际内存
};
