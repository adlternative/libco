/*
* Tencent is pleased to support the open source community by making Libco available.

* Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at
*
*	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, 
* software distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License.
*/

.globl coctx_swap
#if !defined( __APPLE__ )
.type  coctx_swap, @function
#endif
coctx_swap:

#if defined(__i386__)
    movl 4(%esp), %eax
    movl %esp,  28(%eax)
    movl %ebp, 24(%eax)
    movl %esi, 20(%eax)
    movl %edi, 16(%eax)
    movl %edx, 12(%eax)
    movl %ecx, 8(%eax)
    movl %ebx, 4(%eax)


    movl 8(%esp), %eax
    movl 4(%eax), %ebx
    movl 8(%eax), %ecx
    movl 12(%eax), %edx
    movl 16(%eax), %edi
    movl 20(%eax), %esi
    movl 24(%eax), %ebp
    movl 28(%eax), %esp

	ret

#elif defined(__x86_64__)
	leaq (%rsp),%rax //rax = rsp (当前的栈顶)
    //存入了14个寄存器
    movq %rax, 104(%rdi) //* reg[13] = rsp
    movq %rbx, 96(%rdi)
    movq %rcx, 88(%rdi)
    movq %rdx, 80(%rdi)
	  movq 0(%rax), %rax //rax = *rsp
	  movq %rax, 72(%rdi)//rip =rax =rsp
    movq %rsi, 64(%rdi)
	  movq %rdi, 56(%rdi)
    movq %rbp, 48(%rdi)
    movq %r8, 40(%rdi)
    movq %r9, 32(%rdi)
    movq %r12, 24(%rdi)
    movq %r13, 16(%rdi)
    movq %r14, 8(%rdi)
    movq %r15, (%rdi)
	  xorq %rax, %rax //rax = 0

    movq 48(%rsi), %rbp //rbp = 0
    movq 104(%rsi), %rsp //rsp =*(regs[kRSP])=*sp=pfn
    movq (%rsi), %r15 // 0
    movq 8(%rsi), %r14 // 0
    movq 16(%rsi), %r13 // 0
    movq 24(%rsi), %r12 // 0
    movq 32(%rsi), %r9 // 0
    movq 40(%rsi), %r8 // 0
    movq 56(%rsi), %rdi // co
    movq 80(%rsi), %rdx //0
    movq 88(%rsi), %rcx //0
    movq 96(%rsi), %rbx //0
		leaq 8(%rsp), %rsp //rsp之前在regs[13]
		pushq 72(%rsi) //push rax=*ip=pfn 

    movq 64(%rsi), %rsi //rsi=NULL
	ret //pop ip 执行pfn
#endif
// gdb 大法
// (gdb) b         coctx_swap(&(curr->ctx),&(pending_co->ctx) );
// Function "coctx_swap(&(curr->ctx),&(pending_co->ctx) );" not defined.
// Make breakpoint pending on future shared library load? (y or [n]) n
// (gdb) b coctx_swap
// Breakpoint 1 at 0x78b2
// (gdb) r
// Starting program: /home/adl/libco/example_cond 
// [Thread debugging using libthread_db enabled]
// Using host libthread_db library "/usr/lib/libthread_db.so.1".

// Breakpoint 1, 0x000055555555b8b2 in coctx_swap ()
// (gdb) n
// Single stepping until exit from function coctx_swap,
// which has no line number information.
// CoRoutineFunc (co=0x55555563e790) at co_routine.cpp:461
// warning: Source file is more recent than executable.
// 461             if( co->pfn )
// (gdb) i r
// rax            0x0                 0
// rbx            0x0                 0
// rcx            0x0                 0
// rdx            0x0                 0
// rsi            0x0                 0
// rdi            0x55555563e790      93824993191824
// rbp            0x0                 0x0
// rsp            0x7ffff796d008      0x7ffff796d008
// r8             0x0                 0
// r9             0x0                 0
// r10            0x55555563e790      93824993191824
// r11            0x246               582
// r12            0x0                 0
// r13            0x0                 0
// r14            0x0                 0
// r15            0x0                 0
// rip            0x555555557a40      0x555555557a40 <CoRoutineFunc(stCoRoutine_t*, void*)>
// eflags         0x246               [ PF ZF IF ]
// cs             0x33                51
// ss             0x2b                43
// ds             0x0                 0
// es             0x0                 0
// fs             0x0                 0
// --Type <RET> for more, q to quit, c to continue without paging--c
// gs             0x0                 0
// (gdb) print 0x7ffff796d008
// $1 = 140737347244040
// (gdb) print *(0x7ffff796d008)
// $2 = 0
// (gdb) print *co
// $3 = {env = 0x55555563c1c0, pfn = 0x5555555568b0 <Consumer(void*)>, arg = 0x55555563bee0, ctx = {regs = {0x0, 0x0, 0x0, 0x0, 
//       0x0, 0x0, 0x0, 0x55555563e790, 0x0, 0x555555557a40 <CoRoutineFunc(stCoRoutine_t*, void*)>, 0x0, 0x0, 0x0, 
//       0x7ffff796d000}, ss_size = 131072, ss_sp = 0x7ffff794d010 ""}, cStart = 1 '\001', cEnd = 0 '\000', cIsMain = 0 '\000', 
//   cEnableSysHook = 0 '\000', cIsShareStack = 0 '\000', pvEnv = 0x0, stack_mem = 0x555555640860, stack_sp = 0x0, save_size = 0, 
//   save_buffer = 0x0, aSpec = {{value = 0x0} <repeats 1024 times>}}