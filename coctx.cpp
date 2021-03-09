/*
* Tencent is pleased to support the open source community by making Libco
available.

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

#include "coctx.h"
#include <stdio.h>
#include <string.h>

#define ESP 0
#define EIP 1
#define EAX 2
#define ECX 3
// -----------
#define RSP 0
#define RIP 1
#define RBX 2
#define RDI 3
#define RSI 4

#define RBP 5
#define R12 6
#define R13 7
#define R14 8
#define R15 9
#define RDX 10
#define RCX 11
#define R8 12
#define R9 13

//----- --------
// 32 bit
// | regs[0]: ret |
// | regs[1]: ebx |
// | regs[2]: ecx |
// | regs[3]: edx |
// | regs[4]: edi |
// | regs[5]: esi |
// | regs[6]: ebp |
// | regs[7]: eax |  = esp
enum {
  kEIP = 0,
  kEBP = 6,
  kESP = 7,
};

//-------------
// 64 bit
// low | regs[0]: r15 |
//    | regs[1]: r14 |
//    | regs[2]: r13 |
//    | regs[3]: r12 |
//    | regs[4]: r9  |
//    | regs[5]: r8  |
//    | regs[6]: rbp |
//    | regs[7]: rdi |
//    | regs[8]: rsi |
//    | regs[9]: ret |  //ret func addr
//    | regs[10]: rdx |
//    | regs[11]: rcx |
//    | regs[12]: rbx |
// hig | regs[13]: rsp |
enum {
  kRDI = 7,
  kRSI = 8,
  kRETAddr = 9,
  kRSP = 13,
};

// 64 bit
extern "C" {
extern void coctx_swap(coctx_t*, coctx_t*) asm("coctx_swap");
};
#if defined(__i386__)
int coctx_init(coctx_t* ctx) {
  memset(ctx, 0, sizeof(*ctx));
  return 0;
}
int coctx_make(coctx_t* ctx, coctx_pfn_t pfn, const void* s, const void* s1) {
  // make room for coctx_param
  char* sp = ctx->ss_sp + ctx->ss_size - sizeof(coctx_param_t);
  sp = (char*)((unsigned long)sp & -16L);

  coctx_param_t* param = (coctx_param_t*)sp;
  void** ret_addr = (void**)(sp - sizeof(void*) * 2);
  *ret_addr = (void*)pfn;
  param->s1 = s;
  param->s2 = s1;

  memset(ctx->regs, 0, sizeof(ctx->regs));

  ctx->regs[kESP] = (char*)(sp) - sizeof(void*) * 2;
  return 0;
}
#elif defined(__x86_64__)
/*
*全文唯一一处coctx_make是co_resume
*@s: stCoRoutine_t*co
*@s1: NULL
*/
int coctx_make(coctx_t* ctx, coctx_pfn_t pfn, const void* s, const void* s1) {
/*
H
||-----ss_sp + ss_size-------||
||-----sp------||
...
||------ss_sp(stack_buffer)------||
L
*/

  char* sp = ctx->ss_sp + ctx->ss_size - sizeof(void*); /* 基址 + 栈大小 - 一个寄存器大小 获得高地址赋值给sp */
  sp = (char*)((unsigned long)sp & -16LL);/* sp 对齐16字节 0xmmmmmm0 */

  memset(ctx->regs, 0, sizeof(ctx->regs));/* 清空寄存器 */
  void** ret_addr = (void**)(sp);
  *ret_addr = (void*)pfn;/* 这个返回地址上存入需要执行的函数 */
  /* 在寄存器中记录一些必要信息 */
  ctx->regs[kRSP] = sp;/* 保存sp */

  ctx->regs[kRETAddr] = (char*)pfn;/* 别藏了应该就是rip,保存协程函数 */

  /* 保存需要切换回复的协程对象指针,
  等会儿汇编会调用这俩寄存器的值存入rdi和rsi中。 */
  ctx->regs[kRDI] = (char*)s;
  ctx->regs[kRSI] = (char*)s1;/* NULL */
  return 0;
}

int coctx_init(coctx_t* ctx) {
  memset(ctx, 0, sizeof(*ctx));
  return 0;
}

#endif
