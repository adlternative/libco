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

#include "co_routine.h"
#include "co_routine_inner.h"
#include "co_epoll.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <map>

#include <poll.h>
#include <sys/time.h>
#include <errno.h>

#include <assert.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <limits.h>

extern "C"
{
	extern void coctx_swap( coctx_t *,coctx_t* ) asm("coctx_swap");
};
using namespace std;
stCoRoutine_t *GetCurrCo( stCoRoutineEnv_t *env );
struct stCoEpoll_t;


/* stCoRoutineEnv_t结构一个线程只有一个 */
struct stCoRoutineEnv_t
{
  /* 协程栈 max 128 */
	stCoRoutine_t *pCallStack[ 128 ];
  /* 上面的栈当前大小 */
	int iCallStackSize;
  /* epoll封装类的指针 */
	stCoEpoll_t *pEpoll;
	//for copy stack log lastco and nextco
	stCoRoutine_t* pending_co;
	stCoRoutine_t* occupy_co;
};
//int socket(int domain, int type, int protocol);
void co_log_err( const char *fmt,... )
{
}


#if defined( __LIBCO_RDTSCP__) 
static unsigned long long counter(void)
{
	register uint32_t lo, hi;
	register unsigned long long o;
	__asm__ __volatile__ (
			"rdtscp" : "=a"(lo), "=d"(hi)::"%rcx"
			);
	o = hi;
	o <<= 32;
	return (o | lo);

}
static unsigned long long getCpuKhz()
{
	FILE *fp = fopen("/proc/cpuinfo","r");
	if(!fp) return 1;
	char buf[4096] = {0};
	fread(buf,1,sizeof(buf),fp);
	fclose(fp);

	char *lp = strstr(buf,"cpu MHz");
	if(!lp) return 1;
	lp += strlen("cpu MHz");
	while(*lp == ' ' || *lp == '\t' || *lp == ':')
	{
		++lp;
	}

	double mhz = atof(lp);
	unsigned long long u = (unsigned long long)(mhz * 1000);
	return u;
}
#endif

/* 获得时间戳微秒 */
static unsigned long long GetTickMS()
{
#if defined( __LIBCO_RDTSCP__) 
	static uint32_t khz = getCpuKhz();
	return counter() / khz;
#else
	struct timeval now = { 0 };
	gettimeofday( &now,NULL );
	unsigned long long u = now.tv_sec;
	u *= 1000;
	u += now.tv_usec / 1000;
	return u;
#endif
}

/* no longer use
static pid_t GetPid()
{
    static __thread pid_t pid = 0;
    static __thread pid_t tid = 0;
    if( !pid || !tid || pid != getpid() )
    {
        pid = getpid();
#if defined( __APPLE__ )
		tid = syscall( SYS_gettid );
		if( -1 == (long)tid )
		{
			tid = pid;
		}
#elif defined( __FreeBSD__ )
		syscall(SYS_thr_self, &tid);
		if( tid < 0 )
		{
			tid = pid;
		}
#else 
        tid = syscall( __NR_gettid );
#endif

    }
    return tid;

}
static pid_t GetPid()
{
	char **p = (char**)pthread_self();
	return p ? *(pid_t*)(p + 18) : getpid();
}
*/

/* 将某个节点从链表中删除 */
template <class T,class TLink>
void RemoveFromLink(T *ap)
{
	TLink *lst = ap->pLink;
	if(!lst) return ;
	assert( lst->head && lst->tail );
  /* 如果是链表头 */
	if( ap == lst->head )
	{
    /* 更新链表头 */
		lst->head = ap->pNext;
		if(lst->head)
		{
			lst->head->pPrev = NULL;
		}
	}
	else
	{
    /* 更新prev->next */
		if(ap->pPrev)
		{
			ap->pPrev->pNext = ap->pNext;
		}
	}
  /* 如果是链表尾 */
	if( ap == lst->tail )
	{
    /* 更新链表尾 */
		lst->tail = ap->pPrev;
		if(lst->tail)
		{
			lst->tail->pNext = NULL;
		}
	}
	else
	{
    /* 更新next->prev */
		ap->pNext->pPrev = ap->pPrev;
	}

	ap->pPrev = ap->pNext = NULL;
	ap->pLink = NULL;
}


/* 将节点添加到tail */
template <class TNode,class TLink>
void inline AddTail(TLink*apLink,TNode *ap)
{
	if( ap->pLink )
	{
		return ;
	}
	if(apLink->tail)
	{
		apLink->tail->pNext = ap;
		ap->pNext = NULL;
		ap->pPrev = apLink->tail;
		apLink->tail = ap;
	}
	else
	{
		apLink->head = apLink->tail = ap;
		ap->pNext = ap->pPrev = NULL;
	}
	ap->pLink = apLink;
}

/* 弹出head */
template <class TNode,class TLink>
void inline PopHead( TLink*apLink )
{
	if( !apLink->head )
	{
		return ;
	}
	TNode *lp = apLink->head;
  /* 单个节点 */
	if( apLink->head == apLink->tail )
	{
		apLink->head = apLink->tail = NULL;
	}
	else
	{
    /* 更新head */
		apLink->head = apLink->head->pNext;
	}

	lp->pPrev = lp->pNext = NULL;
	lp->pLink = NULL;

	if( apLink->head )
	{
		apLink->head->pPrev = NULL;
	}
}

/* 将后者添加到前者的尾部 */
template <class TNode,class TLink>
void inline Join( TLink*apLink,TLink *apOther )
{

	if( !apOther->head )
	{
		return ;
	}
	TNode *lp = apOther->head;
	while( lp )
	{
		lp->pLink = apLink;
		lp = lp->pNext;
	}
	lp = apOther->head;
	if(apLink->tail)
	{
		apLink->tail->pNext = (TNode*)lp;
		lp->pPrev = apLink->tail;
		apLink->tail = apOther->tail;
	}
	else
	{
		apLink->head = apOther->head;
		apLink->tail = apOther->tail;
	}

	apOther->head = apOther->tail = NULL;
}

/////////////////for copy stack //////////////////////////
/* 分配单个协程栈内存，栈大小为stack_size */
stStackMem_t* co_alloc_stackmem(unsigned int stack_size)
{
	stStackMem_t* stack_mem = (stStackMem_t*)malloc(sizeof(stStackMem_t));
	stack_mem->occupy_co= NULL;
	stack_mem->stack_size = stack_size;
	stack_mem->stack_buffer = (char*)malloc(stack_size);
	stack_mem->stack_bp = stack_mem->stack_buffer + stack_size;
	return stack_mem;
}
/* 分配count个共享协程栈内存 每个栈大小为stack_size */
stShareStack_t* co_alloc_sharestack(int count, int stack_size)
{
	stShareStack_t* share_stack = (stShareStack_t*)malloc(sizeof(stShareStack_t));
	share_stack->alloc_idx = 0;/* 初始坐标为0 */
	share_stack->stack_size = stack_size;/* 栈大小 */

	//alloc stack array
  share_stack->count = count;/* 共享栈数量 */
	stStackMem_t** stack_array = (stStackMem_t**)calloc(count, sizeof(stStackMem_t*)); /* 分配对应数量的共享栈 */
	/* 对每一个共享栈分配内存 */
  for (int i = 0; i < count; i++)
	{
		stack_array[i] = co_alloc_stackmem(stack_size);
	}
	share_stack->stack_array = stack_array;
	return share_stack;
}
/* 为协程实体获取一个共享栈 */
static stStackMem_t* co_get_stackmem(stShareStack_t* share_stack)
{
	if (!share_stack)
	{
		return NULL;
	}
  /* 轮询 */
	int idx = share_stack->alloc_idx % share_stack->count;
	share_stack->alloc_idx++;
  /* 返回其中一个共享栈 */
	return share_stack->stack_array[idx];
}


// ----------------------------------------------------------------------------
struct stTimeoutItemLink_t;
struct stTimeoutItem_t;

/* epoll封装 */
struct stCoEpoll_t
{
	int iEpollFd;/* epoll_fd */
  /* epoll_events 大小,
  一次 epoll_wait 最多返回的就绪事件个数 */
	static const int _EPOLL_SIZE = 1024 * 10;

	struct stTimeout_t *pTimeout;/* 时间轮（数组）（大小就60*1000) */

	struct stTimeoutItemLink_t *pstTimeoutList;/* 超时链表 */

	struct stTimeoutItemLink_t *pstActiveList;/* 活跃链表 */

	co_epoll_res *result;/* epoll的事件结果会在这里 */

};
typedef void (*OnPreparePfn_t)( stTimeoutItem_t *,struct epoll_event &ev, stTimeoutItemLink_t *active );
typedef void (*OnProcessPfn_t)( stTimeoutItem_t *);
/* 定时器项 */
struct stTimeoutItem_t
{
	enum
	{
		eMaxTimeout = 40 * 1000 //40s
	};
	stTimeoutItem_t *pPrev;
	stTimeoutItem_t *pNext;
	stTimeoutItemLink_t *pLink;/* 指向定时器链表 */

	unsigned long long ullExpireTime;/* 过期时间 */

	OnPreparePfn_t pfnPrepare; /* epollwait返回后对于事件准备函数 */
	OnProcessPfn_t pfnProcess;/* epollwait返回后对于事件的处理函数 */

	void *pArg; // routine 协程实体对象指针
	bool bTimeout;/* 超时标记 */
};
/* 定时器链表 */
struct stTimeoutItemLink_t
{
	stTimeoutItem_t *head;
	stTimeoutItem_t *tail;

};
/* 定时器 */
struct stTimeout_t
{
	stTimeoutItemLink_t *pItems;/* 时间轮数组 */
	int iItemSize;/* 时间轮轮数 */

	unsigned long long ullStart;/* 开始时间 */
	long long llStartIdx;/* 坐标 估计是给时间轮转用的 */
};
/* 分配一个定时器 */
stTimeout_t *AllocTimeout( int iSize )
{
	stTimeout_t *lp = (stTimeout_t*)calloc( 1,sizeof(stTimeout_t) );

	lp->iItemSize = iSize;/* 60*1000 */
	lp->pItems = (stTimeoutItemLink_t*)calloc( 1,sizeof(stTimeoutItemLink_t) * lp->iItemSize );

	lp->ullStart = GetTickMS();/* 设置为当前时间戳 */
	lp->llStartIdx = 0;

	return lp;
}
/* 释放一个定时器 */
void FreeTimeout( stTimeout_t *apTimeout )
{
	free( apTimeout->pItems );
	free ( apTimeout );
}
/* 向一个定时器添加一个定时器项 */
int AddTimeout( stTimeout_t *apTimeout,stTimeoutItem_t *apItem ,unsigned long long allNow )
{
  /* 如果没有开始时间???	lp->pItems = (stTimeoutItem	lp->pItems = (stTimeoutItemLink_t*)calloc( 1,sizeof(stTimeoutItemLink_t) * lp->iItemSize );
  Link_t*)calloc( 1,sizeof(stTimeoutItemLink_t) * lp->iItemSize );

  感觉一个AllocTimeout出来的定时器理论上不需要这个判断 */
	if( apTimeout->ullStart == 0 )
	{
		apTimeout->ullStart = allNow;
		apTimeout->llStartIdx = 0;
	}
	/* 如果需要注册的是定时器开始时间还比
  定时器整体的“创建”时间还要晚一些那就是AddTimeout错误的使用 */
  if( allNow < apTimeout->ullStart )
	{
		co_log_err("CO_ERR: AddTimeout line %d allNow %llu apTimeout->ullStart %llu",
					__LINE__,allNow,apTimeout->ullStart);

		return __LINE__;
	}
  /* 如果注册的超时时间比定时器的开始时间都晚
  那就是AddTimeout错误的使用 */
	if( apItem->ullExpireTime < allNow )
	{
		co_log_err("CO_ERR: AddTimeout line %d apItem->ullExpireTime %llu allNow %llu apTimeout->ullStart %llu",
					__LINE__,apItem->ullExpireTime,allNow,apTimeout->ullStart);

		return __LINE__;
	}
  /* 算出计时时长 */
	unsigned long long diff = apItem->ullExpireTime - apTimeout->ullStart;
  /* 如果超过60s以60s 计算 */
	if( diff >= (unsigned long long)apTimeout->iItemSize )
	{
		diff = apTimeout->iItemSize - 1;
		co_log_err("CO_ERR: AddTimeout line %d diff %d",
					__LINE__,diff);

		//return __LINE__;
	}
	/* 因为每次检验超时的时候 开始的格子号 都会更新，
  所以我们需要将新的定时器项添加到
  (diff+开始的格子号)%(60*1000) 的位置上 */
  AddTail( apTimeout->pItems + ( apTimeout->llStartIdx + diff ) % apTimeout->iItemSize , apItem );

	return 0;
}
/* 将定时器apTimeou中所有超时的定时器项添加到结果链表apResult中 */
inline void TakeAllTimeout( stTimeout_t *apTimeout,unsigned long long allNow,stTimeoutItemLink_t *apResult )
{
  /* 同AddTimeout */
	if( apTimeout->ullStart == 0 )
	{
		apTimeout->ullStart = allNow;
		apTimeout->llStartIdx = 0;
	}

  /* 同AddTimeout */
	if( allNow < apTimeout->ullStart )
	{
		return ;
	}
  /* 用本次检验超时时间减去上次检验超时时间+1
  算出需要检验超时时间的格子数  */
	int cnt = allNow - apTimeout->ullStart + 1;
  /* 如果超过6*10^4 ms 那就算 6*10^4 ms */
	if( cnt > apTimeout->iItemSize )
	{
		cnt = apTimeout->iItemSize;
	}
	if( cnt < 0 )
	{
		return;
	}
  /* 对开始的格子之后的cnt个格子的时间链表加入到 结果的超时链表 */
	for( int i = 0;i<cnt;i++)
	{
		int idx = ( apTimeout->llStartIdx + i) % apTimeout->iItemSize;
		Join<stTimeoutItem_t,stTimeoutItemLink_t>( apResult,apTimeout->pItems + idx  );
	}
  /* 更新检验超时的时间 */
	apTimeout->ullStart = allNow;
  /* 更新开始的格子 */
	apTimeout->llStartIdx += cnt - 1;
}

/* coctx_make 会让协程的寄存器中的返回地址绑定CoRoutineFunc,
CoRoutineFunc 会调用用户函数
 */
static int CoRoutineFunc( stCoRoutine_t *co,void * )
{
  /* 执行函数 */
	if( co->pfn )
	{
		co->pfn( co->arg );
	}
  /* 执行结束 */
	co->cEnd = 1;

	stCoRoutineEnv_t *env = co->env;
  /* yield */
	co_yield_env( env );

	return 0;
}


/* 创建一个stCoRoutine_t对象，根据attr指定栈大小等属性，
会和env相关联，绑定协程函数, 参数 */
struct stCoRoutine_t *co_create_env( stCoRoutineEnv_t * env, const stCoRoutineAttr_t* attr,
		pfn_co_routine_t pfn,void *arg )
{
	stCoRoutineAttr_t at;
  /* 如果有属性设置要求
  则拷贝到局部变量at */
	if( attr )
	{
		memcpy( &at,attr,sizeof(at) );
	}
  /* 对属性中指定栈大小作出调整 */
	if( at.stack_size <= 0 )
	{
    /* 128K */
		at.stack_size = 128 * 1024;
	}
	else if( at.stack_size > 1024 * 1024 * 8 )
	{
    /* 8M */
		at.stack_size = 1024 * 1024 * 8;
	}
  /* 取整 取上限 16^3B =2^12B = 4KB（页大小） 整数倍*/
	if( at.stack_size & 0xFFF ) 
	{
		at.stack_size &= ~0xFFF;
		at.stack_size += 0x1000;
	}
  /* 申请一个stCoRoutine_t */
	stCoRoutine_t *lp = (stCoRoutine_t*)malloc( sizeof(stCoRoutine_t) );

	memset( lp,0,(long)(sizeof(stCoRoutine_t))); 

  /* 将env 函数 参数 传入 */
	lp->env = env;
	lp->pfn = pfn;
	lp->arg = arg;

	stStackMem_t* stack_mem = NULL;
	if( at.share_stack )
	{
    /* 共享栈 */
		stack_mem = co_get_stackmem( at.share_stack);
		at.stack_size = at.share_stack->stack_size;
	}
	else
	{
    /* 私有栈 */
		stack_mem = co_alloc_stackmem(at.stack_size);
	}
	lp->stack_mem = stack_mem;

	lp->ctx.ss_sp = stack_mem->stack_buffer;/* sp=stack_buffer 低地址 */
	lp->ctx.ss_size = at.stack_size;

	lp->cStart = 0;
	lp->cEnd = 0;
	lp->cIsMain = 0;
	lp->cEnableSysHook = 0;
	lp->cIsShareStack = at.share_stack != NULL;

	lp->save_size = 0;
	lp->save_buffer = NULL;

	return lp;
}

/* 创建协程，创建或绑定线程env */
int co_create( stCoRoutine_t **ppco,const stCoRoutineAttr_t *attr,pfn_co_routine_t pfn,void *arg )
{
  /* 如果当前尚未初始化线程env （主协程） */
	if( !co_get_curr_thread_env() )
	{
    /* 那么就初始化线程env */
		co_init_curr_thread_env();
	}
  /* 创建协程的实体 */
	stCoRoutine_t *co = co_create_env( co_get_curr_thread_env(), attr, pfn,arg );
	*ppco = co;
	return 0;
}

/* 释放协程 */
void co_free( stCoRoutine_t *co )
{
    /* 如果不是共享栈，释放stack_buffer和stack_mem */
    if (!co->cIsShareStack)
    {
        free(co->stack_mem->stack_buffer);
        free(co->stack_mem);
    }
    //walkerdu fix at 2018-01-20
    //存在内存泄漏
    else
    {
        /* 是共享栈 */

        /* 如果是有保存栈释放保存栈 */
        if(co->save_buffer)
            free(co->save_buffer);
        /* 如果栈内存的占用者是调用的协程实体 ，
        这里仅仅将占用者标记为NULL*/
        if(co->stack_mem->occupy_co == co)
            co->stack_mem->occupy_co = NULL;
    }
    /* 释放协程实体 */
    free( co );
}
/* 感觉co_release这个函数很奇怪，
什么也没有做，仅仅调用了co_free */
void co_release( stCoRoutine_t *co )
{
    co_free( co );
}

/* 切换协程cur->pending */
void co_swap(stCoRoutine_t* curr, stCoRoutine_t* pending_co);

/* （启动）（恢复）到co协程 */
void co_resume( stCoRoutine_t *co )
{
	stCoRoutineEnv_t *env = co->env;
  /* 获取栈顶协程（当前协程） */
	stCoRoutine_t *lpCurrRoutine = env->pCallStack[ env->iCallStackSize - 1 ];
	/* 如果该协程尚未开始工作 */
  if( !co->cStart )
	{
		coctx_make( &co->ctx,(coctx_pfn_t)CoRoutineFunc,co,0 );
		co->cStart = 1;
	}
  /* 将co协程放入调用栈顶 */
	env->pCallStack[ env->iCallStackSize++ ] = co;
  /* 切换到co协程 */
	co_swap( lpCurrRoutine, co );


}

// walkerdu 2018-01-14
// 用于reset超时无法重复使用的协程
void co_reset(stCoRoutine_t * co)
{
    if(!co->cStart || co->cIsMain)
        return;

    co->cStart = 0;
    co->cEnd = 0;

    // 如果当前协程有共享栈被切出的buff，要进行释放
    if(co->save_buffer)
    {
        free(co->save_buffer);
        co->save_buffer = NULL;
        co->save_size = 0;
    }

    // 如果共享栈被当前协程占用，要释放占用标志，否则被切换，会执行save_stack_buffer()
    if(co->stack_mem->occupy_co == co)
        co->stack_mem->occupy_co = NULL;
}

/* yield到另外一个协程 弹调用栈，
  并且 co_swap */
void co_yield_env( stCoRoutineEnv_t *env )
{
	/* 选择调用栈顶俩 */
	stCoRoutine_t *last = env->pCallStack[ env->iCallStackSize - 2 ];
	stCoRoutine_t *curr = env->pCallStack[ env->iCallStackSize - 1 ];

  /*这里真的是协程调用栈上的“弹栈”，
  而一般co_resume将重新恢复栈顶，
  co_resume会是epoll上超时事件
  发生的时候 */
	env->iCallStackSize--;
  /* 从curr跳转到last */
	co_swap( curr, last);
}

void co_yield_ct()
{
	co_yield_env( co_get_curr_thread_env() );
}

void co_yield( stCoRoutine_t *co )
{
	co_yield_env( co->env );
}

/* 保存协程栈内存 到 协程实体的->save_buffer */
void save_stack_buffer(stCoRoutine_t* occupy_co)
{
	///copy out
	stStackMem_t* stack_mem = occupy_co->stack_mem;
  /* bp 栈底高地址 ,sp 栈顶低地址 len为两者之差*/
	int len = stack_mem->stack_bp - occupy_co->stack_sp;
  /* free原有的栈缓存区内容 */
	if (occupy_co->save_buffer)
	{
		free(occupy_co->save_buffer), occupy_co->save_buffer = NULL;
	}
  /* 保存的缓冲区中填入从stack_sp 到 stack_bp内的内容 */
	occupy_co->save_buffer = (char*)malloc(len); //malloc buf;
	occupy_co->save_size = len;

	memcpy(occupy_co->save_buffer, occupy_co->stack_sp, len);
}

/* 切换协程 核心代码*/
void co_swap(stCoRoutine_t* curr, stCoRoutine_t* pending_co)
{
  /* 获得env */
 	stCoRoutineEnv_t* env = co_get_curr_thread_env();

	//get curr stack sp
  /* 这里是获得了一个局部变量的地址作为stack_sp，
    其实放在co_swap 的coctx_swap之前都可以，因为
    这个stack_sp是共享栈模式下会复制到协程对象的
    save_buffer空间内。下次切换回co_swap函数的时
    候我们应该将协程栈空间的内容恢复。
  */
	char c;
	curr->stack_sp= &c;
  /* 如果不是分享栈，
  那么就不管env的pendiong_co和 occupy_co */
	if (!pending_co->cIsShareStack)
	{
		env->pending_co = NULL;
		env->occupy_co = NULL;
	}
	else 
	{
    /* 将需要切换到的协程对象作为env的pending */
		env->pending_co = pending_co;
		//get last occupy co on the same stack mem
    /* 找到需要切换到的协程对象的栈内存上的“占有者” */
		stCoRoutine_t* occupy_co = pending_co->stack_mem->occupy_co;
		//set pending co to occupy thest stack mem;
    /* 更新共享栈的占用者为我们即将切换的协程 */
		pending_co->stack_mem->occupy_co = pending_co;
    /* 将env的占用者修改为旧的占用者 */
		env->occupy_co = occupy_co;
    /* 如果占用者存在且和我们即将切换
      的协程不是同一个协程 */
		if (occupy_co && occupy_co != pending_co)
		{
      /* 保存占用者栈内容 */
			save_stack_buffer(occupy_co);
		}
	}

	//swap context
  /* rdi rsi */
  /* 保存旧协程寄存器到旧协程对象的协程栈，
    并通过将需要切换的协程函数指针push入栈的方式，
    最后ret弹栈到rip中执行需要切换的协程函数指针,
    并通过切换的协程的reg[rsi] reg[rdi]中的内容
    作为协程函数的参数。
  （注意我这里说的rsi,rdi是给协程函数传参的co和NULL）
  */
  /* 函数传参　从左向右　rdi rsi，汇编代码会通过rdi,rsi　
  读或者写reg[],之后rsp会置于sp+8的位置 然后从rbp-rsp之间
  所有空间就是协程的栈帧。rsp现在在我们分配的堆内存的高地址上，
  我们在协程如果有调用的函数就会向低地址开辟新的栈帧，这没有问题，
  除非一直到协程栈的最低地址：ctx->ss_sp，那么我们的程序等着段错误吧！
  值得思考的是分配的默认128KB～8MB 的堆内存可以开char s[128000]
  char s[8000000]也是不小的空间，省着用吧！
  （注意我这里说的rsi,rdi是给coctx_swap函数传参的&(curr->ctx)和
    &(pending_co->ctx)
  */
	coctx_swap(&(curr->ctx),&(pending_co->ctx) );

	//stack buffer may be overwrite, so get again;
	stCoRoutineEnv_t* curr_env = co_get_curr_thread_env();
	stCoRoutine_t* update_occupy_co =  curr_env->occupy_co;
	stCoRoutine_t* update_pending_co = curr_env->pending_co;
	
	if (update_occupy_co && update_pending_co && update_occupy_co != update_pending_co)
	{
		//resume stack buffer
    /* 恢复栈缓冲区 */
		if (update_pending_co->save_buffer && update_pending_co->save_size > 0)
		{
			memcpy(update_pending_co->stack_sp, update_pending_co->save_buffer, update_pending_co->save_size);
		}
	}
}

//int poll(struct pollfd fds[], nfds_t nfds, int timeout);
// { fd,events,revents }
struct stPollItem_t ;
/* poll池对象 继承定时器项*/
struct stPoll_t : public stTimeoutItem_t
{
	struct pollfd *fds;
	nfds_t nfds; // typedef unsigned long int nfds_t;

	stPollItem_t *pPollItems;/* poll项数组 */

  /* 这个iAllEventDetach
  全局没有其他地方用到
  或许表示epoll执行了一次 poll
  */
	int iAllEventDetach;

	int iEpollFd; /* epollfd */

	int iRaiseCnt; /* 估计触发次数 */


};
/* 一个可以放到poll项 也就是我们的pollfd包装 继承定时器项 */
struct stPollItem_t : public stTimeoutItem_t
{
	struct pollfd *pSelf;/* 代表自己的pollfd指针 */
	stPoll_t *pPoll;/* 关联的poll池对象 */

	struct epoll_event stEvent;/* 将会放入epoll上关注事件 */
};
/*
 *   EPOLLPRI 		POLLPRI    // There is urgent data to read.
 *   EPOLLMSG 		POLLMSG
 *
 *   				POLLREMOVE
 *   				POLLRDHUP
 *   				POLLNVAL
 *
 * */
static uint32_t PollEvent2Epoll( short events )
{
	uint32_t e = 0;	
	if( events & POLLIN ) 	e |= EPOLLIN;
	if( events & POLLOUT )  e |= EPOLLOUT;
	if( events & POLLHUP ) 	e |= EPOLLHUP;
	if( events & POLLERR )	e |= EPOLLERR;
	if( events & POLLRDNORM ) e |= EPOLLRDNORM;
	if( events & POLLWRNORM ) e |= EPOLLWRNORM;
	return e;
}
static short EpollEvent2Poll( uint32_t events )
{
	short e = 0;	
	if( events & EPOLLIN ) 	e |= POLLIN;
	if( events & EPOLLOUT ) e |= POLLOUT;
	if( events & EPOLLHUP ) e |= POLLHUP;
	if( events & EPOLLERR ) e |= POLLERR;
	if( events & EPOLLRDNORM ) e |= POLLRDNORM;
	if( events & EPOLLWRNORM ) e |= POLLWRNORM;
	return e;
}

/* 线程私有变量 */
static __thread stCoRoutineEnv_t* gCoEnvPerThread = NULL;

/* env初始化 */
void co_init_curr_thread_env()
{
  /* 申请一块stCoRoutineEnv_t */
	gCoEnvPerThread = (stCoRoutineEnv_t*)calloc( 1, sizeof(stCoRoutineEnv_t) );
	stCoRoutineEnv_t *env = gCoEnvPerThread;

  /* （主协程）调用栈大小初始化为0 */
	env->iCallStackSize = 0;
  /* 调用 co_create_env 创建主协程对象 （主协程实体）*/
	struct stCoRoutine_t *self = co_create_env( env, NULL, NULL,NULL );
	self->cIsMain = 1;/* 设置为Main"主协程" */

	env->pending_co = NULL;
	env->occupy_co = NULL;

  /* 清空ctx */
	coctx_init( &self->ctx );

  /* 在调用栈中放入主协程 */
	env->pCallStack[ env->iCallStackSize++ ] = self;
  /* 申请epoll和定时器相关资源 */
	stCoEpoll_t *ev = AllocEpoll();
  /* 将env和epoll绑定 */
  SetEpoll( env,ev );
}

/* 获得线程私有变量gCoEnvPerThread */
stCoRoutineEnv_t *co_get_curr_thread_env()
{
	return gCoEnvPerThread;
}


/* 切换到定时器项相关的协程 */
void OnPollProcessEvent( stTimeoutItem_t * ap )
{
	stCoRoutine_t *co = (stCoRoutine_t*)ap->pArg;
	co_resume( co );
}

/*
将epoll 上的事件复制到 定时器项上

*/
void OnPollPreparePfn( stTimeoutItem_t * ap,struct epoll_event &e,stTimeoutItemLink_t *active )
{
	stPollItem_t *lp = (stPollItem_t *)ap;
	lp->pSelf->revents = EpollEvent2Poll( e.events );/* 填写pollfd.revents */
	stPoll_t *pPoll = lp->pPoll;/* epoll对象 */
	pPoll->iRaiseCnt++;/* epoll_wait返回后 触发事件次数++ */
  /* 这个iAllEventDetach
  全局没有其他地方用到
  或许表示epoll执行了一次 poll
  第一次触发事件从从epoll的定时器链表中删除，并将
  */
	if( !pPoll->iAllEventDetach )
	{
		pPoll->iAllEventDetach = 1;
    /* 从poll池对象的定时器链表中删除 */
		RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( pPoll );
    /* poll类继承于定时器项
      将poll池对象添加到活跃定时器链表上 */
		AddTail( active,pPoll );
	}
}

/* 主协程eventLoop
等待协程超时事件发生 */
void co_eventloop( stCoEpoll_t *ctx,pfn_co_eventloop_t pfn,void *arg )
{
  /* 如果线程epoll对象没有result */
	if( !ctx->result )
	{
    /* 分配result对象：epoll_event数组的封装类 */
		ctx->result =  co_epoll_res_alloc( stCoEpoll_t::_EPOLL_SIZE );
	}
	co_epoll_res *result = ctx->result;

	for(;;)
	{
    /* epoll_wait 结果放在result中*/
		int ret = co_epoll_wait( ctx->iEpollFd,result,stCoEpoll_t::_EPOLL_SIZE, 1 );

		stTimeoutItemLink_t *active = (ctx->pstActiveList);
		stTimeoutItemLink_t *timeout = (ctx->pstTimeoutList);
    /* 清空超时链表 */
		memset( timeout,0,sizeof(stTimeoutItemLink_t) );
    /* 获得epoll上触发的所有活跃事件 */
		for(int i=0;i<ret;i++)
		{
      /* poll项 */
			stTimeoutItem_t *item = (stTimeoutItem_t*)result->events[i].data.ptr;
      /* 执行可能的准备函数
      如果是hook poll 中 会注册OnPollPreparePfn
      其中会将返回的事件result->events[i]复制到
      item（poll项）定时器项上，还有一些特殊的情况
      会将item（poll项）定时器项加入到active定时器链表中（暂时不知道为何）
      */
			if( item->pfnPrepare )
			{
				item->pfnPrepare( item,result->events[i],active );
			}
			else
			{
        /*否则会直接将item（poll项）定时器项
        加入到active定时器链表中 */
				AddTail( active,item );
			}
		}

    /* 获得当前时间 */
		unsigned long long now = GetTickMS();
    /* 将时间轮上过期对象放入超时链表timeout */
		TakeAllTimeout( ctx->pTimeout,now,timeout );
    /* 遍历超时链表timeout */
		stTimeoutItem_t *lp = timeout->head;
		while( lp )
		{
    /* 表示该项是超时 */
			//printf("raise timeout %p\n",lp);
			lp->bTimeout = true;
			lp = lp->pNext;
		}
    /* 合并超时到活跃 */
		Join<stTimeoutItem_t,stTimeoutItemLink_t>( active,timeout );
    /* 遍历活跃加超时 */
		lp = active->head;
		while( lp )
		{
      /* 弹出头 */
			PopHead<stTimeoutItem_t,stTimeoutItemLink_t>( active );
      /* 如果是超时事件 而且当前时间 < 定时器项超时时间？
      说明该定时器项尚未真的超时 */
      if (lp->bTimeout && now < lp->ullExpireTime)
			{
        /* 重新加入到定时器链表中 */
				int ret = AddTimeout(ctx->pTimeout, lp, now);
        /* 添加成功 */
				if (!ret)
				{
          /* 超时标记取消 */
					lp->bTimeout = false;
          /* 继续遍历 */
					lp = active->head;
					continue;
				}
			}
      /* 如果有处理函数
      （对于一个协程 注册的poll来说
      来说是 resume
      协程调用栈会将该协程入栈，
      然后切换（恢复）到该协程）
      */
			if( lp->pfnProcess )
			{
				lp->pfnProcess( lp );
			}

      /* 继续遍历 */
			lp = active->head;
		}
    /* 这个应该是主线程在处理了所有事件之后的
    可以执行的任务函数 */
		if( pfn )
		{
			if( -1 == pfn( arg ) )
			{
				break;
			}
		}

	}
}

/* 超时事件？一个全局未被使用的函数 */
void OnCoroutineEvent( stTimeoutItem_t * ap )
{
	stCoRoutine_t *co = (stCoRoutine_t*)ap->pArg;
	co_resume( co );
}

/* 申请epollfd和定时器相关资源 */
stCoEpoll_t *AllocEpoll()
{
  /* 这个epoll对象取名叫上下文是不是有问题？ */
	stCoEpoll_t *ctx = (stCoEpoll_t*)calloc( 1,sizeof(stCoEpoll_t) );
  /* 获得epoll_fd maxsize =10240 */
	ctx->iEpollFd = co_epoll_create( stCoEpoll_t::_EPOLL_SIZE );
  /* 申请定时管理器，60 second  精确到毫秒 */
	ctx->pTimeout = AllocTimeout( 60 * 1000 );
	
  /* 申请活跃链表 */
	ctx->pstActiveList = (stTimeoutItemLink_t*)calloc( 1,sizeof(stTimeoutItemLink_t) );
  /* 申请超时链表 */
	ctx->pstTimeoutList = (stTimeoutItemLink_t*)calloc( 1,sizeof(stTimeoutItemLink_t) );


	return ctx;
}

void FreeEpoll( stCoEpoll_t *ctx )
{
	if( ctx )
	{
		free( ctx->pstActiveList );
		free( ctx->pstTimeoutList );
		FreeTimeout( ctx->pTimeout );
		co_epoll_res_free( ctx->result );
	}
	free( ctx );
}

/* 获得当前协程 */
stCoRoutine_t *GetCurrCo( stCoRoutineEnv_t *env )
{
	return env->pCallStack[ env->iCallStackSize - 1 ];
}
/* 获得当前线程上正在执行的协程 */
stCoRoutine_t *GetCurrThreadCo( )
{
	stCoRoutineEnv_t *env = co_get_curr_thread_env();
	if( !env ) return 0;
	return GetCurrCo(env);
}

/* poll的内部函数，将会在向本线程的eventLoop
注册超时事件之后 yield到上个协程，超时以后会将
注册的事件返回到poll，并 在EvnetLoop 中取消监听，
可以说 被hook的pool系统调用 就是yield 到主协程，
主协程的eventLoop 帮我们执行了系统调用。
 */
typedef int (*poll_pfn_t)(struct pollfd fds[], nfds_t nfds, int timeout);
int co_poll_inner( stCoEpoll_t *ctx,struct pollfd fds[], nfds_t nfds, int timeout, poll_pfn_t pollfunc)
{
    /* 如果超时时间0则调用传入的pollfunc,也就是原始版本 */
  if (timeout == 0)
  {
		return pollfunc(fds, nfds, timeout);
	}
  /* 如果时间 < 0 无限等待，则换成INT_MAX*/
	if (timeout < 0)
	{
		timeout = INT_MAX;
	}
	int epfd = ctx->iEpollFd;
	stCoRoutine_t* self = co_self();/* 获得当前线程协程对象 */

	//1.struct change
  /* 貌似后面是转到使用epoll */
  /* poll池对象（继承了定时器项） */
	stPoll_t& arg = *((stPoll_t*)malloc(sizeof(stPoll_t)));
	memset( &arg,0,sizeof(arg) );

	arg.iEpollFd = epfd;
	arg.fds = (pollfd*)calloc(nfds, sizeof(pollfd));
	arg.nfds = nfds;

  /* 性能优化...使用分配的协程栈空间还是重新malloc新空间 */
	stPollItem_t arr[2];
  /* 如果数量 <2 而且不使用共享栈，那就用这个“局部“的栈空间*/
	if( nfds < sizeof(arr) / sizeof(arr[0]) && !self->cIsShareStack)
	{
		arg.pPollItems = arr;
	}
	else
	{
    /* 否则乖乖malloc */
		arg.pPollItems = (stPollItem_t*)malloc( nfds * sizeof( stPollItem_t ) );
	}
	memset( arg.pPollItems,0,nfds * sizeof(stPollItem_t) );

  /* co_resume
  超时事件回调
  等会主协程的epoll会调用它切换回本协程*/
	arg.pfnProcess = OnPollProcessEvent;
	arg.pArg = GetCurrCo( co_get_curr_thread_env() );/* 当前的协程实体 */

	//2. add epoll
  /* 将poll上所有注册的事件转移到epoll上 */
	for(nfds_t i=0;i<nfds;i++)
	{
		arg.pPollItems[i].pSelf = arg.fds + i;//pollfd*
		arg.pPollItems[i].pPoll = &arg;//poll对象
    /* 预处理函数 将epoll 上的事件复制到 定时器项上 */
		arg.pPollItems[i].pfnPrepare = OnPollPreparePfn;
    /* 注意每个poll事件都只是预处理函数，而不是OnPollProcessEvent */
		struct epoll_event &ev = arg.pPollItems[i].stEvent;

		if( fds[i].fd > -1 )
		{
      /* 填写 ptr = poll项数组其中一项item */
			ev.data.ptr = arg.pPollItems + i;
      /* 填写 关注事件 */
			ev.events = PollEvent2Epoll( fds[i].events );
      /* 让epoll开始关注 */
			int ret = co_epoll_ctl( epfd,EPOLL_CTL_ADD, fds[i].fd, &ev );
			if (ret < 0 && errno == EPERM && nfds == 1 && pollfunc != NULL)
			{
				if( arg.pPollItems != arr )
				{
					free( arg.pPollItems );
					arg.pPollItems = NULL;
				}
				free(arg.fds);
				free(&arg);
				return pollfunc(fds, nfds, timeout);
			}
		}
		//if fail,the timeout would work
	}

	//3.add timeout

	unsigned long long now = GetTickMS();
	arg.ullExpireTime = now + timeout;
  /* 由于arg继承了一个计时器项，
    添加计时器项 arg 到epoll的
    时间轮上。其实这里也可以看出来poll
    这个被hook的系统调用即使没有注册任何事件，
    依旧会注册给主协程epoll一个超时事件，主协程
    无论如何1s就会醒来，然后会依次执行epoll上注册的
    每个超时事件或者活跃事件，
    回调函数OnPollProcessEvent 切换回本协程（注意并不是指
    真1s，若在某个超时事件切换到别的协程，然后一直在那里不切出，
    那其他协程就会持续饥饿）
  */
	int ret = AddTimeout( ctx->pTimeout,&arg,now );
	int iRaiseCnt = 0;
	if( ret != 0 )
	{
		co_log_err("CO_ERR: AddTimeout ret %d now %lld timeout %d arg.ullExpireTime %lld",
				ret,now,timeout,arg.ullExpireTime);
		errno = EINVAL;
		iRaiseCnt = -1;

	}
  else
	{
    /* 跳到上一层协程上 */
		co_yield_env( co_get_curr_thread_env() );
    /* 跳回来，说明epoll上已经将所有的poll事件
    写回arg.pollfd[i].revents了 */
		iRaiseCnt = arg.iRaiseCnt;/* 作为返回的活跃事件数 */
	}

  {
		//clear epoll status and memory
    /* 从epoll中取消监听该poll池的超时事件 */
		RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( &arg );
    /* 从epoll中取消监听poll上注册的事件事件 */
		for(nfds_t i = 0;i < nfds;i++)
		{
			int fd = fds[i].fd;
			if( fd > -1 )
			{
        /* 取消关注 */
				co_epoll_ctl( epfd,EPOLL_CTL_DEL,fd,&arg.pPollItems[i].stEvent );
			}
      /* 复制回写事件 */
			fds[i].revents = arg.fds[i].revents;
		}


		if( arg.pPollItems != arr )
		{
			free( arg.pPollItems );
			arg.pPollItems = NULL;
		}

		free(arg.fds);
		free(&arg);
	}
  /* 返回的活跃事件数 */
	return iRaiseCnt;
}

/* 无超时版本的co_poll_inner */
int	co_poll( stCoEpoll_t *ctx,struct pollfd fds[], nfds_t nfds, int timeout_ms )
{
	return co_poll_inner(ctx, fds, nfds, timeout_ms, NULL);
}

/* 将env和epoll绑定 */
void SetEpoll( stCoRoutineEnv_t *env,stCoEpoll_t *ev )
{
	env->pEpoll = ev;
}
/* 获得本线程的epoll对象 */
stCoEpoll_t *co_get_epoll_ct()
{
	if( !co_get_curr_thread_env() )
	{
		co_init_curr_thread_env();
	}
	return co_get_curr_thread_env()->pEpoll;
}
struct stHookPThreadSpec_t
{
	stCoRoutine_t *co;
	void *value;

	enum 
	{
		size = 1024
	};
};
void *co_getspecific(pthread_key_t key)
{
	stCoRoutine_t *co = GetCurrThreadCo();
	if( !co || co->cIsMain )
	{
		return pthread_getspecific( key );
	}
	return co->aSpec[ key ].value;
}
int co_setspecific(pthread_key_t key, const void *value)
{
	stCoRoutine_t *co = GetCurrThreadCo();
	if( !co || co->cIsMain )
	{
		return pthread_setspecific( key,value );
	}
	co->aSpec[ key ].value = (void*)value;
	return 0;
}


/* 禁用hook */
void co_disable_hook_sys()
{
	stCoRoutine_t *co = GetCurrThreadCo();
	if( co )
	{
		co->cEnableSysHook = 0;
	}
}

/* 获得当前线程的协程，
看它是否支持hook */
bool co_is_enable_sys_hook()
{
	stCoRoutine_t *co = GetCurrThreadCo();
	return ( co && co->cEnableSysHook );
}

/* 获得本线程的当前协程 */
stCoRoutine_t *co_self()
{
	return GetCurrThreadCo();
}

//co cond
struct stCoCond_t;

/* 含有一个定时器项 */
struct stCoCondItem_t
{
	stCoCondItem_t *pPrev;
	stCoCondItem_t *pNext;
	stCoCond_t *pLink;

	stTimeoutItem_t timeout;
};

/* stCoCond_t是一个链表 */
struct stCoCond_t
{
	stCoCondItem_t *head;
	stCoCondItem_t *tail;
};

/* 和 OnPollProcessEvent 一样 也是resume
  同时我们可以看出libco代码有多烂了。
*/
static void OnSignalProcessEvent( stTimeoutItem_t * ap )
{
	stCoRoutine_t *co = (stCoRoutine_t*)ap->pArg;
	co_resume( co );
}

stCoCondItem_t *co_cond_pop( stCoCond_t *link );

int co_cond_signal( stCoCond_t *si )
{
	stCoCondItem_t * sp = co_cond_pop( si );
	if( !sp ) 
	{
		return 0;
	}
	RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( &sp->timeout );

	AddTail( co_get_curr_thread_env()->pEpoll->pstActiveList,&sp->timeout );

	return 0;
}
int co_cond_broadcast( stCoCond_t *si )
{
	for(;;)
	{
		stCoCondItem_t * sp = co_cond_pop( si );
		if( !sp ) return 0;

		RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( &sp->timeout );

		AddTail( co_get_curr_thread_env()->pEpoll->pstActiveList,&sp->timeout );
	}

	return 0;
}


int co_cond_timedwait( stCoCond_t *link,int ms )
{
	stCoCondItem_t* psi = (stCoCondItem_t*)calloc(1, sizeof(stCoCondItem_t));
	psi->timeout.pArg = GetCurrThreadCo();
	psi->timeout.pfnProcess = OnSignalProcessEvent;

	if( ms > 0 )
	{
		unsigned long long now = GetTickMS();
		psi->timeout.ullExpireTime = now + ms;

		int ret = AddTimeout( co_get_curr_thread_env()->pEpoll->pTimeout,&psi->timeout,now );
		if( ret != 0 )
		{
			free(psi);
			return ret;
		}
	}
	AddTail( link, psi);

	co_yield_ct();


	RemoveFromLink<stCoCondItem_t,stCoCond_t>( psi );
	free(psi);

	return 0;
}

/* calloc stCoCond_t */
stCoCond_t *co_cond_alloc()
{
	return (stCoCond_t*)calloc( 1,sizeof(stCoCond_t) );
}
/* free stCoCond_t */
int co_cond_free( stCoCond_t * cc )
{
	free( cc );
	return 0;
}

/* 将CoCond链表的头节点弹出 */
stCoCondItem_t *co_cond_pop( stCoCond_t *link )
{
	stCoCondItem_t *p = link->head;
	if( p )
	{
		PopHead<stCoCondItem_t,stCoCond_t>( link );
	}
	return p;
}
