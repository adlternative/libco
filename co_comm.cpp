#include "co_comm.h"

clsCoMutex::clsCoMutex() {
  m_ptCondSignal = co_cond_alloc();
  m_iWaitItemCnt = 0;
}

clsCoMutex::~clsCoMutex() { co_cond_free(m_ptCondSignal); }

/* 上锁 不过是一个计时器 */
void clsCoMutex::CoLock() {
  /* 一个初始化的协程锁
    会选择让m_iWaitItemCnt++;
    然而下次如果还加锁则会无限等待（除非被唤醒）
  */
  if (m_iWaitItemCnt > 0) {
    m_iWaitItemCnt++;
    /* 只加到定时器链表上，
      没有让epoll监听，
      所以无限的“等待”（yield） */
    co_cond_timedwait(m_ptCondSignal, -1);
  } else {
    m_iWaitItemCnt++;
  }
}

void clsCoMutex::CoUnLock() {
  /* 解锁后这个数量--; */
  m_iWaitItemCnt--;
  /* 通知一个条件变量链表上的头条件变量
  所对应的协程 “即将” 唤醒 。 */
  co_cond_signal(m_ptCondSignal);
}

