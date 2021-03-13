#pragma once

#include "co_routine.h"

/* 协程锁 */
class clsCoMutex {
 public:
  clsCoMutex();
  ~clsCoMutex();

  void CoLock();
  void CoUnLock();

 private:
  stCoCond_t* m_ptCondSignal;
  int m_iWaitItemCnt;
};

/* 协程 lock_guard */
class clsSmartLock {
 public:
  clsSmartLock(clsCoMutex* m) {
    m_ptMutex = m;
    m_ptMutex->CoLock();
  }
  ~clsSmartLock() { m_ptMutex->CoUnLock(); }

 private:
  clsCoMutex* m_ptMutex;
};

