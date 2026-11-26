#!/usr/bin/env python3
"""Deterministic exception/progress checks without networking or waiting for a soak."""
import threading
import unittest
from hy2_long_budget import check_window,churn_loop


class TestChurn(unittest.TestCase):
    def run_case(self,fn):
        stop=threading.Event();lock=threading.Lock();successful=[];failures=[]
        doc={'inbounds':{'hy2':{}}}
        thread=threading.Thread(target=churn_loop,args=(stop,doc,fn,successful,failures,lock,.001))
        thread.start();thread.join(1)
        self.assertFalse(thread.is_alive())
        return stop,successful,failures

    def test_unexpected_exception_is_propagated(self):
        def failed(_doc,_rev):raise OSError('sensitive detail intentionally not exposed')
        stop,successful,failures=self.run_case(failed)
        self.assertTrue(stop.is_set());self.assertEqual(successful,[]);self.assertEqual(failures,['churn-OSError'])

    def test_rejected_apply_not_counted(self):
        stop,successful,failures=self.run_case(lambda _doc,_rev:(503,{}))
        self.assertTrue(stop.is_set());self.assertEqual(successful,[]);self.assertEqual(failures,['churn-RuntimeError'])

    def test_success_then_exception_counts_only_success(self):
        def apply(_doc,revision):
            if revision==1:return 200,{'revision':2}
            raise ValueError('must not escape silently')
        stop,successful,failures=self.run_case(apply)
        self.assertTrue(stop.is_set());self.assertEqual(len(successful),1);self.assertEqual(failures,['churn-ValueError'])

    def test_progress_and_short_check(self):
        check_window(10,10,1,1,1,0,True,True)
        check_window(900,900,1,1,1,44,False,True)
        check_window(900,900,1,1,1,0,False,False)
        for args in ((899,900,1,1,1,44,False,True),(900,900,0,1,1,44,False,True),
                     (900,900,1,0,1,44,False,True),(900,900,1,1,0,44,False,True),
                     (900,900,1,1,1,0,False,True)):
            with self.assertRaises(RuntimeError):check_window(*args)

if __name__=='__main__':unittest.main()
