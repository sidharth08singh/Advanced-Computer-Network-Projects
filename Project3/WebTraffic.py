#!/usr/bin/python

import threading
import time
import sys
import subprocess

exitFlag = 0

class myThread (threading.Thread):
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
    def run(self):
        print "Starting " + self.name
        run_iperf(self.name, self.counter, 50)
        print "Exiting " + self.name

def run_iperf(threadName, delay, counter):
    logfile = open('dataFile', 'a')
    while counter:
        if exitFlag:
            thread.exit()
        time.sleep(delay)
        print "%s: flow %s" % (threadName, counter)
	proc = subprocess.Popen(["curl", "-o", "/dev/null", "-F", "myfile=@index.html", "http://20.0.0.1/", "-w", "\"\n%{size_upload};%{speed_upload};%{time_total}\""] , stdout=subprocess.PIPE)
	for line in proc.stdout:
		logfile.write(line)
	proc.wait()
        counter -= 1

# Create new threads
thread1 = myThread(1, "Thread-1", 1)
thread2 = myThread(2, "Thread-2", 2)
thread3 = myThread(3, "Thread-3", 3)
thread4 = myThread(4, "Thread-4", 4) 
thread5 = myThread(5, "Thread-5", 5) 
thread6 = myThread(6, "Thread-6", 6)
thread7 = myThread(7, "Thread-7", 7)
thread8 = myThread(8, "Thread-8", 8)
thread9 = myThread(9, "Thread-9", 9)
thread10 = myThread(10, "Thread-10", 10)
thread11 = myThread(11, "Thread-11", 11)
thread12 = myThread(12, "Thread-12", 12)
thread13 = myThread(13, "Thread-13", 13)
thread14 = myThread(14, "Thread-14", 14)
thread15 = myThread(15, "Thread-15", 15)
thread16 = myThread(16, "Thread-16", 16)
thread17 = myThread(17, "Thread-17", 17)
thread18 = myThread(18, "Thread-18", 18)
thread19 = myThread(19, "Thread-19", 19)
thread20 = myThread(20, "Thread-20", 20)

# Start new Threads
thread1.start()

thread2.start()
thread3.start()
thread4.start()
thread5.start()
thread6.start()
thread7.start()
thread8.start()
thread9.start()
thread10.start()
thread11.start()
thread12.start()
thread13.start()
thread14.start()
thread15.start()
thread16.start()
thread17.start()
thread18.start()
thread19.start()
thread20.start()


print "Exiting Main Thread"

