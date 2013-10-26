import threading
import httplib
import time

URL = '127.0.0.1'
NTHREADS = 3
NREQS_PER_THREAD = 1000
DELAY = 0.1

class SummingThread(threading.Thread):
     def __init__(self, url):
         threading.Thread.__init__(self)
         self.conn = httplib.HTTPConnection(url)

     def run(self):
         for k in range(0, NREQS_PER_THREAD):
             self.conn.request('GET', '/')
             r1 = self.conn.getresponse()
             r1.read()
             time.sleep(DELAY)
         self.conn.close()

threads = []

for j in range(0, NTHREADS):
    threads.append(SummingThread(URL))
    threads[j].start() # This actually causes the thread to run

for j in range(0, NTHREADS):
    threads[j].join()  # This waits until the thread has completed
