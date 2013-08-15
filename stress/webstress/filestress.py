import time
import urllib2

start_time = time.time()

for j in range(0, 1500):
#for j in range(0, 5):
    opener = urllib2.build_opener()
    opener.addheaders = [('User-agent', 'iphone')]
    response = opener.open('http://127.0.0.1/productvideo.mpg')

#    time.sleep(.3)
    print 'file %d' % j
    
elapsed_time = time.time() - start_time
print 'file done in %.3f' % (elapsed_time)
