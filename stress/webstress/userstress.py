import time
import urllib2

start_time = time.time()

for j in range(0, 1000):
#for j in range(0, 5):
    opener = urllib2.build_opener()
    opener.addheaders = [('User-agent', 'android')]
    response = opener.open('http://127.0.0.1/userstats.php')
#    time.sleep(.1)
    print 'db %d' % j
    
elapsed_time = time.time() - start_time
print 'db done in %.3f' % (elapsed_time)    
