import time
import urllib2

start_time = time.time()

for j in range(0, 300):
#for j in range(0, 5):
    opener = urllib2.build_opener()
    opener.addheaders = [('User-agent', 'android')]
    response = opener.open('http://127.0.0.1/search.php')

    print 'cpu %d' % j
    
elapsed_time = time.time() - start_time
print 'cpu done in %.3f' % (elapsed_time)
