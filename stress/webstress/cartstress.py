import time
import urllib2

start_time = time.time()

for j in range(0, 300):
#for j in range(0, 5):
    opener = urllib2.build_opener()
    opener.addheaders = [('User-agent', 'pc')]
    response = opener.open('http://127.0.0.1/updatecart.php')
#    time.sleep(.3)
    print 'app %d' % j
    
elapsed_time = time.time() - start_time
print 'app done in %.3f' % (elapsed_time)
