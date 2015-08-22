import subprocess
import sys
import time
import os
import socket

logfile = None
markerfile = None

def log( string ):
    global logfile

    if logfile == None:
        logfile = open("usapp.log", "w")
    logfile.write(string);
    logfile.flush();
    return

def mark( string ):
    global markerfile

    if markerfile == None:
        markerfile = open("/dev/sysdig-events", "w")
    markerfile.write(string);
    markerfile.flush();
    return

try:
    NCHILDS = int(os.environ['NC'])
    NAME = os.environ['NAME']

    log("simple service daemon starting\n")
    log("linked service dependencies: %d\n" % NCHILDS)
    for j in range(0, NCHILDS):
        # Create the child name
        chname = "srvc_next" + str(j)
        log("  %s\n" % chname)

    if os.environ['ROLE'] == 'root':
        log("Starting request generation loop...\n")

        #try:
        #    settingsfile = open("usapp.cfg", "r")
        #except:
        #    log("error: cannot open usapp.cfg for reading")
        #    sys.exit(0)

        while True:
            mark(">:t:us::")

            for j in range(0, NCHILDS):

                # Set up a TCP/IP socket
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

                # Create the child name
                chname = "srvc_next" + str(j)

                # Connect to the child
                s.connect((chname, 8080))

                # Protocol exchange - sends and receives
                #s.send("GET /API/info HTTP/1.1\nx-SDMarker: %s\n\n" % NAME)

                mark(">:t:us.%s::" % chname)
                s.send(NAME)

                while True:
                    resp = s.recv(1024)
                    if resp == "": break
                    print resp,

                mark("<:t:us.%s::" % chname)

                # Close the connection when completed
                s.close()

            mark("<:t:us::")

            time.sleep(0.1)

    log("Starting request server\n")

    # Establish a TCP/IP socket
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    # Bind to TCP port
    s.bind(("",8080))

    # ... and listen for anyone to contact you
    # queueing up to five requests if you get a backlog
    s.listen(5)

    log("server listening on port 8080\n")

    # Server loop
    while True:
            # Wait for a connection
            connect, address = s.accept()

            # Receive up to 1024 bytes
            resp = (connect.recv(1024)).strip()

            ###########################################
            # Talk to the next tier
            ###########################################
            for j in range(0, NCHILDS):
                # Set up a TCP/IP socket
                sc = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

                # Create the child name
                chname = "srvc_next" + str(j)

                # Connect to the child
                sc.connect((chname, 8080))

                # Protocol exchange - sends and receives
                #sc.send("GET /API/info HTTP/1.1\nx-SDMarker: %s\n\n" % NAME)
                sc.send(resp + '.' + NAME)
                while True:
                    respc = sc.recv(1024)
                    if respc == "": break
                    print respc,

                # Close the connection when completed
                print sc.getsockname()
                sc.close()

            # Send an answer
            connect.send("You said '" + resp + "' to me\n")

            # Done with thw connection. Close it.
            connect.close()
            print "\ndone",address

except Exception as e:
    log("error: " + str(e))

'''
print os.environ['NEXT']
time.sleep(30)
sys.exit(0)

BASE_ADDR = ("127.0.0.1", 45600)

if len(sys.argv) != 2 and len(sys.argv) != 3:
    print "wrong number of arguments"
    sys.exit(0)

depth = int(sys.argv[1])

print "EEE %d" % depth
#subprocess.Popen("python /home/loris/agent/stress/uservices/us.py", shell=False)
execfile("us.py", {1: "44"})
'''