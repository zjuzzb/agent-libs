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

def cpu_ops( tag, num ):
    mark(">:%s.processing::" % tag)
    
    mark(">:%s.processing.prepare::" % tag)
    k = 0
    for j in range(0, num):
        k = k + 1
    mark("<:%s.processing.prepare::" % tag)
    
    mark(">:%s.processing.run::" % tag)
    for j in range(0, num):
        k = k + j * 1000 % 500
    mark("<:%s.processing.run::" % tag)
    
    mark(">:%s.processing.reduce::" % tag)
    for j in range(0, num / 3):
        k = k + j * 1000 % 500
    mark("<:%s.processing.reduce::" % tag)

    mark("<:%s.processing::" % tag)
    
    return

def io_ops( tag, num ):
    mark(">:%s.data_write::" % tag)
    
    tfile = open("tfile.out", "w")
    for j in range(0, num):
        tfile.write("132467890123456790132467890123456790132467890123456790132467890123456790132467890123456790");
    tfile.close()

    mark("<:%s.data_write::" % tag)
    
    return

try:
    #
    # Extract the operational constants
    #
    NCHILDS = int(os.environ['NC'])
    NAME = os.environ['NAME']
    try:
        CPU_OPS = int(os.environ['CPU_OPS'])
    except Exception as e:
        CPU_OPS = 0
    try:
        IO_OPS = int(os.environ['IO_OPS'])
    except Exception as e:
        IO_OPS = 0

    #
    # Initial logging
    #
    log("NAME: %s\n" % NAME)
    log("simple service daemon starting\n")
    log("linked service dependencies: %d\n" % NCHILDS)
    for j in range(0, NCHILDS):
        # Create the child name
        chname = "srvc_next" + str(j)
        log("  %s\n" % chname)
    log("CPU_OPS: %d\n" % CPU_OPS)
    log("IO_OPS: %d\n" % IO_OPS)

    if os.environ['ROLE'] == 'root':
        reqid = 0
        log("Starting request generation loop...\n")

        #try:
        #    settingsfile = open("usapp.cfg", "r")
        #except:
        #    log("error: cannot open usapp.cfg for reading")
        #    sys.exit(0)

        while True:
        #for x in range(0, 10):
            reqid = reqid + 1
            mark(">:%d:%s::" % (reqid, NAME))

            for j in range(0, NCHILDS):
                # Set up a TCP/IP socket
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

                # Create the child name
                chname = "srvc_next" + str(j)
                depname = NAME + ".req" + str(j)
                tag = "%s" % depname

                # Connect to the child
                s.connect((chname, 8080))

                # Protocol exchange - sends and receives
                #s.send("GET /API/info HTTP/1.1\nx-SDMarker: %s\n\n" % NAME)

                mark(">:%d:%s::" % (reqid, tag))
                payload = "%d:%s" % (reqid, tag)
                s.send(payload)

                while True:
                    resp = s.recv(1024)
                    if resp == "": break
                    print resp,

                mark("<:%d:%s::" % (reqid, tag))

                # Close the connection when completed
                s.close()

            if CPU_OPS != 0:
                cpu_ops("%d:%s" % (reqid, tag), CPU_OPS)

            if IO_OPS != 0:
                io_ops("%d:%s" % (reqid, tag), IO_OPS)

            mark("<:%d:%s::" % (reqid, NAME))

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
            tag = resp + "." + NAME

            mark(">:%s::" % tag)

            if CPU_OPS != 0:
                cpu_ops(tag, CPU_OPS)

            if IO_OPS != 0:
                io_ops(tag, IO_OPS)

            ###########################################
            # Talk to the next tier
            ###########################################
            for j in range(0, NCHILDS):
                # Create the child name
                chname = "srvc_next" + str(j)
                depname = "req" + str(j)
                subtag = tag + "." + depname

                mark(">:%s::" % subtag)

                # Set up a TCP/IP socket
                sc = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

                # Connect to the child
                sc.connect((chname, 8080))

                # Protocol exchange - sends and receives
                #sc.send("GET /API/info HTTP/1.1\nx-SDMarker: %s\n\n" % NAME)
                sc.send(subtag)
                while True:
                    respc = sc.recv(1024)
                    if respc == "": break
                    print respc,

                # Close the connection when completed
                print sc.getsockname()
                sc.close()
                mark("<:%s::" % subtag)

            # Send an answer
            connect.send("sent:" + resp)

            # Done with thw connection. Close it.
            connect.close()

            mark("<:%s::" % tag)

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