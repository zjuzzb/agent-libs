import subprocess
import sys
import time
import os
import socket
import json
import random

logfile = None
markerfile = None
g_cnt = 0

def log( string ):
    global logfile

    if logfile == None:
        logfile = open("usapp.log", "w")
    logfile.write(string);
    logfile.flush();
    return
'''
def log( string ):
    sys.stdout.write(string);
    sys.stdout.flush();
    return
'''

def mark( string ):
    global markerfile

    if markerfile == None:
        markerfile = open("/dev/null", "w")
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
    mark(">:%s.write::" % tag)
    
    tfile = open("tfile.out", "w")
    for j in range(0, num):
        tfile.write("132467890123456790132467890123456790132467890123456790132467890123456790132467890123456790");
    tfile.close()
    time.sleep(random.uniform(0, .1))

    mark("<:%s.write::" % tag)
    
    mark(">:%s.read::" % tag)
    time.sleep(random.uniform(0, .2))
    mark("<:%s.read::" % tag)

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
    try:
        SYNC = os.environ['SYNC']
    except Exception as e:
        SYNC = 'true'
    try:
        CHILD_NAMES = json.loads(os.environ['CHILD_NAMES'])
#        log("error *******: %s -- %d" % (str(CHILD_NAMES), len(CHILD_NAMES)))
    except Exception as e:
        CHILD_NAMES = []

    if len(CHILD_NAMES) != NCHILDS:
        log("CHILD_NAMES and NC environment variables don't match")
        sys.exit(0)

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
    log("SYNC: %s\n" % SYNC)
    log("CHILD_NAMES: %s" % str(CHILD_NAMES))

    for cn in CHILD_NAMES:
        cn['cur'] = 0

    if os.environ['ROLE'] == 'root':
        reqid = 0
        log("Starting request generation loop...\n")

        #try:
        #    settingsfile = open("usapp.cfg", "r")
        #except:
        #    log("error: cannot open usapp.cfg for reading")
        #    sys.exit(0)
        #while True:
        for x in range(0, 10):
            reqid = reqid + 1
            mark(">:%d:%s::" % (reqid, NAME))

            chnames = []
            depnames = []
            tags = []
            for j in range(0, NCHILDS):
                # Create the child name and tag
                chnames.append("srvc_next" + str(j))
                cname = CHILD_NAMES[j]['e'][CHILD_NAMES[j]['cur'] % len(CHILD_NAMES[j]['e'])]
                dn = "%s.%s" % (NAME, cname)
                CHILD_NAMES[j]['cur'] += 1
                depnames.append(dn)
                tags.append("%s" % dn)

            if SYNC == 'true':
                for j in range(0, NCHILDS):
                    log("Child transaction start\n")

                    # Set up a TCP/IP socket
                    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

                    # Connect to the child
                    s.connect((chnames[j], 8080))

                    # Protocol exchange - sends and receives
                    #s.send("GET /API/info HTTP/1.1\nx-SDMarker: %s\n\n" % NAME)
                    mark(">:%d:%s:n=%d:" % (reqid, tags[j], reqid))
                    log("Sending request to " + chnames[j])

                    payload = "%d:%s" % (reqid, tags[j])
                    s.send(payload)

                    while True:
                        resp = s.recv(1024)
                        if resp == "": break

                    mark("<:%d:%s::" % (reqid, tags[j]))

                    # Close the connection when completed
                    s.close()
            else:
                ss = []
                for j in range(0, NCHILDS):
                    # Set up a TCP/IP socket
                    ss.append(socket.socket(socket.AF_INET,socket.SOCK_STREAM))

                    # Connect to the child
                    ss[j].connect((chnames[j], 8080))

                    mark(">:%d:%s:n=%d:" % (reqid, tags[j], reqid))
                    payload = "%d:%s" % (reqid, tags[j])
                    ss[j].send(payload)

                for j in range(0, NCHILDS):
                    while True:
                        resp = ss[j].recv(1024)
                        if resp == "": break
                        print resp,

                    mark("<:%d:%s::" % (reqid, tags[j]))

                    # Close the connection when completed
                    ss[j].close()

            if CPU_OPS != 0:
                cpu_ops("%d:%s" % (reqid, NAME), CPU_OPS)

            if IO_OPS != 0:
                io_ops("%d:%s" % (reqid, NAME), IO_OPS)

            mark("<:%d:%s::" % (reqid, NAME))

            time.sleep(0.1)

        time.sleep(1000000)

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

            log("received connection\n")
            
            ##################################################################################################################3
            time.sleep(random.uniform(0, .1))

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
                depname = "%s" % (CHILD_NAMES[j]['e'][CHILD_NAMES[j]['cur'] % len(CHILD_NAMES[j]['e'])])
                CHILD_NAMES[j]['cur'] += 1
                subtag = tag + "." + depname

                if depname == "dbquery" and g_cnt == 7:
                    log("error **************************: %d %s %s" % (g_cnt, depname, tag.split(':')[1]))
                    time.sleep(2)
                g_cnt = g_cnt + 1

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

            mark("<:%s::" % tag)

            # Done with thw connection. Close it.
            connect.close()

except Exception as e:
    log("error: " + str(e))
