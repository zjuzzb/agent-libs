#!/usr/bin/env python3
#
# This will run a fake collector which sysdig agent can connect to so that
# agent functionality can be tested.
# To run:
# > python3 fake-collector.py
#

from __future__ import print_function

from enum import Enum
import gzip
import socket
import struct
import sys
import threading
import draios_pb2
from getchar import getch

class INCOMING_VERBOSITY(Enum):
    OFF = 0
    HEADER_ONLY = 1
    VERBOSE = 2

# const globals
HOST = 'localhost'
PORT = 6666
DRAGENT_PROTOCOL_HEADER_SIZE = 6

# Run a simple socket listener on a seperate thread
class packet_handler(threading.Thread):
    def __init__(self, conn):
        super(packet_handler, self).__init__()
        self.m_conn = conn
        self.m_see_received_messages = INCOMING_VERBOSITY.OFF
        self.m_abort = 0

    def run(self):
        try:
            self.do_run()
        except Exception as e:
            print(e)
        return

    def send(self, msg):
        self.m_conn.send(msg)

    def close(self):
        self.m_conn.close()

    def show(self, value = None):
        if value is None:
            return self.m_see_received_messages
        else:
            self.m_see_received_messages = value

    def abort(self):
        self.m_abort = 1

    def do_run(self):
        while not self.m_abort:
            header_string = self.m_conn.recv(DRAGENT_PROTOCOL_HEADER_SIZE)
            if header_string:
                self.read_protobuf(header_string)
                header_string = ""

    def read_protobuf(self, header_string):
        header = struct.unpack('!IBB', header_string)

        if self.m_see_received_messages.value >= INCOMING_VERBOSITY.HEADER_ONLY.value:
            name = draios_pb2._MESSAGE_TYPE.values_by_number[header[2]].name
            print("{0} Size: {1}".format( name, header[0]))

        remaining_bytes = header[0] - DRAGENT_PROTOCOL_HEADER_SIZE
        if self.m_abort:
            return

        payload = self.m_conn.recv(remaining_bytes)

        if self.m_see_received_messages.value >= INCOMING_VERBOSITY.VERBOSE.value:
            self.print_payload(header[2], payload)

    def print_payload(self, protobuf_type, payload):
        if protobuf_type == draios_pb2.METRICS:
            metrics_obj = draios_pb2.metrics()
            metrics_obj.ParseFromString(payload)
            print(metrics_obj)
        else:
            name = type_to_name(header[2], draios_pb2.message_type.DESCRIPTOR)
            print("{0} message is not supported in fake-collector. You should add it.".format(name))


def send_protobuf(ph, protobuf_obj, message_type):

    dragent_protobuf_version = 4

    out = protobuf_obj.SerializeToString()
    out = gzip.compress(out)
    header = struct.pack('!IBB',
                         DRAGENT_PROTOCOL_HEADER_SIZE + len(out),
                         dragent_protobuf_version,
                         message_type)

    ph.send(header)
    ph.send(out)

    print("")
    name = draios_pb2._MESSAGE_TYPE.values_by_number[message_type].name
    print("Sending {0} ({1})".format(name, message_type))
    print(protobuf_obj)

def send_error_protobuf(ph):
    message = draios_pb2.error_message()
    print("")
    print("Enter Error Message Details")
    print("Error Type: ", end="")
    message.type = int(input())
    print("Description: ", end="")
    message.description = input()
    send_protobuf(ph, message, draios_pb2.ERROR_MESSAGE)

def send_buffer_console(ph):

    while True:
        print("")
        print("Select Message to Send:")
        print("1. Error Message")
        print("q. back")
        print("> ", end="")
        user_input = getch()
        print(user_input)
        print("")

        if user_input == "q":
            return
        if user_input == "1":
            send_error_protobuf(ph)
            return


def console(ph):
    try:
        while True:
            print("")
            print("Select an option:")
            print("1. Toggle Incoming ProtoBuffers")
            print("2. Send ProtoBuffer")
            print("q. Quit")
            print("> ", end="")
            user_input = getch()
            print(user_input)

            if user_input == "q":
                return
            elif user_input == "1":
                temp = INCOMING_VERBOSITY((ph.show().value + 1) % 3)
                print(temp)
                ph.show(temp)
            elif user_input == "2":
                send_buffer_console(ph)
    except Exception as e:
        print(e)

if __name__ == '__main__':
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((HOST, PORT))
        s.listen(5)

        print("")
        print("Add the following to your agent config:")
        print("collector: {0}".format(HOST))
        print("collector_port: {0}".format(PORT))
        print("ssl: false")
        print("compression:")
        print("    enabled: false")
        print("");

        print('Listening for connections on {0}:{1}'.format(HOST, PORT))

        conn, address = s.accept()

        ph = packet_handler(conn)
        ph.start()

        print('Client connected: {0}'.format(address[0]))
        console(ph);

        ph.abort();
        ph.close()
    except socket.error:
        print('Failed to create socket')
        sys.exit(1)

