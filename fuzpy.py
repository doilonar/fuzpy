from scapy.all import *
import binascii
import socket

def fuzz_replier(target,port):
    try:
        # Open socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set reuse ON
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind port
        s.bind((target, port))
        s.listen(1)
        conn, addr = s.accept()
        print("[" + time.strftime('%a %H:%M:%S') + "]" + " - " + "Connected to: "), addr
        print("[" + time.strftime('%a %H:%M:%S') + "]" + " - " + "Waiting for a connection.. ")
        # Loop to send crafted packages
        while 1:
            data = conn.recv(4096)
            if not data: break
            print("[" + time.strftime('%a %H:%M:%S') + "]" + " - " + "Received: ") + data
            packet = IP(dst=target) / TCP(dport=port) / fuzz(Raw())

            # Log the packet  in hexa and timestamp
            fileLog = target + ".log"
            logPacket = open(fileLog, "w+")
            logPacket.write("["+time.strftime('%a %H:%M:%S')+"]"+ " - Packet sent: " + binascii.hexlify(bytes(packet))+"\n")
            logPacket.close()

            # Write bytecodes to socket
            print("["+time.strftime('%a %H:%M:%S')+"]"+" - "+"Packet sent: ")
            conn.send(bytes(packet))
            print(bytes(packet))
        conn.close()
    except socket.error as error:
        print error
        print "Sorry something went wrong!"

def fuzz_connect(target,port):
    try:
        while 1:
            # Open socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set reuse ON
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind port
            s.connect((target, port))
            s.settimeout(1.0)
            print("[" + time.strftime('%a %H:%M:%S') + "]" + " - " + "Connected to:"), target, port
            print("[" + time.strftime('%a %H:%M:%S') + "]" + " - " + "Establishing connection.. ")
            packet = IP(dst=target) / TCP(dport=port) / fuzz(Raw())

            # Log the packet in hexa and timestamp
            fileLog = target + ".log"
            logPacket = open(fileLog, "w+")
            logPacket.write("["+time.strftime('%a %H:%M:%S')+"]"+ " - Packet sent: " + binascii.hexlify(bytes(packet))+"\n")
            logPacket.close()

            # Write bytecodes to socket
            print("["+time.strftime('%a %H:%M:%S')+"]"+" - "+"Packet sent: ")
            s.send(bytes(packet))
            # Packet sent:
            print(bytes(packet))
            try:
                data = s.recv(4096)
                s.settimeout(0)
                print("[" + time.strftime('%a %H:%M:%S') + "]" + " - "+ "Data received: '{msg}'".format(msg=data))
            except socket.error, e:
                err = e.args[0]
                if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                    print 'Sorry, No data available'
                    continue
        s.close()
    except socket.error as error:
        print error
        print "Sorry, something went wrong!"

def howtouse():
    print "Usage: fuzpy.py  Hostname Port Payload"
    sys.exit(-1)

if __name__ == "__main__":
    try:
        # Set target
        target = sys.argv[1]
        port = int(sys.argv[2])

        fuzz_connect(target, port)
        fuzz_replier(target, port)
    except IndexError:
        howtouse()

