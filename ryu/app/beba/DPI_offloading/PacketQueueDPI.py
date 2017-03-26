import Queue
import threading
from scapy.sendrecv import sendp

from params import *


###########################################################################################
# Thread to send the packet in the Queue to the DPI, it is used only if the traffic is
# redirected to the controller that is in charge to forward it to the DPI


# ABSTRACT class, it will have 3 implementation, depending on where the DPI is located
class _ThreadSendPacketAbstract(threading.Thread):
    def __init__(self, pktQueueDPI):
        threading.Thread.__init__(self)
        self.stop_event = threading.Event()
        self._pktQueueDPI = pktQueueDPI
        self.daemon = True

    def run(self):
        raise NotImplementedError


# Class to simulate the sending of the packet, it doesn't do anything with the packet that ideally must go to the DPI
class _ThreadSendPacketFake(_ThreadSendPacketAbstract):
    def run(self):
        while not self.stop_event.is_set():
            try:
                #print "Dimensione coda: " + str(self._pktQueueDPI._queue.qsize())
                packet = self._pktQueueDPI._queue.get(False)
            except Queue.Empty:
                # When the queue is empty, wait 2 second, maybe meanwhile some traffic arrives
                self.stop_event.wait(2)


# Class that send the packet directed to the DPI, on a local interface define with the constant LOCAL_DPI_INTERFACE
class _ThreadSendPacketLocal(_ThreadSendPacketAbstract):
    def run(self):
        while not self.stop_event.is_set():
            try:
                #print "Dimensione coda: " + str(self._pktQueueDPI._queue.qsize())
                packet = self._pktQueueDPI._queue.get(False)
            except Queue.Empty:
                # When the queue is empty, wait 2 second, maybe meanwhile some traffic arrives
                self.stop_event.wait(2)
            else:
                sendp(packet, iface=LOCAL_DPI_INTERFACE)


class PacketQueueDPI:
    def __init__(self):
        self._queue = Queue.Queue()
        self.threadSendPacket = None

    def addPacket(self, packet):
        self._queue.put(packet)

    def stopSendingPacket(self):
        self.threadSendPacket.stop_event.set()

    def startSendingPacket(self):
        if self.threadSendPacket is None or self.threadSendPacket.stop_event.is_set():
            print "Starting Thread to send packet to the DPI!"
            if LOCAL_DPI == 1:
                self.threadSendPacket = _ThreadSendPacketLocal(self)
            elif FAKE_DPI == 1:
                self.threadSendPacket = _ThreadSendPacketFake(self)
            else:
                # No constants, fake dpi is default
                print "NO constant on where the DPI is located! FAKE is default!"
                self.threadSendPacket = _ThreadSendPacketFake(self)
            self.threadSendPacket.start()
        else:
            print "Thread to send packet to the DPI already started"
