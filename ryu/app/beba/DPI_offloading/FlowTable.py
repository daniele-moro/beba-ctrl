import threading
import Queue
from params import CSV_FILE, CSV_FIRST_ROW
import csv
import os.path


class FlowTable:
    def __init__(self):
        self._flow_table = dict()
        self.lock = threading.Lock()
        self.queue = Queue.Queue()  # Used to decouple the _flow_table used by Ryu thread
                                    # with the thread used to write on the csv File
        self.threadFlushTable = None

    def addFlow(self, ip_src, ip_dst, tcp_src, tcp_dst, flow_data_variable):
        self.lock.acquire()
        try:
            print "Add element to flow table!!!!!!!!!!!"
            pkts_up = 0
            pkts_down = 0
            # Flow on the other direction-->SWAP src with dst
            if (flow_data_variable[4] == 0):
                pkts_down = flow_data_variable[0]
                #print "SWAP!"
                temp = ip_src
                ip_src = ip_dst
                ip_dst = temp
                temp = tcp_src
                tcp_src = tcp_dst
                tcp_dst = temp
            else:
                pkts_up = flow_data_variable[0]

            #Convert IP tuple to String
            str_ip_src = str(ip_src[0]) + "." + str(ip_src[1]) + "." + str(ip_src[2]) + "." + str(ip_src[3])
            str_ip_dst = str(ip_dst[0]) + "." + str(ip_dst[1]) + "." + str(ip_dst[2]) + "." + str(ip_dst[3])

            tuple = self._flow_table.get((str_ip_src, str_ip_dst, tcp_src, tcp_dst),
                                         [0, 0, 0, 0, 0, 0, 0])  # (start, end, byte UP, byte DOWN, n match)
            if (tuple[0] == 0 or tuple[0] > flow_data_variable[1]):
                tuple[0] = flow_data_variable[1]
            if (tuple[1] < flow_data_variable[2]):
                tuple[1] = flow_data_variable[2]
            if (flow_data_variable[4] == 0):
                tuple[3] = flow_data_variable[3]
            else:
                tuple[2] = flow_data_variable[3]
            tuple[4] += 1

            if tuple[5] == 0:
                tuple[5] = pkts_up
            if tuple[6] == 0:
                tuple[6] = pkts_down
            # Check if I have the information of both the direction of the flow
            if (tuple[4] == 2):
                #print "-----------------------------------Putting element in the queue!-------------------------------------------"
                # Here I have to remove the entry from the dictionary and put it on the queue to print to the file
                self.queue.put((str_ip_src, str_ip_dst, tcp_src, tcp_dst,
                                tuple[0], tuple[1], tuple[2], tuple[3], tuple[4], tuple[5], tuple[6]))
                del self._flow_table[(str_ip_src, str_ip_dst, tcp_src, tcp_dst)]
            else:
                self._flow_table.update({(str_ip_src, str_ip_dst, tcp_src, tcp_dst): tuple})
        except:
            import traceback; traceback.print_exc()
        finally:
            self.lock.release()

    def _writeQueueToCsv(self):
        #print "Flushing the queue to the csv file!!!!"

        filePresent = os.path.isfile(CSV_FILE)

        with open(CSV_FILE, 'a') as csvfile:
            if not filePresent:
                csvfile.write(CSV_FIRST_ROW)
            csvwriter = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_NONNUMERIC)
            while True:
                try:
                    elem = self.queue.get(False)
                    #print "Element found in the queue, writing"
                except Queue.Empty:
                    #print "Queue Empty!"
                    break
                else:
                    #print "Element found in the queue, writing"
                    csvwriter.writerow(elem)

    # Start the thread to make the flushing of the queue into the CSV file
    def startFlush(self):
        if self.threadFlushTable is None or self.threadFlushTable.stop_event.is_set():
            self.threadFlushTable = _ThreadFlushTable(self)
            self.threadFlushTable.start()

    # Stop the thread that make the flushing of the queue into the CSV file
    def stopFlush(self):
        self.threadFlushTable.stop_event.set()


# Thread to make a timeout system to flush the queue to the csv file
class _ThreadFlushTable(threading.Thread):
    def __init__(self, flowTableObj):
        threading.Thread.__init__(self)
        self.daemon = True
        self.stop_event = threading.Event()
        self.flowTableObj = flowTableObj

    def run(self):
        while not self.stop_event.wait(10):
            # Here I simply call the _writeQueueToCsv to write on the csv file
            self.flowTableObj._writeQueueToCsv()
