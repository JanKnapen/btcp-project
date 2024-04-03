#!/usr/bin/env python3
#
# Some unit tests to help you hone aspects your BTCP implementation.
#
# The real test of your implementation is the "allbad_network_large" 'integration test'
# in testframework.py, but if that one fails it can be hard to find the cause, due to
# the random nature of the network simulation.
#
# These unit tests are more artificial, but should be easier to get running.  If you think
# there's a bug in one of the tests (that is, the tests fails, but you think your code is
# correct, please drop me an email, awesterb at cs.ru.nl.)
#
# The unit tests are roughly ordered by difficulty indicated by a number 00-99.
# Getting all tests working up to difficulty 50 is considered decent.
#
# We'll be adding more test during the course of the semester, so please keep an eye
# on Brightspace.

import unittest
import multiprocessing
import logging
import btcp.server_socket
import btcp.client_socket
import queue
import contextlib
import threading
import select
import time
import queue
import sys
import os

DEFAULT_WINDOW = 10 
DEFAULT_TIMEOUT = 2_000 # ms
DEFAULT_LOGLEVEL = 'WARNING'

logger = logging.getLogger(os.path.basename(__file__)) # we don't want __main__

class T(unittest.TestCase):
    def test_10_connect(self): 
        barrier = multiprocessing.Barrier(2)
        self.assertTrue(run_in_separate_processes((barrier,), 
                                                  T._connect_client, 
                                                  T._connect_server))
    @staticmethod
    def _connect_client(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        barrier.wait()

    @staticmethod
    def _connect_server(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        barrier.wait()

    def test_11_hello_world(self): 
        barrier = multiprocessing.Barrier(2)
        self.assertTrue(run_in_separate_processes((barrier,), 
                                                  T._hello_world_client, 
                                                  T._hello_world_server))
    @staticmethod
    def _hello_world_client(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        c.send(b"Hello world!")
        barrier.wait()

    @staticmethod
    def _hello_world_server(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        rh = RecvHelper(s)
        rh.expect(b"Hello world!")
        barrier.wait()

    def test_20_also_close(self): 
        self.assertTrue(run_in_separate_processes((), 
                                                  T._also_close_client, 
                                                  T._also_close_server))
        # no barrier here -shutdown should make sure its final acks are sent

    @staticmethod
    def _also_close_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        c.send(b"Hello world!")
        c.shutdown()

    @staticmethod
    def _also_close_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        RecvHelper(s).expect_closed(b"Hello world!")

    def test_21_duplication(self): 
        self.assertTrue(run_in_separate_processes((), 
                                                  T._duplication_client, 
                                                  T._duplication_server, timeout=5))
    @staticmethod
    def _duplication_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        with c._lossy_layer.effect(Duplication):
            c.connect()
            c.send(b"Hello world!")
            c.shutdown()

    @staticmethod
    def _duplication_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        RecvHelper(s).expect_closed(b"Hello world!")

    def test_22_corrupted_duplicates(self): 
        # Sends a duplicate with bitflips first 
        #  - should be caught by properly implemented checksums
        # It's easier to deal with this than normal bitflips, as retransmission is not required.
        self.assertTrue(run_in_separate_processes((), 
                                                  T._corrupted_duplicates_client, 
                                                  T._corrupted_duplicates_server, timeout=5))
    @staticmethod
    def _corrupted_duplicates_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        c.send(b"Hello world!")
        c.shutdown()

    @staticmethod
    def _corrupted_duplicates_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        with s._lossy_layer.effect(Duplication, first_effect=CorruptReceivedData):
            s.accept()
            RecvHelper(s).expect(b"Hello world!")
    
    def test_30_reordering(self): 
        # If this one fails, you might not be keeping track of sequence numbers correctly
        self.assertTrue(run_in_separate_processes((), 
                                                  T._reordering_client, 
                                                  T._reordering_server, timeout=5))
    @staticmethod
    def _reordering_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        c.send(b"Hello world 1!")
        c.send(b"Hello world 2!")
        c.shutdown()

    @staticmethod
    def _reordering_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        rh = RecvHelper(s)
        with s._lossy_layer.effect(ReorderReceived):
            rh.expect(b"Hello world 1!")
            rh.expect(b"Hello world 2!")
        rh.expect_closed()

    def test_60_drop_every_other(self): 
        # In this test the server only gets retransmissions from the client after
        # a connection has been established
        self.assertTrue(run_in_separate_processes((), 
                                                  T._drop_every_other_client, 
                                                  T._drop_every_other_server, timeout=10))

    @staticmethod
    def _drop_every_other_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        for i in range(2):
            c.send(f"Hello world {i}!".encode())
        c.shutdown()

    @staticmethod
    def _drop_every_other_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        rh = RecvHelper(s)
        s.accept()
        with s._lossy_layer.effect(DropSecondReceived):
            for i in range(2):
                rh.expect(f"Hello world {i}!".encode())
        rh.expect_closed()

    def test_70_drop_every_other_ack(self): 
        # In this test the client only gets retransmissions from the server
        # once a connection has been established
        self.assertTrue(run_in_separate_processes((), 
                                                  T._drop_every_other_ack_client, 
                                                  T._drop_every_other_ack_server, timeout=10))

    @staticmethod
    def _drop_every_other_ack_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        with c._lossy_layer.effect(DropSecondReceived):
            for i in range(3):
                c.send(f"Hello world {i}!".encode())
            c.shutdown()

    @staticmethod
    def _drop_every_other_ack_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        rh = RecvHelper(s)
        s.accept()
        for i in range(3):
            rh.expect(f"Hello world {i}!".encode())
        rh.expect_closed()


    def test_80_drop_every_other_always(self): 
        # In this test both client and server only get retransmissions,
        # including the segments from the handshakes.
        #
        # The barrier is needed here because the server might wait for an ACK on its FIN&ACK,
        # which the client can't give if its process has exited.
        self.assertTrue(run_in_separate_processes((), 
                                                  T._drop_every_other_always_client, 
                                                  T._drop_every_other_always_server, timeout=10))

    @staticmethod
    def _drop_every_other_always_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        with c._lossy_layer.effect(DropSecondReceived):
            c.connect()
            for i in range(3):
                c.send(f"Hello world {i}!".encode())
            c.shutdown()

    @staticmethod
    def _drop_every_other_always_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        rh = RecvHelper(s)
        with s._lossy_layer.effect(DropSecondReceived):
            s.accept()
            for i in range(3):
                rh.expect(f"Hello world {i}!".encode())
            rh.expect_closed()


    def test_90_reconnect(self): 
        self.assertTrue(run_in_separate_processes((), 
                                                  T._reconnect_client, 
                                                  T._reconnect_server, timeout=10))
    @staticmethod
    def _reconnect_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        c.send(b"Hello world!")
        c.shutdown()
        c.connect()
        c.send(b"Hello world, again!")
        c.shutdown()

    @staticmethod
    def _reconnect_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        rh = RecvHelper(s)
        s.accept()
        rh.expect_closed(b"Hello world!")
        s.accept()
        rh.expect_closed(b"Hello world, again!")

    def test_91_old_segments(self): 
        # this tests replays some messages from a previous connection,
        # which should only cause you trouble when you don't use random initial sequence numbers
        barrier = multiprocessing.Barrier(2)
        self.assertTrue(run_in_separate_processes((barrier,), 
                                                  T._old_segments_client, 
                                                  T._old_segments_server, timeout=10))
   
    @staticmethod
    def _old_segments_client(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        with c._lossy_layer.effect(Record) as recorder:
            c.send(b"Hello world!")
            c.shutdown()
        c.connect()
        barrier.wait() # wait for connection to start replaying recording
        with c._lossy_layer.effect(Replay, recorder) as replay:
            c.send(b"Hello world, again!")
            replay.wait()
        c.shutdown()

    @staticmethod
    def _old_segments_server(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        rh = RecvHelper(s)
        rh.expect(b"Hello world!")
        rh.expect_closed()
        s.accept()
        barrier.wait()
        rh.expect_closed(b"Hello world, again!")




class Identity(btcp.lossy_layer.BasicHandler):
    """Handler creator that does nothing in particular"""
    pass

class RecvHelper:
    """Helper to receive the desired number of bytes from a BTCP socket."""
    def __init__(self, btcp_socket):
        self._btcp_socket = btcp_socket
        self._buffered = b""

    def _pop_buffered(self):
        res, self._buffered = self._buffered, b""
        return res

    def recv_exactly(self, length):
        """Blocks until we have received `length` bytes, and returns these bytes.

        Only returns less if the BTCP connection is closed, which the BTCP socket
        indicated by having recv() return b"" """
        buf = self._pop_buffered()
        while len(buf) < length:
            extra = self._btcp_socket.recv()
            if extra == b"":
                return buf 
            buf += extra
        res,self._buffered = buf[:length],buf[length:]
        return res

    def expect(self, data):
        result = self.recv_exactly(len(data))
        if data != result:
            raise AssertionError(f"expected to receive {repr(data)}, but got {repr(result)}")

    def expect_closed(self, data=None):
        if data!=None:
            self.expect(data)
        result = self._btcp_socket.recv()
        if result != b"":
            raise AssertionError(f"expected the BTCP socket to be closed, but recv() returned {repr(result)} instead of b\"\"")
            

class CorruptReceivedData(btcp.lossy_layer.BasicHandler):
    """Handler that replaces all received segments' data by "check checksum!" """
    def __init__(self, old_handler):
        super().__init__(old_handler)

    def segment_received(self, segment):
        segment = bytearray(segment)
        check_checksum = b"check checksum! "
        for i in range(btcp.constants.HEADER_SIZE, 
                       btcp.constants.SEGMENT_SIZE):
            segment[i] = check_checksum[i % len(check_checksum)]
        self._old_handler.segment_received(bytes(segment))


class Duplication(btcp.lossy_layer.BasicHandler):
    """Handler that duplicates every outgoing and incoming segment.

    An effect can be applied to the first and second instances of each such segment
    using the `first_effect` and `second_effect` arguments.

    Ticks are only sent through the first_effect handler."""
    def __init__(self, old_handler, first_effect=Identity, second_effect=Identity):
        super().__init__(old_handler)
        self._first_handler = first_effect(old_handler)
        self._second_handler = second_effect(old_handler)
    
    def send_segment(self, segment):
        self._first_handler.send_segment(segment)
        self._second_handler.send_segment(segment)

    def segment_received(self, segment):
        self._first_handler.segment_received(segment)
        self._second_handler.segment_received(segment)

    def tick(self):
        self._first_handler.tick()


class ReorderReceived(btcp.lossy_layer.BasicHandler):
    """Handler that swaps consecutive packets. """
    def __init__(self, old_handler, max_holding_ticks=2):
        super().__init__(old_handler)
        self._held_segment = None
        self._ticks_left = None
        self._max_holding_ticks = max_holding_ticks

    def segment_received(self, segment):
        if self._held_segment:
            self._old_handler.segment_received(segment)
            self._release_held_segment()
        self._held_segment = segment
        self._ticks_left = self._max_holding_ticks

    def tick(self):
        self._old_handler.tick()
        if self._ticks_left == None:
            return
        self._ticks_left -= 1
        if self._ticks_left <= 0:
            self._release_held_segment()

    def _release_held_segment(self):
        assert(self._held_segment != None)
        self._old_handler.segment_received(self._held_segment)
        self._held_segment = None
        self._ticks_left = None

class DropSecondReceived(btcp.lossy_layer.BasicHandler):
    """Handler that drops every other appearance of the same sequence number in received segments"""
    def __init__(self, old_handler):
        super().__init__(old_handler)
        self._seen = set()

    def segment_received(self, segment):
        if segment[0:2] in self._seen:
            logger.debug(f"not dropping segment with seqnr 0x{segment[0:2].hex()}")
            self._old_handler.segment_received(segment)
            self._seen.remove(segment[0:2])
            return
        logger.debug(f"dropping segment with seqnr 0x{segment[0:2].hex()}")
        self._seen.add(segment[0:2])

class Record(btcp.lossy_layer.BasicHandler):
    """Handler that records segments"""
    def __init__(self, old_handler):
        super().__init__(old_handler)
        self._sent_segments = []
        self._received_segments = []
        self._t0 = time.time()

    def t(self):
        return time.time()-self._t0

    def send_segment(self, segment):
        self._sent_segments.append((self.t(), segment))
        logger.debug(f"recorded sent segment with seqnr 0x{segment[0:2].hex()}")
        self._old_handler.send_segment(segment)

    def segment_received(self, segment):
        self._received_segments.append((self.t(), segment))
        logger.debug(f"recorded received segment with seqnr 0x{segment[0:2].hex()}")
        self._old_handler.segment_received(segment)

class Replay(btcp.lossy_layer.BasicHandler):
    """Handler that replays a recording"""
    def __init__(self, old_handler, recording):
        super().__init__(old_handler)
        self._sent_segments = list(reversed(recording._sent_segments))
        self._received_segments = list(reversed(recording._received_segments))
        logger.debug(f"replaying {len(self._sent_segments)} sent and {len(self._received_segments)} received segments")
        self._t0 = time.time()
        self._done = threading.Event()

    def t(self):
        return time.time()-self._t0

    def tick(self):
        t = self.t()
        while self._received_segments and self._received_segments[-1][0] < t:
            _, segment = self._received_segments.pop()
            logger.debug(f"replaying received segment with seqnr 0x{segment[0:2].hex()}")
            self._old_handler.segment_received(segment)
        while self._sent_segments and self._sent_segments[-1][0] < t:
            _, segment = self._sent_segments.pop()
            logger.debug(f"replaying sent segment with seqnr 0x{segment[0:2].hex()}")
            self._old_handler.send_segment(segment)
        if not (self._sent_segments or self._received_segments):
            self._done.set()
        self._old_handler.tick()

    def wait(self):
        """Waits until all segments have been replayed"""
        self._done.wait()
        


def run_in_separate_processes(args, *targets, timeout=5):
    """ Run the given functions with args in separate processes and terminates them if they haven't finished within `timeout` seconds.  We use separate processes instead of threads, because threads cannot be aborted. Returns True if all the processes exited without exception or timeout. """

    # queue via which the processes signal their completion
    q = multiprocessing.Queue(len(targets))

    processes_left = len(targets)

    processes = list([ multiprocessing.Process(
        target=run_process, 
        args=(target, q, idx, logger.getEffectiveLevel())+args, 
        name=f"{repr(target.__name__)}"
    ) for (idx,target) in enumerate(targets)])

    for process in processes:
        process.start()

    deadline = time.time() + timeout

    while processes_left > 0:
        eta = deadline - time.time()
        if eta < 0:
            break # get didn't time out, but we ran out of time nonetheless
        logger.info(f"waiting for a process to finish for {eta:.3f} seconds")
        try:
            (idx, success) = q.get(True, eta)
        except queue.Empty:
            # timeout
            logger.error("""

        T I M E O U T

    Woops, it looks like your code hangs. 

    Check below whether the client, server, or both timed out.

""")
            for process in processes:
                if process.is_alive():
                    logger.error(f"Process {process.name} ({process.pid}) timed out")
            break

        process = processes[idx]
        process.join()
        processes_left -= 1
        if not success:
            logger.error(f"""

        C R A S H

    Woops, process {process.name} ({process.pid}) crashed.

    Check the traceback and error message above.

""")
            break
        logger.info(f"Process {process.name} ({process.pid}) completed gracefully")
    else:
        return True # while loop ended without break - all processes joined before deadline

    for process in processes:
        if process.is_alive():
            logger.warning(f"  terminating process {process.name} ({process.pid})...")
            process.terminate()
    for process in processes:
        if process.is_alive():
            logger.warning(f"  waiting for process {process.name} ({process.pid}) exitcode={process.exitcode} to join...")
            process.join()
            logger.warning(f"    process {process.name} ({process.pid}) exited with code {process.exitcode}")
        else:
            logger.warning(f"  process {process.name} ({process.pid}) has already exited wih code {process.exitcode}")
    return False

def run_process(func, queue, idx, loglevel, *args):
    configure_logger(loglevel) # logger configuration is not shared between processes
    success = False
    try:
        func(*args)
        success = True
    finally:
        queue.put_nowait((idx, success))

def configure_logger(loglevel):
    # must be run for each process separately
    logging.basicConfig(level=loglevel,
            format="%(asctime)s:%(name)s:%(levelname)s:%(message)s")

if __name__ == "__main__":
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description=f"""bTCP unit tests
        
Please also have a look at the Python unittest module options:

  {os.path.basename(__file__)} -- -h

""", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-l", "--loglevel",
                        choices=["DEBUG", "INFO", "WARNING",
                                 "ERROR", "CRITICAL"],
                        help="Log level "
                             "for the python built-in logging module. ",
                        default=DEFAULT_LOGLEVEL)
    args, extra = parser.parse_known_args()

    if extra and extra[0] == '--':
        del extra[0]
    # We do this so that:
    #   python3 unittests.py -h     # prints help for BTCP unittests module
    #   python3 unittests.py -- -h  # prints usage for Python unittest module 

    if args.loglevel == DEFAULT_LOGLEVEL:
        print(f"""NB:  Using default {DEFAULT_LOGLEVEL} loglevel; if you need more details, use:

  python3 {os.path.basename(__file__)} -l DEBUG

""")

    configure_logger(getattr(logging, args.loglevel.upper()))

    # Pass the extra arguments to unittest
    sys.argv[1:] = extra

    # Start test suite
    unittest.main()
