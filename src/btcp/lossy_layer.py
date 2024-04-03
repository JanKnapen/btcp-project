"""
Students should NOT need to modify any code in this file!

However, do read the docstrings to understand what's going on.
"""


import socket
import select
import sys
import threading
import signal
import contextlib
from _thread import interrupt_main

import logging

from btcp.constants import *


logger = logging.getLogger(__name__)



class LossyLayer:
    """The lossy layer emulates the network layer in that it provides bTCP with
    an unreliable segment delivery service between a and b.

    When the lossy layer is created, a thread (the "network thread") is started
    that calls handle_incoming_segments. When the lossy layer is destroyed, it
    will signal that thread to end, join it, wait for it to terminate, then
    destroy its UDP socketet.

    Students should NOT need to modify any code in this class.
    """

    def handle_incoming_segments(self):
        """This is the main method of the "network thread".

        Continuously read from the socket and whenever a segment arrives,
        call the lossy_layer_segment_received method of the associated socket.

        If no segment is received for TIMER_TICK ms, call the lossy_layer_tick
        method of the associated socket.

        When flagged, return from the function. This is used by LossyLayer's
        destructor. Note that destruction will *not* attempt to receive or send any
        more data; after event gets set the method will send one final segment to
        the transport layer, or give one final tick if no segment is received in
        TIMER_TICK ms, then return.

        Students should NOT need to modify any code in this method.
        """
        btcp_socket, event, udp_socket = self._bTCP_socket, self._event, self._udp_socket

        logger.info("Starting handle_incoming_segments")
        while not event.is_set():
            try:
                # We do not block here, because we might never check the loop condition in that case
                rlist, wlist, elist = select.select([udp_socket], [], [], TIMER_TICK / 1000)
                if rlist:
                    segment, address = udp_socket.recvfrom(SEGMENT_SIZE)
                    
                    with self._handler_lock:
                        self._handler_stack[-1].segment_received(segment)

                    # We *assume* here that students aren't leaving multiple processes
                    # sending segments from different remote IPs and ports running.
                    # We *could* check the address for validity but then we'd have
                    # to resolve hostnames etc and honestly I don't see a pressing need
                    # for that.
                else:
                    with self._handler_lock:
                        self._handler_stack[-1].tick()
            except Exception as e:
                logger.exception("Exception in the network thread")
                signal.raise_signal(signal.SIGTERM)
                raise

    def __init__(self, btcp_socket, local_ip, local_port, remote_ip, remote_port):
        logger.info("LossyLayer.__init__() was called")
        self._bTCP_socket = btcp_socket
        self._remote_ip = remote_ip
        self._remote_port = remote_port

        self._handler_lock = threading.RLock() 
        # _handler_lock protects _handler_stack;  it's reentrant because BTCP implementations
        # are likely to sent a segment in response to one received
        self._handler_stack = [BottomHandler(self)]

        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Disable UDP checksum generation (and by extension, checking) s.t.
        # corrupt packets actually make it to the bTCP layer.
        # socket.SO_NO_CHECK is not defined in Python, so hardcode the value
        # from /usr/include/asm-generic/socket.h:#define SO_NO_CHECK  11.
        try: 
            self._udp_socket.setsockopt(socket.SOL_SOCKET, 11, 1)
        except OSError as err:
            logger.debug("Could not set SO_NO_CHECK - testframework.py might not create corrupted packages reliably!  (unittests.py should still work fine.) ")
        self._udp_socket.bind((local_ip, local_port))        

        self._event = threading.Event()
        self._thread = threading.Thread(target=self.handle_incoming_segments,
                                        daemon=True)
        logger.info("Starting network thread")
        self._thread.start()
        logger.info("Lossy layer initialized, listening on "
                    "local address %s & port %i, "
                    "remote address %s & port %i",
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port)


    def __del__(self):
        logger.info("LossyLayer.__del__() called.")
        self.destroy()
        logger.info("LossyLayer.__del__() finished.")


    def destroy(self):
        """Flag the thread that it can stop, wait for it to do so, then close
        the lossy segment delivery service's UDP socket.

        Should be safe to call multiple times, so safe to call from __del__.
        """
        logger.info("LossyLayer.destroy() called.")
        if self._event is not None and self._thread is not None:
            self._event.set()
            self._thread.join()
        if self._udp_socket is not None:
            self._udp_socket.close()
        self._event = None
        self._thread = None
        self._udp_socket = None
        logger.info("LossyLayer.destroy() finished.")


    def send_segment(self, segment):
        """Put the segment into the network

        Should be safe to call from either the application thread or the
        network thread.
        """
        logger.debug("Attempting to send segment:")
        with self._handler_lock:
            self._handler_stack[-1].send_segment(segment)

    def effect(self, handler_creator, *handler_args, **handler_kwargs):
        """Temporarily changes the behaviour of the lossy layer by adding
        a handler that has first dibs on incoming segments from the UDP socket,
        and outgoing segments from the BTCP socket.  These handlers are used to make the lossy
        layer unreliable by adding duplication, packet loss, etc..

        The handler_creator argument should be a function that takes the old 'first dibs' handler and
        creates the new handler from it (which should be returned by handler_creator). The handler_creator
        is also passed the `handler_args` and `handler_kwargs` for convenience.

        Handlers should be an object with three methods:  
            - send_segment(self, segment)
            - segment_received(self, segment)
            - tick(self)

        The tick method should always call the tick method on the old handler.

        A trivial handler would have the first two methods pass the segment to the corresponding method 
        on the old handler.

        These methods should not block;  if a segment is to be delayed, it should be temporarily stored
        in the handler object. The `tick` method can be used to trigger the actual sent.
        """
        return temporary_handler(self, handler_creator, *handler_args, **handler_kwargs)
 
@contextlib.contextmanager
def temporary_handler(lossy_layer, handler_creator, *args, **kwargs):
    with lossy_layer._handler_lock:
        old_handler = lossy_layer._handler_stack[-1]
        handler = handler_creator(old_handler, *args, **kwargs)
        lossy_layer._handler_stack.append(handler)
    try:
        yield handler
    finally:
        with lossy_layer._handler_lock:
            popped_handler = lossy_layer._handler_stack.pop()
            assert(handler == popped_handler)

class BasicHandler:
    """A default handler implementation that passes all segment to the old handler."""
    def __init__(self, old_handler):
        self._old_handler = old_handler

    def send_segment(self, segment):
        self._old_handler.send_segment(segment)

    def segment_received(self, segment):
        self._old_handler.segment_received(segment)

    def tick(self):
        self._old_handler.tick()

class BottomHandler:
    """The handler at the bottom of the handler stack that sends segments to and receives 
    segments from the UDP socket."""
    def __init__(self, lossy_layer):
        self._lossy_layer = lossy_layer

    def send_segment(self, segment):
        # we do not log here on purpose
        bytes_sent = self._lossy_layer._udp_socket.sendto(segment,
                                             (self._lossy_layer._remote_ip,
                                              self._lossy_layer._remote_port))
        if bytes_sent != len(segment):
            logger.critical("The lossy layer was only able to send %i bytes "
                            "of a segment!",
                            bytes_sent)

    def segment_received(self, segment):
        self._lossy_layer._bTCP_socket.lossy_layer_segment_received(segment)

    def tick(self):
        self._lossy_layer._bTCP_socket.lossy_layer_tick()

