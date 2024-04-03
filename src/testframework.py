#!/usr/bin/env python3

import unittest
import filecmp
import threading
import time
import signal
import sys

"""This exposes a constant bytes object called TEST_BYTES_85MIB which, as the
name suggests, is a little over 85 MiB in size. You can send it, receive it,
and check it for equality on the receiving end.

Pycharm may complain about an unresolved reference. This is a lie. It simply
cannot deal with a python source file this large so it cannot resolve the
reference. Python itself will run it fine, though.

You can also use the file large_input.py as-is for file transfer.
"""
from large_input import TEST_BYTES_85MIB
from small_input import TEST_BYTES_72KIB


SMALL_INPUTFILE = "small_input.py"
LARGE_INPUTFILE = "large_input.py"
OUTPUTFILE = "testframework-output.file"
TIMEOUT = 100
WINSIZE = 100
LOGLEVEL = "WARNING"
INTF = "lo"
NETEM_ADD     = "sudo tc qdisc add dev {} root netem".format(INTF)
NETEM_CHANGE  = "sudo tc qdisc change dev {} root netem {}".format(INTF, "{}")
NETEM_DEL     = "sudo tc qdisc del dev {} root netem".format(INTF)
NETEM_CORRUPT = "corrupt 1%"
NETEM_DUP     = "duplicate 10%"
NETEM_LOSS    = "loss 10% 25%"
NETEM_REORDER = "delay 20ms reorder 25% 50%"
NETEM_DELAY   = "delay " + str(TIMEOUT) + "ms 20ms"
NETEM_ALL     = "{} {} {} {}".format(NETEM_CORRUPT, NETEM_DUP, NETEM_LOSS, NETEM_REORDER)


def run_command_with_output(command, input=None, cwd=None, shell=True, timeout=None, termination_func=None):
    """run command and retrieve output"""
    import subprocess
    process = None
    try:
        process = subprocess.Popen(command, cwd=cwd, shell=shell, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        print("\nProcess started:", file=sys.stderr)
        print(str(command), file=sys.stderr)
    except Exception as e:
        print("problem running command : \n   ", str(command), "\n problem: ", str(e), file=sys.stderr)
    else:
        while True:
            try:
                [stdoutdata, stderrdata] = process.communicate(input, timeout)  # no pipes set for stdin/stdout/stdout streams so does effectively only just wait for process ends  (same as process.wait()
            except subprocess.TimeoutExpired:
                print("\nChecking whether process needs to be terminated:\n", str(command), file=sys.stderr)
                if termination_func is not None and termination_func():
                    print("Terminate. Sending to process.", file=sys.stderr)
                    process.terminate()
                else:
                    print("Not terminating yet.", file=sys.stderr)
            else:
                print("Command ", str(command), " finished.", file=sys.stderr)
                break

    if process and process.returncode:
        print(stderrdata, file=sys.stderr)
        print("\nproblem running command : \n   ", str(command), "\n return value: ", process.returncode, file=sys.stderr)

    return stdoutdata


def run_command(command,cwd=None, shell=True):
    """run command with no output piping"""
    import subprocess
    process = None
    try:
        process = subprocess.Popen(command, shell=shell, cwd=cwd)
        print("\nProcess started:", file=sys.stderr)
        print(str(process), file=sys.stderr)
    except Exception as e:
        print("problem running command : \n   ", str(command), "\n problem: ", str(e), file=sys.stderr)
    else:
        process.communicate()  # wait for the process to end

    if process and process.returncode:
        print("problem running command : \n   ", str(command), "\n return value: ", process.returncode, file=sys.stderr)


class TestbTCPFramework(unittest.TestCase):
    """Test cases for bTCP"""

    def setUp(self):
        """Setup before each test

        This is an example test setup that uses the client and server process
        to test your application. Feel free to use a different test setup.
        """
        print("\n\n\n\n\n\n\nSETTING UP TEST ENVIRONMENT\n", file=sys.stderr)
        # ensure we can initialize a clean netem
        print("\nCLEANING NETEM IF PRESENT. ERROR IS NOT A PROBLEM.\n", file=sys.stderr)
        run_command(NETEM_DEL)
        # default netem rule (does nothing)
        print("\nSETTING UP NEW NETEM\n", file=sys.stderr)
        run_command(NETEM_ADD)

        # Clearing out output file.
        with open(OUTPUTFILE, 'w'):
            print("\nCLEARED OUTPUTFILE\n", file=sys.stderr)
        # launch localhost server
        print("\nLAUNCHING SERVER THREAD\n", file=sys.stderr)
        self._server_terminate = threading.Event()
        self._server_thread = threading.Thread(target=run_command_with_output,
                                               args=("python3 server_app.py -w {} -t {} -o {} -l {}".format(WINSIZE, TIMEOUT, OUTPUTFILE, LOGLEVEL),),
                                               kwargs={"timeout" : 20,
                                                       "termination_func" : self._server_terminate.is_set})
        self._server_thread.start()
        print("\nTEST SETUP COMPLETE\n", file=sys.stderr)


    def tearDown(self):
        """Clean up after every test

        This is an example test setup that uses the client and server process
        to test your application. Feel free to use a different test setup.
        """
        print("\nTEARING DOWN TEST ENVIRONMENT\n", file=sys.stderr)
        # clean the environment
        run_command(NETEM_DEL)


    def joinServer(self):
        # close server
        # no actual work to do for this for our given implementation:
        # run_command_with_output terminates once the application it runs
        # terminates; so the thread should terminate by itself after the client
        # application disconnects from the server. All we do is a simple check
        # to see whether the server actually terminates, and wait for it to
        # terminate to ensure it's finished writing its file.
        print("\nJOINING SERVER THREAD\n", file=sys.stderr)
        self._server_thread.join(timeout=15)
        while self._server_thread.is_alive():
            print("Something is keeping your server process alive. This may indicate a problem with shutting down.", file=sys.stderr)
            self._server_terminate.set()
            self._server_thread.join(timeout=15)
        self._server_terminate = None


    def runclient_and_assert(self, infile):
        # launch localhost client connecting to server
        run_command_with_output("python3 client_app.py -w {} -t {} -i {} -l {}".format(WINSIZE, TIMEOUT, infile, LOGLEVEL),
                                timeout=15,
                                termination_func=lambda: not self._server_thread.is_alive())
        # client sends content to server
        # server receives content from client
        self.joinServer()
        # content received by server matches the content sent by client
        assert filecmp.cmp(infile, OUTPUTFILE)


    def test_1_1_ideal_network_small(self):
        """reliability over an ideal network

        This is an example testcase that uses the client and server process
        to test your application. Feel free to use a different test setup.
        """
        print("\ntest_1_1_ideal_network_small\n", file=sys.stderr)
        print("\nSTARTING TEST: IDEAL NETWORK SMALL\n", file=sys.stderr)
        self._ideal_network(SMALL_INPUTFILE)
        print("\nFINISHED TEST: IDEAL NETWORK SMALL\n", file=sys.stderr)


    def test_1_2_ideal_network_large(self):
        """reliability over an ideal network

        This is an example testcase that uses the client and server process
        to test your application. Feel free to use a different test setup.
        """
        print("\ntest_1_2_ideal_network_large\n", file=sys.stderr)
        print("\nSTARTING TEST: IDEAL NETWORK LARGE\n", file=sys.stderr)
        self._ideal_network(LARGE_INPUTFILE)
        print("\nFINISHED TEST: IDEAL NETWORK LARGE\n", file=sys.stderr)


    def _ideal_network(self, infile):
        # setup environment (nothing to set)
        self.runclient_and_assert(infile)


    def test_2_1_flipping_network_small(self):
        """reliability over network with bit flips
        (which sometimes results in lower layer packet loss)"""
        print("\ntest_2_1_flipping_network_small\n", file=sys.stderr)
        print("\nSTARTING TEST: BITFLIPPING NETWORK SMALL\n", file=sys.stderr)
        self._flipping_network(SMALL_INPUTFILE)
        print("\nFINISHED TEST: BITFLIPPING NETWORK SMALL\n", file=sys.stderr)


    def __test_2_2_flipping_network_large(self):
        """reliability over network with bit flips
        (which sometimes results in lower layer packet loss)"""
        print("\ntest_2_2_flipping_network_large\n", file=sys.stderr)
        print("\nSTARTING TEST: BITFLIPPING NETWORK LARGE\n", file=sys.stderr)
        self._flipping_network(LARGE_INPUTFILE)
        print("\nFINISHED TEST: BITFLIPPING NETWORK LARGE\n", file=sys.stderr)


    def _flipping_network(self, infile):
        # setup environment
        run_command(NETEM_CHANGE.format(NETEM_CORRUPT))
        self.runclient_and_assert(infile)


    def test_3_1_duplicates_network_small(self):
        """reliability over network with duplicate packets"""
        print("\ntest_3_1_duplicates_network_small\n", file=sys.stderr)
        print("\nSTARTING TEST: DUPLICATING NETWORK SMALL\n", file=sys.stderr)
        self._duplicates_network(SMALL_INPUTFILE)
        print("\nFINISHED TEST: DUPLICATING NETWORK SMALL\n", file=sys.stderr)


    def __test_3_2_duplicates_network_large(self):
        """reliability over network with duplicate packets"""
        print("\ntest_3_2_duplicates_network_large\n", file=sys.stderr)
        print("\nSTARTING TEST: DUPLICATING NETWORK LARGE\n", file=sys.stderr)
        self._duplicates_network(LARGE_INPUTFILE)
        print("\nFINISHED TEST: DUPLICATING NETWORK LARGE\n", file=sys.stderr)


    def _duplicates_network(self, infile):
        # setup environment
        run_command(NETEM_CHANGE.format(NETEM_DUP))
        self.runclient_and_assert(infile)


    def test_4_1_lossy_network_small(self):
        """reliability over network with packet loss"""
        print("\ntest_4_1_lossy_network_small\n", file=sys.stderr)
        print("\nSTARTING TEST: LOSSY NETWORK SMALL\n", file=sys.stderr)
        self._lossy_network(SMALL_INPUTFILE)
        print("\nFINISHED TEST: LOSSY NETWORK\n", file=sys.stderr)


    def __test_4_2_lossy_network_large(self):
        """reliability over network with packet loss"""
        print("\ntest_4_2_lossy_network_large\n", file=sys.stderr)
        print("\nSTARTING TEST: LOSSY NETWORK LARGE\n", file=sys.stderr)
        self._lossy_network(LARGE_INPUTFILE)
        print("\nFINISHED TEST: LOSSY NETWORK\n", file=sys.stderr)


    def _lossy_network(self, infile):
        # setup environment
        run_command(NETEM_CHANGE.format(NETEM_LOSS))
        self.runclient_and_assert(infile)


    def test_5_1_reordering_network_small(self):
        """reliability over network with packet reordering"""
        print("\ntest_5_1_reordering_network_small\n", file=sys.stderr)
        print("\nSTARTING TEST: REORDERING NETWORK SMALL\n", file=sys.stderr)
        self._reordering_network(SMALL_INPUTFILE)
        print("\nFINISHED TEST: REORDERING NETWORK SMALL\n", file=sys.stderr)


    def __test_5_2_reordering_network_large(self):
        """reliability over network with packet reordering"""
        print("\ntest_5_2_reordering_network_large\n", file=sys.stderr)
        print("\nSTARTING TEST: REORDERING NETWORK LARGE\n", file=sys.stderr)
        self._reordering_network(LARGE_INPUTFILE)
        print("\nFINISHED TEST: REORDERING NETWORK LARGE\n", file=sys.stderr)


    def _reordering_network(self, infile):
        # setup environment
        run_command(NETEM_CHANGE.format(NETEM_REORDER))
        self.runclient_and_assert(infile)


    def test_6_1_delayed_network_small(self):
        """reliability over network with delay relative to the timeout value"""
        print("\ntest_6_1_delayed_network_small\n", file=sys.stderr)
        print("\nSTARTING TEST: DELAYED NETWORK SMALL\n", file=sys.stderr)
        self._delayed_network(SMALL_INPUTFILE)
        print("\nFINISHED TEST: DELAYED NETWORK SMALL\n", file=sys.stderr)


    def __test_6_2_delayed_network_large(self):
        """reliability over network with delay relative to the timeout value"""
        print("\ntest_6_2_delayed_network_large\n", file=sys.stderr)
        print("\nSTARTING TEST: DELAYED NETWORK LARGE\n", file=sys.stderr)
        self._delayed_network(LARGE_INPUTFILE)
        print("\nFINISHED TEST: DELAYED NETWORK LARGE\n", file=sys.stderr)


    def _delayed_network(self, infile):
        # setup environment
        run_command(NETEM_CHANGE.format(NETEM_DELAY))
        self.runclient_and_assert(infile)


    def test_7_1_allbad_network_small(self):
        """reliability over network with all problems: corruption, duplication,
        delay, loss, reordering"""
        print("\ntest_7_1_allbad_network_small\n", file=sys.stderr)
        print("\nSTARTING TEST: ALL BAD NETWORK SMALL\n", file=sys.stderr)
        self._allbad_network(SMALL_INPUTFILE)
        print("\nFINISHED TEST: ALL BAD NETWORK SMALL\n", file=sys.stderr)


    def __test_7_2_allbad_network_large(self):
        """reliability over network with all problems: corruption, duplication,
        delay, loss, reordering"""
        print("\ntest_7_2_allbad_network_large\n", file=sys.stderr)
        print("\nSTARTING TEST: ALL BAD NETWORK LARGE\n", file=sys.stderr)
        self._allbad_network(LARGE_INPUTFILE)
        print("\nFINISHED TEST: ALL BAD NETWORK LARGE\n", file=sys.stderr)


    def _allbad_network(self, infile):
        # setup environment
        run_command(NETEM_CHANGE.format(NETEM_ALL))
        self.runclient_and_assert(infile)


#    def test_command(self):
#        #command=['dir','.']
#        out = run_command_with_output("dir .")
#        print(out)


if __name__ == "__main__":
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="bTCP tests")
    parser.add_argument("-w", "--window",
                        help="Define bTCP window size used",
                        type=int, default=100)
    parser.add_argument("-t", "--timeout",
                        help="Define the timeout value used (ms)",
                        type=int, default=TIMEOUT)
    args, extra = parser.parse_known_args()
    TIMEOUT = args.timeout
    WINSIZE = args.window

    # Pass the extra arguments to unittest
    sys.argv[1:] = extra

    # Start test suite
    unittest.main()
