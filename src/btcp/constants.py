"""
TIMER_TICK:
    timer tick in milliseconds; how much time is allowed to pass with no
    segment arriving before the network thread calls lossy_layer_tick of the
    associated socket.

    Feel free to alter as needed, but should probably stay > 10ms to avoid
    excessive resource use.
"""
TIMER_TICK = 100

"""
CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT:
    Constants used in the lossy_layer code to define the connection. bTCP as
    implemented here does not offer multiplexing or selection of destination
    host. Only alter these if you are running into issues on the default ports
    and addresses, probably should consult with a student assistant before
    doing so.
"""
CLIENT_IP = 'localhost'
CLIENT_PORT = 20000
SERVER_IP = 'localhost'
SERVER_PORT = 30000

"""
HEADER_SIZE, PAYLOAD_SIZE, SEGMENT_SIZE:
    Predefined sizes, given in bytes. Only alter these if you are actually
    deviating from the assignment text.
"""
HEADER_SIZE = 10
PAYLOAD_SIZE = 1008
SEGMENT_SIZE = HEADER_SIZE + PAYLOAD_SIZE
