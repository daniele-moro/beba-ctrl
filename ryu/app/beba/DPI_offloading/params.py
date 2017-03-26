# CONFIGURATION PARAMETERS FILE
# Modifing these parameters you can modify
# - the position of the DPI with respect to the controller and the switch,
# - the location of the DPI when connected on a local port of the switch
# - the position of the DPI when is the controller that needs to forward traffic to
# - the switch configuration parameters such as type of switch (stateless or stateful),
#   number of packets to forward to the DPI


# -------------------- OUTPUT FILE PARAMETERS ------------------
CSV_FILE = "flow_table.csv"
CSV_FIRST_ROW = 'ip_src,ip_dst,tcp_src,tcp_dst,ts_start,ts_end,byte_up,byte_down,matching,pkts_up,pkts_down\n'
# ---------------------------------------------------------------

# ------------------- DPI PARAMETERS ---------------------------
NO_DPI = 0					# NO traffic forwarding to DPI
DPI_DIRECTLY_CONNECTED = 1	# DPI directly connected to one of the port of the switch
DPI_ON_CONTROLLER = 0		# DPI connected in some way to the controller

# if DPI_DIRECTLY_CONNECTED == 1 this parameter is needed
DPI_PORT = 2				# Port where the DPI is directly connected

# if DPI_ON_CONTROLLER == 1 this parameter is needed
LOCAL_DPI = 0				# DPI on a local port (on the same machine of the CONTROLLER) named LOCAL_DPI_INTERFACE
FAKE_DPI = 1				# DPI not present, packets are discarded

# if LOCAL_DPI == 1 this parameter is needed
LOCAL_DPI_INTERFACE = "lo"  # Local port on the controller machine where the DPI is listening
# ---------------------------------------------------------------


# --------------- SWITCH CONFIGURATION PARAMETERS ---------------
HOST_CLIENT_PORT = 1		# Port number of the CLIENT HOST (usually h1)
NAT_OR_HOST_SERVER_PORT = 3	# Port number of the SERVER or NAT HOST (usually h3)

LOCAL_FORWARDING = 1		# You can disable the local forwarding, useful when you use TCPREPLAY on the Client host

# CLIENT = host that sends SYN, SERVER = host that replies with SYN-ACK
# CTS = Client To Server
# STC = Server To Client
PKT_TO_DPI_CTS = 10			# Number of packets to forward to the DPI on the direction CLIENT->SERVER
PKT_TO_DPI_STC = 10			# Number of packets to forward to the DPI on the direction SERVER->CLIENT

STATELESS = 0				# Parameter to configure as STATELESS the switch
# ---------------------------------------------------------------
