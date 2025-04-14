

Default_Source_Address = "127.0.0.1"
Default_Destination_Address = "127.0.0.1"

# Takes free port which was open for the connection from the source computer 
Default_Source_Port = 12345
Default_Destination_Port = 12345

Default_Port_Range = [0,1000]

# TODO default based on system values


import netifaces as ni
iface = 'en0'  # replace with your actual interface name; TODO may have to get this from system also
Default_Source_MAC_Address = ni.ifaddresses(iface)[ni.AF_LINK][0]['addr']

Default_Destination_MAC_Address = Default_Source_Address



Default_Ether_Type = 0x0800

Default_TCP_Payload = None