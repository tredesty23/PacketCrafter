import socket
import sys
import re
import string
from bitstring import Bits, BitArray
import math
import random

# Regular expressions for IP
ipv4_regex = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)$')

# For later IPv6 implementation
# ipv6_regex = re.compile(r"""
# ^(  
#     # 1) Full 8 groups, like 2001:0db8:85a3:0000:0000:8a2e:0370:7334
#     (?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|

#     # 2) 7 groups + "::", e.g. 2001:db8:85a3::8a2e:370:7334
#     (?:[0-9A-Fa-f]{1,4}:){1,7}:|

#     # 3) "::" + 7 groups, e.g. ::ffff:c000:280
#     #    (or smaller sets, e.g. ::1)
#     :(?::[0-9A-Fa-f]{1,4}){1,7}|

#     # 4) Other mixed uses of "::"
#     (?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|
#     (?:[0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|
#     (?:[0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|
#     (?:[0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|
#     (?:[0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|
#     [0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6}|

#     # 5) Link-local + zone index, e.g. fe80::1234:5678%eth0
#     fe80:(:[0-9A-Fa-f]{0,4}){0,4}%[0-9A-Za-z]{1,}|

#     # 6) IPv4-mapped or embedded addresses, e.g. ::ffff:192.168.0.1
#     ::(ffff(:0{1,4}){0,1}:){0,1}
#       (?:(25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3,3}
#       (25[0-5]|2[0-4]\d|[01]?\d?\d)|

#     (?:[0-9A-Fa-f]{1,4}:){1,4}:
#       (?:(25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3,3}
#       (25[0-5]|2[0-4]\d|[01]?\d?\d)
# )$
# """, re.VERBOSE)

# Converts an IPv4 string (e.g. '192.168.1.1') to a 32-bit integer (e.g. 3232235777).
def ip_to_int(ip_str: str) -> int:
    import ipaddress

    return int(ipaddress.ip_address(ip_str))

# Used for checksum computation
def ones_complement_sum_16bit(bit_arr):
    data = bit_arr.tobytes()
    length = len(data)
    total = 0

    # Process 16-bit words
    for i in range(0, length, 2):
        word = data[i:i+2]
        # if length is odd, pad last byte
        if len(word) < 2:
            word += b'\x00'
        val = (word[0] << 8) + word[1]
        total += val
        # fold any carry bits > 16 back into lower 16
        total = (total & 0xFFFF) + (total >> 16)

    return total & 0xFFFF

# TODO fix
# Takes IP of current device and transforms it to a value for filling IPv4 Header BitArray
Source_Address = Default_Source_Address = ip_to_int("192.168.1.1")

# Default is the source, will be replaced manually
Destination_Address = Default_Source_Address

# Takes free port which was open for the connection from the source computer 
Source_Port = Default_Source_Port = 60000 # TODO FIX
Default_Destination_Port = 80

Port_Range = Default_Port_Range = [0,1000]

# for TCP Header checksum computation
class Pseudo_IPv4_Header:
    def __init__(self, Source_Address, Destination_Address, Reserved, Protocol, TCP_Length):
        self.Source_Address = Source_Address
        self.Destination_Address = Destination_Address
        self.Reserved = Reserved
        self.Protocol = Protocol
        self.TCP_Length = TCP_Length
    def to_bitarray(self):
        return (
                self.Source_Address
                + self.Destination_Address
                + self.Reserved
                + self.Protocol
                + self.TCP_Length
            )
    
"""
IPv4_Header Class

Concatenate all standard fields in typical IPv4 header order:
    1 byte:  Version + IHL
    1 byte:  DSCP + ECN
    2 bytes: Total Length
    2 bytes: Identification
    2 bytes: Flags + Fragment Offset
    1 byte:  Time To Live
    1 byte:  Protocol
    2 bytes: Header Checksum
    4 bytes: Source Address
    4 bytes: Destination Address
    (variable) Options
"""

class IPv4_Header:
    def __init__(self,
                Differentiated_Services_Code_Point,
                Explicit_Congestion_Notification,
                Identification,
                Time_To_Live,
                Protocol,
                Header_Checksum,
                Source_Address,
                Destination_Address,
                Options,
                TCP_Header_Length):

        self.IP_Version = BitArray(uint = 4, length = 4)
        self.Internet_Header_Length = BitArray(uint = 5, length = 4)
        self.Differentiated_Services_Code_Point = BitArray(uint = 0, length = 6)
        self.Explicit_Congestion_Notification = BitArray(uint = 0, length = 2)
        self.Identification = BitArray(uint = random.getrandbits(16), length = 16)
        self.Flags = BitArray(uint = 2, length = 3)
        self.Fragment_Offset = BitArray(uint = 0, length = 13)
        self.Time_To_Live = BitArray(uint = 64, length = 8)
        self.Protocol = BitArray(uint = 6, length = 8)
        self.Header_Checksum = BitArray(uint = 0, length = 16)
        self.Source_Address = BitArray(uint = Default_Source_Address, length = 32)
        self.Destination_Address = Default_Source_Address
        self.Options = BitArray()
        self.Total_Length = BitArray(uint = (self.Internet_Header_Length.value * 4 + TCP_Header_Length), length = 16)

        # Set fields with user configuration
        if Differentiated_Services_Code_Point:
            self.Differentiated_Services_Code_Point = BitArray(uint = Differentiated_Services_Code_Point, length = 6)

        if Explicit_Congestion_Notification:
            self.Explicit_Congestion_Notification = BitArray(uint = Explicit_Congestion_Notification, length = 2)

        if Identification:
            self.Identification = BitArray(uint = Identification, length = 16)

        if Time_To_Live:
            self.Time_To_Live = BitArray(uint = Time_To_Live, length = 8)

        if Protocol:
            self.Protocol = BitArray(uint = Protocol, length = 8)
        
        if Header_Checksum:
            self.Header_Checksum = BitArray(uint = Header_Checksum, length = 16)

        if Source_Address:
            self.Source_Address = BitArray(uint = Source_Address, length = 32)

        if Destination_Address:
            self.Destination_Address = BitArray(uint = Destination_Address, length = 32)

        if Options:
            bit_length = Options.bit_length()
            if bit_length % 32 != 0:
                bit_length = ((bit_length // 32) + 1) * 32
            self.Options = BitArray(uint = Options, length = bit_length)
            self.Internet_Header_Length = BitArray(uint = (5 + bit_length // 32), length = 4)
    
    def compute_checksum(self):
        ip_header_ba = self.to_bitarray
        checksum = ones_complement_sum_16bit(ip_header_ba)
        final_checksum = (~checksum) & 0xFFFF
        self.Header_Checksum.value = final_checksum

    def to_bitarray(self):
        # 1. Version (4 bits) + Internet_Header_Length (4 bits) => 8 bits
        version_ihl = self.IP_Version + self.Internet_Header_Length

        # 2. tos = DSCP (6 bits) + ECN (2 bits) => 8 bits
        tos = self.Differentiated_Services_Code_Point + self.Explicit_Congestion_Notification

        # 3. Flags (3 bits) + Fragment Offset (13 bits) => 16 bits
        flags_frag = self.Flags + self.Fragment_Offset

        ip_header = (
            version_ihl
            + tos
            + self.Total_Length
            + self.Identification
            + flags_frag
            + self.Time_To_Live
            + self.Protocol
            + self.Header_Checksum
            + self.Source_Address
            + self.Destination_Address
            + self.Options
        )

        return ip_header
    
"""
TCP_Header class:

Concatenate all standard fields in typical TCP header order:
    2 bytes:  Source Port
    2 bytes:  Destination Port
    4 bytes:  Sequence Number
    4 bytes:  Acknowledgment Number
    2 bytes:  Data Offset + Reserved + Flags
    2 bytes:  Window
    2 bytes:  Checksum
    2 bytes:  Urgent Pointer
    (variable) Options
    (variable) Data (payload) - returned in the to_bitarray_with_data function
"""

class TCP_Header:
    def __init__(self,
                Source_Port,
                Destination_Port,
                Sequence_Number,
                ACK_Number,
                Data_Offset,
                CWR,
                ECE,
                URG,
                ACK,
                PSH,
                RST,
                SYN,
                FIN,
                Window,
                Checksum,
                Urgent_Pointer,
                Options,
                Data):
        
        self.Source_Port = BitArray(uint = Default_Source_Port, length = 16)
        self.Destination_Port = BitArray(uint = Default_Destination_Port, length = 16)
        self.Sequence_Number = BitArray(uint = 0, length = 32)
        self.ACK_Number = BitArray(uint=0, length=32)
        self.Data_Offset = BitArray(uint=5, length=4)
        self.Flags = BitArray(uint = 0, length = 8)
        self.Reserved = BitArray(uint = 0, length = 4)
        self.Window = BitArray(uint = 65535, length = 16)
        self.Checksum = BitArray(uint = 0, length = 16)
        self.Urgent_Pointer = BitArray(uint = 0, length = 16)
        self.Options = BitArray()
        self.Data = BitArray()

        # Set fields with user configuration
        if Source_Port:
            self.Source_Port = BitArray(uint = Source_Port, length = 16)

        if Destination_Port:
            self.Destination_Port = BitArray(uint = Destination_Port, length = 16)

        # Default 0
        if Sequence_Number is None:
            if SYN is None or SYN == 0:
                self.Sequence_Number = BitArray(uint = 0, length = 32)
            else:
                rand_seq = random.getrandbits(32)
                self.Sequence_Number = BitArray(uint = rand_seq, length = 32)
        else:
            self.Sequence_Number = BitArray(uint = Sequence_Number, length = 32)

        if ACK_Number:
            self.ACK_Number = BitArray(uint=ACK_Number, length=32)

        if Data_Offset:
            self.Data_Offset = BitArray(uint = Data_Offset, length=4)
        
        if CWR or ECE or URG or ACK or PSH or RST or SYN or FIN:
            # Default flags for TCP header are 0
            def flag_bit(val):
                return BitArray(uint=(1 if val else 0), length=1)
            self.Flags = (
                flag_bit(CWR)
                + flag_bit(ECE)
                + flag_bit(URG)
                + flag_bit(ACK)
                + flag_bit(PSH)
                + flag_bit(RST)
                + flag_bit(SYN)
                + flag_bit(FIN)
            )

        if Window:
            self.Window = BitArray(uint = Window, length = 16)

        if Checksum:
            self.Checksum = BitArray(uint = Checksum, length = 16)

        if Urgent_Pointer:
            self.Urgent_Pointer = BitArray(uint = Urgent_Pointer, length = 16)

        if Options:
            bit_length = Options.bit_length()
            if bit_length % 32 != 0:
                bit_length = ((bit_length // 32) + 1) * 32
            self.Options = BitArray(uint = Options, length = bit_length)
            self.Data_Offset = BitArray(uint = (5 + (bit_length // 32)), length = 4)
        
        if Data is None:
            self.Data = BitArray(uint = Data, length = Data.bit_length())

        self.compute_checksum()
        
    def compute_checksum(self, Destination_Address):
        sum = 0

        if isinstance(Source_Address, int):
            Source_Address = BitArray(uint = ip_to_int(Source_Address), length = 32)

        if isinstance(Destination_Address, int):
            Destination_Address = BitArray(uint = ip_to_int(Destination_Address), length=32)

        psh_ipv4_header = Pseudo_IPv4_Header(Source_Address=Source_Address, Destination_Address=Destination_Address, Reserved = BitArray(uint = 0, length = 4), Protocol = BitArray(uint = 6, length = 8) , TCP_Length=(self.Data_Offset * 4 + len(self.Data)))
        buffer = psh_ipv4_header.to_bitarray() + self.to_bitarray_with_data()

        checksum_val = ones_complement_sum_16bit(buffer)
        final_checksum_val = (~checksum_val) & 0xFFFF
        self.Checksum = final_checksum_val

    def to_bitarray(self):
        offset_reserved_flags = self.Data_Offset + self.Reserved + self.Flags  # 16 bits total

        tcp_header = (
            self.Source_Port
            + self.Destination_Port
            + self.Sequence_Number
            + self.ACK_Number
            + offset_reserved_flags
            + self.Window
            + self.Checksum
            + self.Urgent_Pointer
            + self.Options
        )
        return tcp_header

    def to_bitarray_with_data(self):
        return self.to_bitarray() + self.Data


def send_raw_packet(packet_bytes):
    """
    Send manually crafted IPv4 + TCP packet via raw socket.
    packet_bytes: The raw, fully constructed packet (IP header + TCP header + data).
    dest_ip:      Destination IP string, e.g. '192.168.1.10'.
    
    Note: Requires root privileges on most systems.
    """
    # Create a raw socket. IPPROTO_RAW on some systems, IPPROTO_TCP on others.
    # AF_INET = IPv4
    # SOCK_RAW  = raw socket
    # IPPROTO_RAW or IPPROTO_TCP can vary based on OS.
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # Tell the kernel we’ve built the IP header ourselves (include “IP_HDRINCL”)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    # Send the packet. The destination address is required here;
    # the zero port in sendto() is typically ignored for raw sockets.
    sock.sendto(packet_bytes, (Destination_Address, 0))
    sock.close()

# TODO make scanner functions
def SYN_Scan(packet, port_range):
    for i in range(port_range[0], port_range[1]):
        # TODO send packets
        return 1

def main():
    scan_type
    ip_args = {}
    tcp_args = {}
    global Port_Range
    global Source_Address
    global Destination_Address
    global Source_Port

    i = 1
    try:
        while i < len(sys.argv):
            arg = sys.argv[i]
            value = sys.argv[i + 1] if i + 1 < len(sys.argv) else None

            # isisisisisisisisisis SCAN TYPE isisisisisisisisisis

            if arg is "-sS":
                scan_type = "SYN"
            elif arg is "-sT":
                scan_type = "TCP"
            elif arg is "-p":
                if(re.match(r"^(-?\d+)-(-?\d+)$", arg)):
                    port_range = int(arg.split("-"))
                else:
                    raise Exception("Invalid input")

            # isisisisisisisisisis IP HEADER isisisisisisisisisis

            elif arg is "-IP_Version":
                if value in ("4", "6"):
                    ip_args["IP_Version"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-Internet_Header_Length":
                if value.isdigit() and 5 <= int(value) <= 15:
                    ip_args["Internet_Header_Length"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-Differentiated_Services_Code_Point":
                if value.isdigit() and 0 <= int(value) <= 63:
                    ip_args["Differentiated_Services_Code_Point"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-Explicit_Congestion_Notification":
                if value.isdigit() and 0 <= int(value) <= 3:
                    ip_args["Explicit_Congestion_Notification"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-Total_Length":
                if value.isdigit() and 0 <= int(value) <= 65535:
                    ip_args["Total_Length"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-ID":
                if value.isdigit() and 0 <= int(value) <= 65535:
                    ip_args["ID"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-Flags":
                if value.startswith("0b") and len(value) <= 5:
                    ip_args["Flags"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-Fragment_Offset":
                if value.isdigit() and 0 <= int(value) <= 8191:
                    ip_args["Fragment_Offset"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-Protocol":
                if value.isdigit() and 0 <= int(value) <= 255:
                    ip_args["Protocol"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-Source_Address":
                if ipv4_regex.match(value):
                    Source_Address = ip_to_int(value)
                else:
                    raise Exception("Invalid input")
                
            elif arg is "-Destination_Address":
                if ipv4_regex.match(value):
                    Destination_Address = ip_to_int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-IP_Header_Options":
                if len(value) % 8 is 0:
                    ip_args["IP_Header_Options"] = int(value)
                else:
                    raise Exception("Invalid input")

            # isisisisisisisisisis TCP HEADER isisisisisisisisisis

            elif arg is "-Source_Port" or arg is "-Destination_Port":
                if value.isdigit() and 0 <= int(value) <= 65535:
                    tcp_args[arg.strip("-")] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-Sequence_Number" or arg is "-ACK_Number":
                if value.isdigit() and 0 <= int(value) <= 0xFFFFFFFF:
                    tcp_args[arg.strip("-")] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-Data_Offset":
                if value.isdigit() and 5 <= int(value) <= 15:
                    tcp_args["Data_Offset"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-Reserved":
                if value.isdigit() and 0 <= int(value) <= 7:
                    tcp_args["Reserved"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg in ("-CWR", "-ECE", "-URG", "-ACK", "-PSH", "-RST", "-SYN", "-FIN"):
                if value in ("0", "1"):
                    tcp_args[arg.strip("-")] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-Window":
                if value.isdigit() and 0 <= int(value) <= 65535:
                    tcp_args["Window"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-Urgent_Pointer":
                if value.isdigit() and 0 <= int(value) <= 65535:
                    tcp_args["Urgent_Pointer"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg is "-TCP_Header_Options":
                if len(value) % 8 is 0:
                    tcp_args["TCP_Header_Options"] = int(value)
                else:
                    raise Exception("Invalid input")        
            elif arg is "-TCP_Data":
                tcp_args["Data"] = value
            i += 2
    except Exception as e:
        print(f"Error: {e}")
        exit(1)
    
    # Create the IPv4_Header object
    ipv4_header = IPv4_Header(
                            Differentiated_Services_Code_Point = ip_args.get("Differentiated_Services_Code_Point", None),
                            Explicit_Congestion_Notification   = ip_args.get("Explicit_Congestion_Notification", None),
                            Identification                     = ip_args.get("ID", None),
                            Time_To_Live                       = ip_args.get("Time_To_Live", None),
                            Protocol                           = ip_args.get("Protocol", None),
                            Header_Checksum                    = None,  # will compute later
                            Source_Address                     = Source_Address,
                            Destination_Address                = Destination_Address,
                            Options                            = ip_args.get("IP_Header_Options", None),
                        )

    # Create the TCP_Header object
    tcp_header = TCP_Header(
                            Source_Port     = tcp_args.get("Source_Port", None),
                            Destination_Port= tcp_args.get("Destination_Port", None),
                            Sequence_Number = tcp_args.get("Sequence_Number", None),
                            ACK_Number      = tcp_args.get("ACK_Number", None),
                            Data_Offset     = tcp_args.get("Data_Offset", None),
                            CWR             = tcp_args.get("CWR", None),
                            ECE             = tcp_args.get("ECE", None),
                            URG             = tcp_args.get("URG", None),
                            ACK             = tcp_args.get("ACK", None),
                            PSH             = tcp_args.get("PSH", None),
                            RST             = tcp_args.get("RST", None),
                            SYN             = tcp_args.get("SYN", None),
                            FIN             = tcp_args.get("FIN", None),
                            Window          = tcp_args.get("Window", None),
                            Urgent_Pointer  = tcp_args.get("Urgent_Pointer", None),
                            Options         = tcp_args.get("TCP_Header_Options", None),
                            Data            = None   # If you have data or payload
                        )

    # Create socket
    sock_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    if tcp_args["Source_Port"] is None:
        sock_recv.bind(("0.0.0.0", 0))  # Listen for all inbound TCP on this machine
        Source_Address = socket.gethostbyname(socket.gethostname())
        Source_Port = sock_recv.getsockname()[1]
    else:
        sock_recv.bind(("0.0.0.0", tcp_args["Source_Port"]))

    # Generate Packet
    tcp_header.compute_checksum()
    ipv4_header.compute_checksum()
    packet = ipv4_header + tcp_header

    # send_raw_packet(packet.tobytes())

    # Listen for response
    while True:
        packet, addr = sock_recv.recvfrom(65535)
        print("Got packet from", addr,"len:", len(packet))