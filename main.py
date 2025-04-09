import socket
import sys
import re
import string
from bitstring import Bits, BitArray
import math
import struct
import ipaddress
import random
import time


# This test is gpt generated
def sanity_check_packet(ipv4_header: BitArray, tcp_header: BitArray) -> bool:
    packet_bytes = ipv4_header + tcp_header
    raw = packet_bytes.tobytes()

    # Basic length check
    if len(raw) < 40:
        print("❌ Packet too short. Should be at least 40 bytes (20 IP + 20 TCP).")
        return False

    # Extract IP version and header length
    version_ihl = raw[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    ip_header_length = ihl * 4

    if version != 4:
        print(f"❌ Invalid IP version: {version} (expected 4).")
        return False

    if ihl < 5:
        print(f"❌ IP Header Length too short: {ihl} (should be ≥ 5).")
        return False

    # Validate total length field
    total_length = struct.unpack("!H", raw[2:4])[0]
    if total_length != len(raw):
        print(f"⚠️ IP Total Length field = {total_length}, but actual = {len(raw)}.")

    # Validate IP addresses
    src_ip = socket.inet_ntoa(raw[12:16])
    dst_ip = socket.inet_ntoa(raw[16:20])
    try:
        ipaddress.ip_address(src_ip)
        ipaddress.ip_address(dst_ip)
    except ValueError:
        print(f"❌ Invalid IP addresses: src={src_ip}, dst={dst_ip}.")
        return False

    # Validate TCP source/destination ports
    try:
        src_port, dst_port = struct.unpack("!HH", raw[ip_header_length:ip_header_length + 4])
        if not (0 <= src_port <= 65535) or not (0 <= dst_port <= 65535):
            print(f"❌ Invalid TCP port values: src={src_port}, dst={dst_port}.")
            return False
    except struct.error:
        print("❌ TCP header too short or corrupted.")
        return False

    print("✅ Packet sanity check passed.")
    return True

# gpt generated prints
def print_packet_details(packet: BitArray):
    """
    Parse and print the detailed IPv4 and TCP header fields from a full packet.
    
    Parameters:
      packet: BitArray containing the full IPv4 packet (header + payload).
    """
    # Convert the BitArray to bytes.
    raw = packet.tobytes()
    
    # --- Parse IPv4 Header ---
    # Byte 0: Version and IHL.
    version_ihl = raw[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    ip_header_length = ihl * 4  # in bytes

    # Byte 1: DSCP and ECN (not split here but printed as one byte)
    dscp_ecn = raw[1]
    # Bytes 2-3: Total Length
    total_length = struct.unpack("!H", raw[2:4])[0]
    # Bytes 4-5: Identification
    identification = struct.unpack("!H", raw[4:6])[0]
    # Bytes 6-7: Flags (3 bits) and Fragment Offset (13 bits)
    flags_fragment = struct.unpack("!H", raw[6:8])[0]
    flags = flags_fragment >> 13
    fragment_offset = flags_fragment & 0x1FFF
    # Byte 8: Time To Live (TTL)
    ttl = raw[8]
    # Byte 9: Protocol
    protocol = raw[9]
    # Bytes 10-11: Header Checksum
    header_checksum = struct.unpack("!H", raw[10:12])[0]
    # Bytes 12-15: Source IP
    src_ip = socket.inet_ntoa(raw[12:16])
    # Bytes 16-19: Destination IP
    dst_ip = socket.inet_ntoa(raw[16:20])
    
    # Options: if IHL > 5
    if ihl > 5:
        options = raw[20:ip_header_length]
    else:
        options = None

    # --- Print IPv4 Header Details ---
    print("=====================================")
    print("           IPv4 HEADER")
    print("=====================================")
    print("IP Version:                   ", version)
    print("Internet Header Length:       ", ip_header_length, "bytes")
    print("DSCP + ECN:                   ", format(dscp_ecn, "08b"))
    print("Total Length:                 ", total_length, "bytes")
    print("Identification:               ", identification)
    print("Flags:                        ", format(flags, "03b"))
    print("Fragment Offset:              ", fragment_offset)
    print("Time To Live (TTL):           ", ttl)
    print("Protocol:                     ", protocol)
    print("Header Checksum:              ", hex(header_checksum))
    print("Source Address:               ", src_ip)
    print("Destination Address:          ", dst_ip)
    if options:
        print("Options:                      ", options.hex())
    else:
        print("Options:                      (none)")
    
    # --- Parse TCP Header ---
    # The TCP header starts at offset = ip_header_length.
    tcp_offset = ip_header_length

    # Bytes tcp_offset to tcp_offset+2: Source Port.
    src_port = struct.unpack("!H", raw[tcp_offset:tcp_offset+2])[0]
    # Bytes tcp_offset+2 to tcp_offset+4: Destination Port.
    dst_port = struct.unpack("!H", raw[tcp_offset+2:tcp_offset+4])[0]
    # Bytes tcp_offset+4 to tcp_offset+8: Sequence Number.
    sequence_number = struct.unpack("!I", raw[tcp_offset+4:tcp_offset+8])[0]
    # Bytes tcp_offset+8 to tcp_offset+12: Acknowledgment Number.
    ack_number = struct.unpack("!I", raw[tcp_offset+8:tcp_offset+12])[0]
    # Byte tcp_offset+12: Data Offset (upper 4 bits) and Reserved (lower 4 bits).
    data_offset_reserved = raw[tcp_offset+12]
    data_offset = data_offset_reserved >> 4  # in 32-bit words
    tcp_header_length = data_offset * 4       # in bytes
    # Byte tcp_offset+13: TCP Flags.
    tcp_flags = raw[tcp_offset+13]
    # Bytes tcp_offset+14 to tcp_offset+16: Window Size.
    window = struct.unpack("!H", raw[tcp_offset+14:tcp_offset+16])[0]
    # Bytes tcp_offset+16 to tcp_offset+18: Checksum.
    tcp_checksum = struct.unpack("!H", raw[tcp_offset+16:tcp_offset+18])[0]
    # Bytes tcp_offset+18 to tcp_offset+20: Urgent Pointer.
    urgent_pointer = struct.unpack("!H", raw[tcp_offset+18:tcp_offset+20])[0]

    # Options: if TCP header length > 20 bytes.
    if tcp_header_length > 20:
        tcp_options = raw[tcp_offset+20:tcp_offset+tcp_header_length]
    else:
        tcp_options = None
    
    # TCP Data: remainder of the packet after the TCP header.
    tcp_data = raw[tcp_offset+tcp_header_length:]
    
    # --- Print TCP Header Details ---
    print("\n=====================================")
    print("              TCP HEADER")
    print("=====================================")
    print("Source Port:                  ", src_port)
    print("Destination Port:             ", dst_port)
    print("Sequence Number:              ", sequence_number)
    print("Acknowledgment Number:        ", ack_number)
    print("Data Offset:                  ", tcp_header_length, "bytes")
    # Print flags as an 8-bit binary string.
    print("Flags:                        ", format(tcp_flags, "08b"))
    print("Window:                       ", window)
    print("Checksum:                     ", hex(tcp_checksum))
    print("Urgent Pointer:               ", urgent_pointer)
    if tcp_options:
        print("Options:                      ", tcp_options.hex())
    else:
        print("Options:                      (none)")
    if tcp_data:
        print("Data:                         ", tcp_data.hex())
    else:
        print("Data:                         (none)")
    print("=====================================\n")
    print("Packet: ", packet,"\n")

def print_header_details(ip_header, tcp_header):
    """
    Print detailed fields of an IPv4 header and a TCP header.
    
    Parameters:
      ip_header: An instance of IPv4_Header.
      tcp_header: An instance of TCP_Header.
    """
    print("=====================================")
    print("           IPv4 HEADER")
    print("=====================================")
    print("IP Version:                   ", ip_header.IP_Version.uint)
    # IHL is in 32-bit words; multiply by 4 for bytes.
    print("Internet Header Length:       ", ip_header.Internet_Header_Length.uint * 4, "bytes")
    print("Differentiated Services (DSCP):", ip_header.Differentiated_Services_Code_Point.uint)
    print("Explicit Congestion Notif (ECN):", ip_header.Explicit_Congestion_Notification.uint)
    print("Total Length:                 ", ip_header.Total_Length.uint, "bytes")
    print("Identification:               ", ip_header.Identification.uint)
    print("Flags:                        ", ip_header.Flags.bin)
    print("Fragment Offset:              ", ip_header.Fragment_Offset.uint)
    print("Time To Live (TTL):           ", ip_header.Time_To_Live.uint)
    print("Protocol:                     ", ip_header.Protocol.uint)
    print("Header Checksum:              ", hex(ip_header.Header_Checksum.uint))
    
    # Convert the 32-bit BitArrays to an IP string using socket.inet_ntoa()
    src_ip = socket.inet_ntoa(ip_header.Source_Address.tobytes())
    dst_ip = socket.inet_ntoa(ip_header.Destination_Address.tobytes())
    print("Source Address:               ", src_ip)
    print("Destination Address:          ", dst_ip)
    
    # Options may be empty; if not, print binary string.
    if ip_header.Options.length > 0:
        print("Options:                      ", ip_header.Options.bin)
    else:
        print("Options:                      (none)")
    
    print("\n=====================================")
    print("              TCP HEADER")
    print("=====================================")
    print("Source Port:                  ", tcp_header.Source_Port.uint)
    print("Destination Port:             ", tcp_header.Destination_Port.uint)
    print("Sequence Number:              ", tcp_header.Sequence_Number.uint)
    print("ACK Number:                   ", tcp_header.ACK_Number.uint)
    # TCP Data_Offset is in 32-bit words; multiply by 4 for bytes.
    print("Data Offset:                  ", tcp_header.Data_Offset.uint * 4, "bytes")
    print("Reserved:                     ", tcp_header.Reserved.uint)
    print("Flags:                        ", tcp_header.Flags.bin)
    print("Window:                       ", tcp_header.Window.uint)
    print("Checksum:                     ", hex(tcp_header.Checksum.uint))
    print("Urgent Pointer:               ", tcp_header.Urgent_Pointer.uint)
    
    if tcp_header.Options.length > 0:
        print("Options:                      ", tcp_header.Options.bin)
    else:
        print("Options:                      (none)")
        
    if tcp_header.Data.length > 0:
        print("Data:                         ", tcp_header.Data.bin)
    else:
        print("Data:                         (none)")
    
    print("=====================================\n")
    print("Packet: ", ip_header.to_bitarray() + tcp_header.to_bitarray_with_data(), "\n")

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

global Default_Source_Address
global Default_Destination_Address
global Default_Source_Port
global Default_Destination_Port

global Source_Address
global Destination_Address
global Source_Port
global Destination_Port

global Port_Range


Source_Address = Default_Source_Address = "192.168.1.1"

# Default is the source, will be replaced manually
Destination_Address = Default_Destination_Address = "192.168.1.1"

# Takes free port which was open for the connection from the source computer 
Source_Port = Default_Source_Port = 12345 # TODO FIX
Destination_Port = Default_Destination_Port = 80

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
                Options
                ):

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
        self.Source_Address = BitArray(uint = ip_to_int(Default_Source_Address), length = 32)
        self.Destination_Address = BitArray(uint = ip_to_int(Default_Destination_Address), length = 32)
        self.Options = BitArray(0)
        self.Total_Length = BitArray(uint = 0, length = 16) # will be updated

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
            self.Source_Address = BitArray(uint = ip_to_int(Source_Address), length = 32)

        if Destination_Address:
            self.Destination_Address = BitArray(uint = ip_to_int(Destination_Address), length = 32)

        if Options:
            bit_length = Options.bit_length()
            if bit_length % 32 != 0:
                bit_length = ((bit_length // 32) + 1) * 32
            self.Options = BitArray(uint = Options, length = bit_length)
            self.Internet_Header_Length = BitArray(uint = (5 + bit_length // 32), length = 4)
    
    def compute_checksum(self):
        ip_header_ba = self.to_bitarray()  # Add parentheses here
        checksum = ones_complement_sum_16bit(ip_header_ba)
        final_checksum = (~checksum) & 0xFFFF
        self.Header_Checksum = BitArray(uint=final_checksum, length=16)  # Use BitArray

    def update_total_length(self, tcp_bitarray_with_data: BitArray):
        tcp_length = len(tcp_bitarray_with_data.tobytes()) # in bytes
        ip_length = self.Internet_Header_Length.uint * 4 # typically 20 bytes
        self.Total_Length = BitArray(uint=(ip_length + tcp_length), length=16)

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
        self.Options = BitArray(0)
        self.Data = BitArray(0)

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
        
        if Data:
            self.Data = BitArray(uint = Data, length = Data.bit_length())

        self.compute_checksum()

        # This will be used to store the length of the tcp header + data
        # Default is minimum tcp header size 
        self.TCP_Header_Length = len(self.to_bitarray_with_data().tobytes())
        
    def compute_checksum(self):

        global Destination_Address
        global Source_Address

        src_addr = BitArray(uint = ip_to_int(Source_Address), length = 32)

        dst_addr = BitArray(uint = ip_to_int(Destination_Address), length=32)

        psh_ipv4_header = Pseudo_IPv4_Header(Source_Address=src_addr,
                                            Destination_Address=dst_addr,
                                            Reserved = BitArray(uint = 0, length = 4),
                                            Protocol = BitArray(uint = 6, length = 8),
                                            TCP_Length = BitArray(uint = (self.Data_Offset.uint * 4 + len(self.Data)), length = 16)
                                        )
        buffer = psh_ipv4_header.to_bitarray() + self.to_bitarray_with_data()
        checksum_val = ones_complement_sum_16bit(buffer)
        final_checksum_val = (~checksum_val) & 0xFFFF
        
        self.Checksum = BitArray(uint=final_checksum_val, length=16)

    def to_bitarray(self):

        tcp_header = (
            self.Source_Port
            + self.Destination_Port
            + self.Sequence_Number
            + self.ACK_Number
            + self.Data_Offset
            + self.Reserved
            + self.Flags
            + self.Window
            + self.Checksum
            + self.Urgent_Pointer
            + self.Options
        )
        return tcp_header

    def to_bitarray_with_data(self):
        return self.to_bitarray() + self.Data

def main():
    ip_args = {}
    tcp_args = {}
    global Port_Range
    global Source_Address
    global Destination_Address
    global Source_Port
    global Destination_Port

    i = 1

    try:
        if len(sys.argv) == 1:
            raise Exception("Invalid input, no arguments used")

        while i < len(sys.argv):
            arg = sys.argv[i]
            value = sys.argv[i + 1] if i + 1 < len(sys.argv) else None

            # ____________________ SCAN TYPE ____________________

            if arg == "-sS":
                scan_type = "SYN"
            elif arg == "-sT":
                scan_type = "TCP"
            elif arg == "-p":
                if(re.match(r"^(-?\d+)-(-?\d+)$", arg)):
                    port_range = int(arg.split("-"))
                else:
                    raise Exception("Invalid input")

            # ____________________ IP HEADER ____________________

            elif arg == "-IP_Version":
                if value in ("4", "6"):
                    ip_args["IP_Version"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-Internet_Header_Length":
                if value.isdigit() and 5 <= int(value) <= 15:
                    ip_args["Internet_Header_Length"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-Differentiated_Services_Code_Point":
                if value.isdigit() and 0 <= int(value) <= 63:
                    ip_args["Differentiated_Services_Code_Point"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-Explicit_Congestion_Notification":
                if value.isdigit() and 0 <= int(value) <= 3:
                    ip_args["Explicit_Congestion_Notification"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-Total_Length":
                if value.isdigit() and 0 <= int(value) <= 65535:
                    ip_args["Total_Length"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-ID":
                if value.isdigit() and 0 <= int(value) <= 65535:
                    ip_args["ID"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-Flags":
                if value.startswith("0b") and len(value) <= 5:
                    ip_args["Flags"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-Fragment_Offset":
                if value.isdigit() and 0 <= int(value) <= 8191:
                    ip_args["Fragment_Offset"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-Protocol":
                if value.isdigit() and 0 <= int(value) <= 255:
                    ip_args["Protocol"] = int(value)
                else:
                    raise Exception("Invalid input")
                
            elif arg == "-IPv4_Checksum":
                if value.isdigit() and 0 <= int(value) <= 65535:
                    tcp_args["Header_Checksum"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-Source_Address":
                if ipv4_regex.match(value):
                    Source_Address = ip_to_int(value)
                else:
                    raise Exception("Invalid input")
                
            elif arg == "-Destination_Address":
                if ipv4_regex.match(value):
                    Destination_Address = ip_to_int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-IP_Header_Options":
                if len(value) % 8 == 0:
                    ip_args["IP_Header_Options"] = int(value)
                else:
                    raise Exception("Invalid input")

            # ____________________ TCP HEADER ____________________

            elif arg == "-Source_Port":
                if value.isdigit() and 0 <= int(value) <= 65535:
                    Source_Port = int(value)
                else:
                    raise Exception("Invalid input")
                
            elif arg == "-Destination_Port":
                if value.isdigit() and 0 <= int(value) <= 65535:
                    Destination_Port = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-Sequence_Number" or arg == "-ACK_Number":
                if value.isdigit() and 0 <= int(value) <= 0xFFFFFFFF:
                    tcp_args[arg.strip("-")] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-Data_Offset":
                if value.isdigit() and 5 <= int(value) <= 15:
                    tcp_args["Data_Offset"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-Reserved":
                if value.isdigit() and 0 <= int(value) <= 7:
                    tcp_args["Reserved"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == ("-CWR", "-ECE", "-URG", "-ACK", "-PSH", "-RST", "-SYN", "-FIN"):
                if value in ("0", "1"):
                    tcp_args[arg.strip("-")] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-Window":
                if value.isdigit() and 0 <= int(value) <= 65535:
                    tcp_args["Window"] = int(value)
                else:
                    raise Exception("Invalid input")
                
            elif arg == "-TCP_Checksum":
                if value.isdigit() and 0 <= int(value) <= 65535:
                    tcp_args["Window"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-Urgent_Pointer":
                if value.isdigit() and 0 <= int(value) <= 65535:
                    tcp_args["Urgent_Pointer"] = int(value)
                else:
                    raise Exception("Invalid input")

            elif arg == "-TCP_Header_Options":
                if (len(value) % 8) == 0:
                    tcp_args["TCP_Header_Options"] = int(value)
                else:
                    raise Exception("Invalid input")        
            elif arg == "-TCP_Data":
                tcp_args["Data"] = value
            else:
                raise Exception("Invalid input")

            i += 2
    except Exception as e:
        print(f"Error: {e}")
        exit(1)

    

    # Create a raw receiving socket for inbound TCP packets
    sock_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock_recv.bind(("0.0.0.0", Source_Port))  # Bind to listen on all interfaces

    # Get actual source details from the bound socket.
    # First, get a preliminary source port from sock_recv.
    Source_Port = sock_recv.getsockname()[1]
    # Then use a temporary UDP socket to get the external IP address.
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    temp_sock.connect(('8.8.8.8', 80))
    Source_Address = temp_sock.getsockname()[0]
    temp_sock.close()

    # Create the TCP_Header object
    tcp_header = TCP_Header(
                            Source_Port     = Source_Port,
                            Destination_Port= Destination_Port,
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
                            Checksum        = tcp_args.get("Checksum", None),
                            Urgent_Pointer  = tcp_args.get("Urgent_Pointer", None),
                            Options         = tcp_args.get("TCP_Header_Options", None),
                            Data            = None # If you have data or payload
                        )
    
    # Create the IPv4_Header object
    ipv4_header = IPv4_Header(
                            Differentiated_Services_Code_Point = ip_args.get("Differentiated_Services_Code_Point", None),
                            Explicit_Congestion_Notification   = ip_args.get("Explicit_Congestion_Notification", None),
                            Identification                     = ip_args.get("ID", None),
                            Time_To_Live                       = ip_args.get("Time_To_Live", None),
                            Protocol                           = ip_args.get("Protocol", None),
                            Header_Checksum                    = ip_args.get("Header_Checksum", None),
                            Source_Address                     = Source_Address,
                            Destination_Address                = Destination_Address,
                            Options                            = ip_args.get("IP_Header_Options", None),
                        )
    # Create raw socket for sending
    sock_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock_send.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)


    # Prepare headers
    ipv4_header.update_total_length(tcp_bitarray_with_data = tcp_header.to_bitarray_with_data())

    tcp_header.compute_checksum()
    ipv4_header.compute_checksum()

    print_header_details(ip_header = ipv4_header, tcp_header = tcp_header)
    
    # Send the packet
    try:
        if sanity_check_packet(ipv4_header.to_bitarray(), tcp_header.to_bitarray_with_data()):
            packet = ipv4_header.to_bitarray() + tcp_header.to_bitarray_with_data()

            print_packet_details(packet = packet)

            sent_bytes = sock_send.sendto(packet.tobytes(), (Destination_Address, 0))

            if sent_bytes == 0:
                raise RuntimeError("❌ Packet send returned 0 bytes (nothing sent)")

            print(f"✅ Packet sent ({sent_bytes} bytes)")
        else:
            raise ValueError("❌ Packet sanity check failed")
    except (OSError, RuntimeError, ValueError) as e:
        print(f"❌ Failed to send packet: {e}")


    # Listen for responses on the raw receiving socket (sock_recv)
    received_packets = []
    timeout = 5  # seconds to wait for responses
    sock_recv.settimeout(timeout)
    start_time = time.time()

    while time.time() - start_time < timeout:   
        try:
            packet_data, addr = sock_recv.recvfrom(65535)
            if addr[0] == Destination_Address:  # Only store packets from our target
                received_packets.append({
                    'timestamp': time.time(),
                    'source_ip': addr[0],
                    'source_port': addr[1],
                    'data': packet_data,
                    'length': len(packet_data)
                })
        except socket.timeout:
            continue
        
    sock_send.close()
    sock_recv.close()

    # Print received packets
    print(f"Received {len(received_packets)} packets:")
    for i, pkt in enumerate(received_packets):
        print(f"Packet {i+1}: From {pkt['source_ip']}:{pkt['source_port']} - {pkt['length']} bytes")

main()