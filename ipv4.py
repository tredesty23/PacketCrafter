
from config import Default_Destination_Address, Default_Source_Address
from utils import ip_to_int, ones_complement_sum_16bit
from bitstring import BitArray, Bits
import random
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
    def __init__(
        self,
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
        self.Total_Length = BitArray(uint = 40, length = 16) # will be updated
        self.Identification = BitArray(uint = random.getrandbits(16), length = 16)
        self.Flags = BitArray(uint = 2, length = 3)
        self.Fragment_Offset = BitArray(uint = 0, length = 13)
        self.Time_To_Live = BitArray(uint = 64, length = 8)
        self.Protocol = BitArray(uint = 6, length = 8)
        self.Header_Checksum = BitArray(uint = 0, length = 16)
        self.Source_Address = BitArray(uint = ip_to_int(Default_Source_Address), length = 32)
        self.Destination_Address = BitArray(uint = ip_to_int(Default_Destination_Address), length = 32)
        self.Options = BitArray(0)

        # Set fields with user configuration
        if Differentiated_Services_Code_Point is not None:
            self.Differentiated_Services_Code_Point = BitArray(uint = Differentiated_Services_Code_Point, length = 6)

        if Explicit_Congestion_Notification is not None:
            self.Explicit_Congestion_Notification = BitArray(uint = Explicit_Congestion_Notification, length = 2)

        if Identification is not None:
            self.Identification = BitArray(uint = Identification, length = 16)

        if Time_To_Live is not None:
            self.Time_To_Live = BitArray(uint = Time_To_Live, length = 8)

        if Protocol is not None:
            self.Protocol = BitArray(uint = Protocol, length = 8)
        
        if Header_Checksum is not None:
            self.Header_Checksum = BitArray(uint = Header_Checksum, length = 16)

        if Source_Address is not None:
            self.Source_Address = BitArray(uint = ip_to_int(Source_Address), length = 32)

        if Destination_Address is not None:
            self.Destination_Address = BitArray(uint = ip_to_int(Destination_Address), length = 32)

        if Options is not None:
            bit_length = Options.bit_length()
            if bit_length % 32 != 0:
                bit_length = ((bit_length // 32) + 1) * 32
            self.Options = BitArray(uint = Options, length = bit_length)
            self.Internet_Header_Length = BitArray(uint = (5 + bit_length // 32), length = 4)
    
    def compute_checksum(self):
        ip_header_ba = self.to_bitarray()
        checksum = ones_complement_sum_16bit(ip_header_ba)
        final_checksum = (~checksum) & 0xFFFF
        self.Header_Checksum = BitArray(uint = final_checksum, length=16)  # Use BitArray

    def update_total_length(self, tcp_length):
        ip_length = self.Internet_Header_Length.uint * 4 # typically 20 bytes
        self.Total_Length = BitArray(uint=(ip_length + tcp_length), length=16)

    def to_bitarray(self):
        # 1. Version (4 bits) + Internet_Header_Length (4 bits) => 8 bits

        # 2. tos = DSCP (6 bits) + ECN (2 bits) => 8 bits
        # 3. Flags (3 bits) + Fragment Offset (13 bits) => 16 bits
        self.Flags + self.Fragment_Offset

        ip_header = (
            self.IP_Version
            + self.Internet_Header_Length
            + self.Differentiated_Services_Code_Point
            + self.Explicit_Congestion_Notification
            + self.Total_Length
            + self.Identification
            + self.Flags
            + self.Fragment_Offset
            + self.Time_To_Live
            + self.Protocol
            + self.Header_Checksum
            + self.Source_Address
            + self.Destination_Address
            + self.Options
        )

        return ip_header
    