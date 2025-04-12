from config import Default_Source_Port, Default_Destination_Port
from utils import ip_to_int, ones_complement_sum_16bit
from bitstring import BitArray, Bits
import random

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
        self.Reserved = BitArray(uint = 0, length = 4)
        self.Flags = BitArray(uint = 0, length = 8)
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

        # This will be used to store the length of the tcp header + data
        # Default is minimum tcp header size 
        self.TCP_Header_Length = len(self.to_bitarray_with_data().tobytes())
        
    def compute_checksum(self, Destination_Address, Source_Address):

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
        
        self.Checksum = BitArray(uint=final_checksum_val, length = 16)

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