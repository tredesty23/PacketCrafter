from config import Default_Source_MAC_Address, Default_Destination_MAC_Address, Default_Ether_Type, Default_TCP_Payload
from bitstring import BitArray
from utils import mac_to_int

"""
Ethernet_Frame class

Concatenate all standard fields in typical IPv4 header order:
    This field contains the hardware (MAC) address of the device that should receive the frame on the local network.
    6 bytes:  Destination_MAC_Address

    This field contains the hardware address of the device sending the frame.
    6 bytes:  Source_MAC_Address

    This field indicates what protocol is being carried in the payload. For example, 0x0800 denotes IPv4,
    0x86DD denotes IPv6, and 0x0806 denotes ARP.
    2 bytes:  EtherType

    This checksum is usually computed by your network interface card (NIC)
    and is appended to the end of the frame; you generally don't construct it manually.
    4 bytes: (Optional) Frame Check Sequence (FCS, 4 bytes):
"""

class Ethernet_Frame:
    def __init__(
        self,
        Source_MAC_Address = Default_Source_MAC_Address,
        Destination_MAC_Address = Default_Destination_MAC_Address,
        EtherType = Default_Ether_Type,
        Payload = Default_TCP_Payload
    ):
        self.Destination_MAC_Address = BitArray(uint = mac_to_int(Destination_MAC_Address), length = 48)
        self.Source_MAC_Address = BitArray(uint = mac_to_int(Source_MAC_Address), length = 48)
        self.EtherType = BitArray(uint = EtherType, length = 16)
        if Payload is None:
            raise Exception("No payload configured for ethernet frame construction")
        else:
            self.Payload = Payload

    def to_bitarray(self):
        return self.Destination_MAC_Address + self.Source_MAC_Address + self.EtherType + self.Payload
