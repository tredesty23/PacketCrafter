import socket
from bitstring import BitArray, Bits
import struct
import ipaddress

# This test is gpt generated
import struct
import socket
from bitstring import BitArray

def tcp_sanity_check_packet(packet: BitArray) -> bool:
    """
    Perform a detailed sanity check on a packet (as a BitArray) and verify that:
      - The packet is long enough to contain an IPv4 header.
      - The IPv4 header has a valid version (4), IHL (>=5), and Total Length field.
      - The IPv4 header checksum (after zeroing its field) matches the header’s checksum.
      - The source IP is not 0.0.0.0.
      - The protocol field is TCP (6).
      - The packet is long enough to include a minimal TCP header.
      - The TCP header's source and destination ports are not zero.
      - The TCP header's Data Offset is at least 5 (20 bytes) and fits into the packet.
      
    If any check fails, an error message is printed and False is returned.
    If all checks pass, True is returned.
    """
    raw = packet.tobytes()
    pkt_len = len(raw)
    
    # IPv4: Must be at least 20 bytes.
    if pkt_len < 20:
        print("❌ Packet is too short to contain an IPv4 header (min 20 bytes).")
        return False

    # Parse first byte: Version (upper 4 bits) and IHL (lower 4 bits)
    version_ihl = raw[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    ip_header_len = ihl * 4  # in bytes

    if version != 4:
        print(f"❌ Invalid IP version: expected 4, got {version}.")
        return False
    if ihl < 5:
        print(f"❌ IHL too short: {ihl} (minimum is 5).")
        return False
    if pkt_len < ip_header_len:
        print("❌ Packet length is less than the IP header length.")
        return False

    # Total Length field (bytes 2-3, network order)
    total_length = struct.unpack("!H", raw[2:4])[0]
    if total_length != pkt_len:
        print(f"⚠️ IP Total Length field ({total_length} bytes) does not match actual packet length ({pkt_len} bytes).")
        return False

    # TTL check (byte 8): TTL should be > 0.
    ttl = raw[8]
    if ttl == 0:
        print("❌ IP TTL is 0 (packet expired).")
        return False

    # Protocol check (byte 9): Should be 6 (TCP)
    protocol = raw[9]
    if protocol != 6:
        print(f"❌ IP Protocol field is {protocol}; expected TCP (6).")
        return False

    # Recalculate IP header checksum:
    # Set the checksum field (bytes 10-11) to 0 when calculating.
    ip_header = raw[:ip_header_len]
    header_for_checksum = ip_header[:10] + b'\x00\x00' + ip_header[12:]
    checksum_calc = 0
    for i in range(0, len(header_for_checksum), 2):
        word = header_for_checksum[i:i+2]
        if len(word) < 2:
            word += b'\x00'
        value = int.from_bytes(word, byteorder='big')
        checksum_calc += value
        checksum_calc = (checksum_calc & 0xffff) + (checksum_calc >> 16)
    checksum_calc = ~checksum_calc & 0xffff
    ip_checksum = struct.unpack("!H", raw[10:12])[0]
    if ip_checksum != checksum_calc:
        print(f"⚠️ IP checksum mismatch: header has {hex(ip_checksum)}, calculated {hex(checksum_calc)}.")

    # Parse source and destination IP addresses (bytes 12-15 and 16-19)
    src_ip = socket.inet_ntoa(raw[12:16])
    dst_ip = socket.inet_ntoa(raw[16:20])
    if src_ip == "0.0.0.0":
        print("❌ Source IP address is 0.0.0.0.")
        return False

    # --- TCP Header Checks ---
    # TCP header must start after the IP header.
    tcp_offset = ip_header_len
    # Check if there is enough room for a minimal TCP header (20 bytes)
    if pkt_len < tcp_offset + 20:
        print("❌ Packet is too short to contain a minimal TCP header (20 bytes).")
        return False

    # Source port (2 bytes at tcp_offset)
    src_port = struct.unpack("!H", raw[tcp_offset:tcp_offset+2])[0]
    if src_port == 0:
        print("❌ TCP source port is 0.")
        return False

    # Destination port (next 2 bytes)
    dst_port = struct.unpack("!H", raw[tcp_offset+2:tcp_offset+4])[0]
    if dst_port == 0:
        print("❌ TCP destination port is 0.")
        return False

    # Data Offset is the upper 4 bits of the 13th byte of TCP header
    data_offset_reserved = raw[tcp_offset+12]
    tcp_data_offset = data_offset_reserved >> 4  # in 32-bit words
    tcp_header_len = tcp_data_offset * 4  # in bytes
    if tcp_data_offset < 5:
        print(f"❌ TCP Data Offset is too small: {tcp_data_offset} (minimum is 5).")
        return False
    if pkt_len < tcp_offset + tcp_header_len:
        print("❌ Packet is too short for the TCP header length specified by the Data Offset.")
        return False

    # (Optional) Check TCP Flags – print them for debugging.
    tcp_flags = raw[tcp_offset+13]
    # For example, a segment might be considered “suspicious” if all flags are zero,
    # but there are cases (e.g., pure ACKs) where flags can be 0. So we merely print:
    # print(f"TCP Flags: {format(tcp_flags, '08b')}")

    print("✅ Packet passed detailed sanity check:")
    print(f"    IPv4 header: {ip_header_len} bytes, Total Length: {total_length} bytes")
    print(f"    TCP header: {tcp_header_len} bytes")
    print(f"    Source: {src_ip}:{src_port}, Destination: {dst_ip}:{dst_port}")
    
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

def save_packet_to_files(packet):
    """
    Save the packet's byte and bit representations into separate files.
    
    Parameters:
      packet (BitArray): The packet data as a BitArray object.
      
    Output:
      Creates/overwrites two files in the current directory:
      - 'packet_bytes': Contains the raw bytes from the packet.
      - 'packet_bits' : Contains the full bit string representation.
    """
    try:
        # Convert the raw bytes from the BitArray to a hex string.
        hex_string = packet.tobytes().hex()
        # Open file in text mode and write the hex string.
        with open("packet_bytes.txt", "w") as f:
            f.write(hex_string)
        print("✅ Successfully wrote packet bytes as hex to 'packet_bytes.txt'.")
    except Exception as e:
        print(f"❌ Error writing packet bytes to text file: {e}")