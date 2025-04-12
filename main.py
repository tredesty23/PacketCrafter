import socket
import sys
import re
from bitstring import Bits, BitArray
from utils import ip_to_int
import time
from ipv4 import IPv4_Header
from tcp import TCP_Header
from utils import sanity_check_packet, print_packet_details, save_packet_to_files
from config import Default_Destination_Address, Default_Source_Address, Default_Source_Port, Default_Destination_Port, Default_Port_Range
import traceback

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

def main():
    ip_args = {}
    tcp_args = {}
    Port_Range = Default_Port_Range
    Source_Address = Default_Source_Address
    Destination_Address = Default_Destination_Address
    Source_Port = Default_Source_Port
    Destination_Port = Default_Destination_Port

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
    ipv4_header.update_total_length(tcp_header.TCP_Header_Length)

    tcp_header.compute_checksum(Destination_Address = Destination_Address, Source_Address = Source_Address)
    ipv4_header.compute_checksum()
    
    packet = ipv4_header.to_bitarray() + tcp_header.to_bitarray_with_data()

    # Send the packet
    try:
        if sanity_check_packet(packet):
            
            print_packet_details(packet)
            
            save_packet_to_files(packet)

            sent_bytes = sock_send.sendto(packet.tobytes(), (Destination_Address, 1000))

            if sent_bytes == 0:
                raise RuntimeError("❌ Packet send returned 0 bytes (nothing sent)")

            print(f"✅ Packet sent ({sent_bytes} bytes)")
        else:
            raise ValueError("❌ Packet sanity check failed")
    except (OSError, RuntimeError, ValueError) as e:
        traceback.print_exc()
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