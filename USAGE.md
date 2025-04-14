# USAGE.md

## Overview

This project is a Python3-based tool for crafting and injecting custom TCP/IP packets at the data link layer. It allows users to define specific IP and TCP header fields using command-line arguments.

> **Note:** Scanning options such as `-sS` and `-sT` are recognized but **not implemented** yet.

---

## Installation

To install:

```bash
git clone https://github.com/yourusername/yourproject.git # clone project
cd yourproject # enter project folder
python3 -m venv venv # create virtual enviroement
source venv/bin/activate # only run path on windows
pip install -r requirements.txt # install dependencies
```

---

## Basic Usage

You must provide arguments in **pairs**: a flag followed by its value.

```bash
python3 main.py -Source_Address 192.168.1.10 -Destination_Address 192.168.1.1 -Source_Port 12345 -Destination_Port 80 -TCP_Data "Hello"
```

**Note** All fields have default values, but if no arguments are provided, the program will exit with an error.

---

## Arguments

### Scan Type Options (⚠️ Not yet implemented)
- `-sS`: SYN scan
- `-sT`: TCP connect scan
- `-p <start-end>`: Port range (e.g., `80-80` for a single port)

### IP Header Options

| Flag | Description | Accepted Values |
|------|-------------|-----------------|
| `-IP_Version` | Set IP version | `4` or `6` |
| `-Internet_Header_Length` | Internet Header Length | Integer `5–15` |
| `-Differentiated_Services_Code_Point` | DSCP field value | Integer `0–63` |
| `-Explicit_Congestion_Notification` | ECN bits | Integer `0–3` |
| `-Total_Length` | Total IP packet length | Integer `0–65535` |
| `-ID` | IP Identification field | Integer `0–65535` |
| `-Flags` | Flag bits | Binary string (e.g., `0b010`, max 5 chars) |
| `-Fragment_Offset` | Fragment offset | Integer `0–8191` |
| `-Protocol` | Protocol number (e.g., `6` for TCP) | Integer `0–255` |
| `-IPv4_Checksum` | Header checksum | Integer `0–65535` |
| `-Source_Address` | IPv4 source address | e.g., `192.168.1.100` |
| `-Destination_Address` | IPv4 destination address | e.g., `192.168.1.1` |
| `-IP_Header_Options` | Additional options | Length must be multiple of 8 |

### TCP Header Options

| Flag | Description | Accepted Values |
|------|-------------|-----------------|
| `-Source_Port` | Source port | Integer `0–65535` |
| `-Destination_Port` | Destination port | Integer `0–65535` |
| `-Sequence_Number` / `-ACK_Number` | Sequence or ACK number | Integer `0–4294967295` |
| `-Data_Offset` | TCP data offset | Integer `5–15` |
| `-Reserved` | Reserved bits | Integer `0–7` |
| TCP Flags (`-CWR`, `-ECE`, `-URG`, `-ACK`, `-PSH`, `-RST`, `-SYN`, `-FIN`) | Set flag | `0` or `1` |
| `-Window` | Window size | Integer `0–65535` |
| `-TCP_Checksum` | TCP checksum | Integer `0–65535` *(currently writes to Window field)* |
| `-Urgent_Pointer` | Urgent pointer | Integer `0–65535` |
| `-TCP_Header_Options` | Additional TCP options | Length must be multiple of 8 |
| `-TCP_Data` | Payload data | String |

---

## Notes

- The script injects the packet at the **data link layer** using the **default MAC address**.
- You should ensure you have appropriate permissions (e.g., run with `sudo` on Unix systems).

(should work without sudo currently also)

---

## Example

# Run tcpdump in another terminal window with a filter to see the packet
*You can also use wireshark or any other packet capturing software*

```bash
tcpdump -i en0 ether host aa:bb:cc:dd:ee:ff # put your own mac address
```

**Note** You can run main.py once also to and there you can see your mac address

```bash
python3 main.py -SYN 1 -ACK 1
```

---

## License

Open source project
