# Packet Crafter / Sender / Analyzer

> Inspired by the [Scapy](https://scapy.net/) module

## 📚 Description

This project is a tool for crafting, sending, and analyzing network packets. It was built for **learning purposes**, with the goal of understanding how network protocols work and how custom packets can be manually built.

While some minor functions (like printing and basic checks) were generated with the help of ChatGPT, the majority of the code is handwritten.

⚠️ **Note:** And yes the majority of the code is done by me, so I'm sorry for the lack of elegance in some places.

---

## 🎯 Objectives

- Manual generation of packets for various protocols
- Clear, explicit, and beginner-friendly code
- Better understanding of protocol headers and low-level networking

---

## ✅ Features

- [x] IPv4 header generation
- [x] TCP header generation
- [ ] Support for additional protocols
- [ ] Port scanning
- [ ] Analyzing capabilities of received received packages with explicit human readable and (useful for learning) info
- [ ] Packet spoofing
- [ ] Man page

---

## ⚠️ Known Issues

- ~~Currently, sending packets using the `sendto()` function may fail.~~
  ~~- The OS considers the arguments invalid.~~
  ~~- You can find this behavior in the [`main.py`](./main.py) file, near the end, after the *sanity check*.~~
  ```bash
  sent_bytes = sock_send.sendto(packet.tobytes(), (Destination_Address, 1000))

⚠️ **Note:** I just found out why this was happening, i use macos, and raw sockets are highly restricted on macos(and the majority of operating systems, a thing i didn't know when i started this project, it's i good thing i learned that now) and so I have to go a layer deeper, to the Data-Link layer! So I have to construct the ethernet header myself!

So i looked more into how scapy and nmap bypass these restrictions, and that's it! Finally I can maybe make this program work:)

---

## 🛠️ How to Use ()

1. Clone the repository:
   ```bash
   git clone https://github.com/username/packet-crafter.git
   cd packet-crafter

2. Run the script(no current implementations are made, firstly the issues mentioned have to be fixed):
   
   So an example usage(it wouldn't do anything with the flag yet, would just try to send a packet to itself)

   ⚠️ It requires sudo privileges to send raw packets.
   ```bash
   sudo python3 main.py -sS

---

## 📄 License

This project is open-source and free to use for educational purposes. If you find it useful or build upon it, credit is appreciated!
