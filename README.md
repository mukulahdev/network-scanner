# net-scan

**Find the devices and open ports on your own lab network, the way arp-scan and nmap do.**

`net-scan` is a small Python tool, built line by line in the
[MUKULAH Dev](https://www.youtube.com/@mukulahdev) course *Network scanning*.
Every line is explained in the videos.

* **`scan`:** asks every address on a network with ARP (built with Scapy) and
  lists who answered: IP, MAC and maker. MACs set by software, like the ones
  from our [MAC changer](https://github.com/mukulahdev/mac-changer), are spotted.
* **`ports`:** knocks on a device's doors with TCP and reports open, closed and
  filtered, like nmap; a pool of threads knocks on many doors at once.
* **Safe by design:** it refuses public networks and addresses, and networks
  bigger than 1,024 addresses.
* **16 unit tests**, none of which sends a packet.

---

## Requirements

* Linux with Python 3.11 or newer
* Scapy (`sudo apt install python3-scapy`, or `pip install -r requirements.txt` in a venv)
* Root (or `sudo`) for the ARP scan: Scapy builds packets by hand

---

## Install

```bash
git clone https://github.com/mukulahdev/network-scanner.git
cd network-scanner
sudo install -m 755 net_scanner.py /usr/local/bin/net-scan
net-scan --version
```

---

## Usage

```bash
sudo net-scan scan 192.168.230.0/24              # who is on my lab network?
net-scan ports 192.168.230.133                   # doors 1-1024
net-scan ports 192.168.230.133 -p 22,80,8000-8100
net-scan ports 192.168.230.129 -w 20             # 20 knocks at once
net-scan --help
```

---

## Tests

```bash
python3 -m unittest -v
```

---

## Responsible use

For learning, and only on networks and devices you own or have written
permission to test. Scanning other people's networks without permission can be
illegal. The tool refuses public addresses on purpose.

---

## License

MIT. See [LICENSE](LICENSE).
