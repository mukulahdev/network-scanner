import socket
import unittest
from unittest import mock

import net_scanner as ns
from scapy.all import ARP, Ether


class TestNetwork(unittest.TestCase):
    def test_private_lab_network(self):
        network = ns.lab_network("192.168.230.0/24")
        self.assertEqual(network.num_addresses, 256)

    def test_any_address_on_the_street_works(self):
        network = ns.lab_network("192.168.230.128/24")
        self.assertEqual(str(network), "192.168.230.0/24")

    def test_refuses_public_networks(self):
        with self.assertRaises(ValueError):
            ns.lab_network("8.8.8.0/24")

    def test_refuses_huge_networks(self):
        with self.assertRaises(ValueError):
            ns.lab_network("10.0.0.0/8")


class TestArpRequest(unittest.TestCase):
    def test_envelope_and_letter(self):
        packet = ns.arp_request(ns.lab_network("192.168.230.0/24"))
        self.assertEqual(packet[Ether].dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(packet[ARP].op, 1)  # 1 = who has? (a request)
        self.assertEqual(packet[ARP].pdst, "192.168.230.0/24")


class TestVendor(unittest.TestCase):
    def test_vmware(self):
        self.assertEqual(ns.vendor_of("00:0c:29:43:66:ca"), "VMware")

    def test_set_by_software(self):
        mac = "52:fb:8f:41:e2:61"  # from our MAC changer, part 4
        self.assertEqual(ns.vendor_of(mac), "random (set by software)")

    def test_unknown(self):
        self.assertEqual(ns.vendor_of("00:11:22:33:44:55"), "unknown")


class TestPorts(unittest.TestCase):
    def test_refuses_public_hosts(self):
        with self.assertRaises(ValueError):
            ns.port_scan("8.8.8.8", [80])

    def test_open_and_closed(self):
        with socket.socket() as server:  # a pretend program on our own machine
            server.bind(("127.0.0.1", 0))
            server.listen()
            port = server.getsockname()[1]
            self.assertEqual(ns.knock("127.0.0.1", port).state, "open")
        self.assertEqual(ns.knock("127.0.0.1", port).state, "closed")

    def test_silence_means_filtered(self):
        with mock.patch("socket.create_connection", side_effect=TimeoutError):
            self.assertEqual(ns.knock("192.168.230.129", 22).state, "filtered")

    def test_results_come_back_in_order(self):
        fake = lambda ip, p: ns.Port(p, "closed")
        with mock.patch.object(ns, "knock", fake):
            ports = ns.port_scan("192.168.230.133", [80, 21, 443])
        self.assertEqual([p.number for p in ports], [21, 80, 443])


class TestCommandLine(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(ns.parse_ports("80,22,20-23"), [20, 21, 22, 23, 80])

    def test_bad_ports_are_refused(self):
        with self.assertRaises(ValueError):
            ns.parse_ports("0-70000")

    def test_ports_has_defaults(self):
        args = ns.build_parser().parse_args(["ports", "192.168.230.133"])
        self.assertEqual((args.ports, args.workers), ("1-1024", 100))

    def test_public_network_exits_with_2(self):
        with mock.patch("sys.stderr"):
            self.assertEqual(ns.main(["ports", "8.8.8.8", "-p", "80"]), 2)


if __name__ == "__main__":
    unittest.main()
