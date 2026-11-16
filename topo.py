#!/usr/bin/env python3
"""
Mininet topology for the Adaptive Load Balancer.

h1 h2 h3 (clients) --- s1 --- h4 h5 h6 (TCP servers)
VIP = 10.0.0.100:80

Usage:
  sudo python3 topo.py --demo
  sudo python3 topo.py
"""

import argparse
import os
import time
from collections import Counter
from subprocess import PIPE

from mininet.cli import CLI # type: ignore
from mininet.link import TCLink # type: ignore
from mininet.log import setLogLevel # type: ignore
from mininet.net import Mininet # type: ignore
from mininet.node import OVSSwitch, RemoteController # type: ignore

VIP = "10.0.0.100"
HERE = os.path.dirname(os.path.abspath(__file__))


def build():
    net = Mininet(
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=False
    )

    net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653
    )

    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    # Create three clients and three backend servers.
    for i in range(1, 7):
        h = net.addHost(
            "h%d" % i,
            ip="10.0.0.%d/24" % i,
            mac="00:00:00:00:00:%02x" % i
        )

        # Limit backend server links to 10 Mbps.
        net.addLink(h, s1, bw=10 if i >= 4 else None)

    return net


def start_server(net, name):
    net.get(name).cmd(
        "python3 %s/server.py %s 80 > /tmp/%s.log 2>&1 &"
        % (HERE, name, name)
    )


def stop_server(net, name):
    net.get(name).cmd('pkill -f "server.py %s"' % name)


def burst(net, per_client=10):
    """Send concurrent HTTP requests from all three clients."""
    procs = []

    for client in ("h1", "h2", "h3"):
        for _ in range(per_client):
            procs.append(
                net.get(client).popen(
                    [
                        "sh",
                        "-c",
                        "curl -s -m 8 http://%s/ | head -n1" % VIP
                    ],
                    stdout=PIPE
                )
            )

    results = Counter()

    for proc in procs:
        output = proc.communicate()[0].decode().strip()
        results[output or "FAILED"] += 1

    return results


def show(title, results):
    print("\n== %s ==" % title)

    for result, count in sorted(results.items()):
        print("   %-20s %d" % (result, count))


def demo(net):
    print("\n[1] 30 concurrent requests, all servers healthy")
    show("Distribution", burst(net, 10))

    time.sleep(3)

    print("\n[2] Stopping the application on h5")
    stop_server(net, "h5")

    time.sleep(4)

    show("Distribution with h5 down", burst(net, 10))

    print("\n[3] Restarting h5")
    start_server(net, "h5")

    time.sleep(6)

    show("Distribution after recovery", burst(net, 10))

    print(
        "\nSee requests.log and the controller output "
        "for request logs, load, and failure events."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run automated tests, then open the Mininet CLI"
    )
    args = parser.parse_args()

    setLogLevel("info")

    net = build()
    net.start()

    try:
        for name in ("h4", "h5", "h6"):
            start_server(net, name)

        time.sleep(4)

        if args.demo:
            demo(net)

        CLI(net)

    finally:
        for name in ("h4", "h5", "h6"):
            stop_server(net, name)

        net.stop()