# Adaptive Load Balancer

A project that distributes HTTP-over-TCP connections across three backend servers using Ryu, Mininet, and OpenFlow 1.3. Clients connect to a single virtual IP at `10.0.0.100:80`.

```text
h1, h2, h3 (clients) -- s1 (Open vSwitch) -- h4, h5, h6 (TCP servers)
                             |
                         Ryu controller
```

## How it works

- The controller selects a backend for each new TCP flow and installs forwarding and address-rewrite rules in both directions.
- The adaptive score combines the number of tracked flows and the measured throughput on each backend's switch port. Active flow count is a proxy for server load.
- The controller prefers healthy backends below the overload thresholds. A backend is marked overloaded at 10 tracked flows or 8 Mbps and recovers once both measurements fall below their lower thresholds.
- TCP health probes and switch link events detect failures. The controller removes rules for a failed backend and excludes it from new assignments. A successful TCP probe can return it to rotation.
- The demo launches 30 concurrent requests from three clients in each phase. It tests normal operation, an application failure on `h5`, and recovery after restarting `h5`.

## Run the lab

Use a Linux machine or Linux VM with Docker, Mininet, Open vSwitch, Python 3, and curl. Run both terminals on the same Linux machine, from the repository directory. See the [Mininet installation guide](https://mininet.org/download/) and the [Ryu documentation](https://ryu.readthedocs.io/en/latest/getting_started.html).

In the first terminal, build and start the controller.

```bash
docker build -t adaptive-lb-ryu .
docker run --rm --network host --volume "$PWD:/app" adaptive-lb-ryu \
  ryu-manager --ofp-tcp-listen-port 6653 lb_controller.py
```

In the second terminal, start the topology and run the demo.

```bash
sudo python3 topo.py --demo
```

The demo prints backend counts and opens the Mininet CLI. Run `h1 curl -s http://10.0.0.100/ | head -n 1` there for a manual request. Type `exit` to stop the topology, then press Ctrl+C in the controller terminal. The controller prints load and health events and appends request decisions to `requests.log`.

## Static versus adaptive comparison

The supplied controller implements adaptive balancing. A static baseline and comparison measurements are still pending. For a comparison, run a static round-robin baseline and the adaptive controller with the same topology, link speeds, request count, and failure timing. Record per-backend responses, failed requests, and, if measured, response latency under each policy.
