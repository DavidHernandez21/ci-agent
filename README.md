# CI Agent

eBPF-based egress audit tool for CI environments. Captures outbound network connections with executable paths and DNS hostnames.

## Usage

```bash
make                                    # Build
sudo ./ci-agentd                        # Run daemon (no filters)
sudo ./ci-agentd --proto tcp            # Filter by protocol
sudo ./ci-agentd --pid 1234             # Filter by pid
sudo ./ci-agentd --exe curl             # Filter by executable substring
sudo ./ci-agentd --dst 1.1.1.1          # Filter by destination IP
sudo ./ci-agentd --src local            # Match loopback (127.0.0.0/8, ::1)
sudo ./ci-agentd --no-local-src         # Exclude loopback source traffic
sudo ./ci-agentd --no-local-dst         # Exclude loopback destination traffic
sudo ./ci-agentd --no-port 22           # Exclude events with port 22 (src or dst)
nc -U /run/ci-agent.sock                # View logs (in another terminal)
dig google.com                          # Test DNS capture
curl https://www.github.com             # Generate traffic
```
