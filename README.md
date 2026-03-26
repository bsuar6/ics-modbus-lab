# ICS/OT Modbus Homelab — Anomaly Detection Lab

A hands-on ICS/OT security lab built from scratch on a Linux VM simulating a real industrial Modbus TCP environment. This lab covers PLC setup, protocol analysis, attack simulation, and custom anomaly detection — mapped to MITRE ATT&CK for ICS.

---

## Why This Lab

Modbus TCP is one of the most widely deployed industrial protocols in the world, used in water treatment plants, power grids, manufacturing, and oil and gas facilities. It was designed in 1979 with zero security in mind — no authentication, no encryption, no access control. Anyone on the network can send commands to a PLC.

This lab simulates that environment, establishes a traffic baseline, launches attack simulations, and builds a real-time anomaly detector to catch malicious activity — the core workflow of an ICS/OT security analyst.

---

## Environment

- **Host Machine:** macOS
- **VM:** Ubuntu 24.04 LTS running in Parallels
- **PLC Runtime:** OpenPLC v3 (open source software PLC)
- **Protocol:** Modbus TCP on port 502
- **Tools:** Wireshark, Scapy, pymodbus, Python 3

---

## Architecture
```
┌─────────────────────┐       Modbus TCP        ┌─────────────────────┐
│   Python Scripts    │ ────── port 502 ───────▶ │    OpenPLC v3       │
│ (client/attacker)   │                          │  (software PLC)     │
└─────────────────────┘                          └─────────────────────┘
          │                                                │
          ▼                                                ▼
┌─────────────────────┐                       ┌─────────────────────────┐
│  modbus_detector.py │                       │   webserver_program.st  │
│  (Scapy-based NIDS) │                       │   var_out := var_in     │
└─────────────────────┘                       └─────────────────────────┘
```

---

## Step 1 — Installing OpenPLC

OpenPLC is a free, open source PLC runtime that implements standard IEC 61131-3 programming languages. It exposes a real Modbus TCP server on port 502, making it ideal for ICS security labs without physical hardware.

### Installation
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git
git clone https://github.com/thiagoralves/OpenPLC_v3.git
cd OpenPLC_v3
./install.sh linux
```

The installer compiles the runtime, sets up the web interface, and installs all dependencies. This takes approximately 5-10 minutes.

### Starting OpenPLC
```bash
./start_openplc.sh
```

OpenPLC runs two services:
- **Port 8080** — Main web interface (HTTP) for managing programs, monitoring, and configuration
- **Port 8443** — REST API (HTTPS) for programmatic control
- **Port 502** — Modbus TCP server (starts when PLC program is running)

---

## Step 2 — Hardening the Lab Environment

Before doing anything else, the default OpenPLC configuration was hardened to reduce attack surface. This is standard practice in OT environments — even lab environments should reflect secure configuration principles.

### Problem 1: Web Interface Bound to All Interfaces

By default OpenPLC binds its web interface to `0.0.0.0`, meaning it is accessible from any device on the network. This is dangerous even in a lab.

**Fix:** Changed the bind address to `127.0.0.1` so the web interface is only accessible from within the VM itself.

Located the web server configuration file:
```bash
grep -rn "port=8443" ~/OpenPLC_v3/webserver/
```

Opened the file and changed:
```python
# Before
False, host='0.0.0.0', threaded=True, port=8443, ssl_context=context)

# After
False, host='127.0.0.1', threaded=True, port=8443, ssl_context=context)
```

**Why this matters:** Binding to `0.0.0.0` exposes the management interface to every device on the local network. An attacker with network access could interact with the PLC web interface, upload malicious programs, or modify configurations. Restricting to `127.0.0.1` ensures only local processes can reach it — a core principle of least privilege access.

### Problem 2: Default Credentials

OpenPLC ships with default credentials (`openplc`/`openplc`) that are publicly documented. Default credentials are one of the most common attack vectors in ICS environments.

**Fix:** Immediately changed the admin password after first login.

Navigation: **Settings → Users → openplc user → Change Password**

**Why this matters:** The 2021 Oldsmar water treatment plant attack involved an attacker gaining remote access to a SCADA system. While the exact vector was debated, default and weak credentials are a persistent critical vulnerability in OT environments per CISA advisories.

### Problem 3: Port Conflict

During setup, port 8443 was already in use by a Parallels system service. Attempting to kill the process caused the VM to restart because it was a system-managed process.

**Resolution:** Changed OpenPLC's web interface port to 8888 instead of killing a critical system process. This demonstrates an important OT security principle — understanding what is running on a system before taking action, as unplanned changes can cause unintended outages.
```bash
# Verified what was listening before making changes
sudo ss -tlnp | grep 8443
sudo lsof -i :8443
```

---

## Step 3 — Loading a PLC Program

A PLC program defines what the controller does. Without a program the PLC runs nothing and generates no Modbus traffic to analyze.

### The Program

Uploaded `webserver_program.st` — a simple Structured Text (IEC 61131-3) program:
```
PROGRAM prog0
  VAR
    var_in : BOOL;
    var_out : BOOL;
  END_VAR
  var_out := var_in;
END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK Main(INTERVAL := T#50ms, PRIORITY := 0);
    PROGRAM Inst0 WITH Main : prog0;
  END_RESOURCE
END_CONFIGURATION
```

**What it does:** Every 50 milliseconds it reads the value of `var_in` and copies it to `var_out`. This mimics a real PLC I/O loop — a sensor reading mapped to an output like a pump or valve.

**Modbus register mapping:**
| Variable | Type | Modbus Address | Function Code |
|----------|------|---------------|---------------|
| var_out | Coil | 0 | FC1 (read), FC5 (write) |
| var_in | Discrete Input | 0 | FC2 (read only) |

The program was uploaded through the web UI: **Programs → Upload Program → Compile**. Compilation converts the Structured Text into C code that runs on the OpenPLC runtime.

### Starting the PLC

Clicked **Start PLC** on the dashboard. Verified Modbus port 502 opened:
```bash
sudo ss -tlnp | grep 502
```

Output confirmed:
```
LISTEN 0  5  0.0.0.0:502  0.0.0.0:*  users:(("openplc",pid=26176,fd=5))
```

---

## Step 4 — Establishing Baseline Traffic

Before detecting attacks you must know what normal looks like. This is called **baselining** and is a foundational ICS security practice referenced in NIST SP 800-82.

### Installing pymodbus
```bash
pip install pymodbus --break-system-packages
```

### Basic Modbus Test

`modbus_test.py` sends three operations to the PLC and reads back results:
```python
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('127.0.0.1', port=502)
client.connect()

client.write_coil(0, True)           # FC5 - Write coil 0 ON
result = client.read_coils(0)         # FC1 - Read coil 0 back
result = client.read_discrete_inputs(0) # FC2 - Read discrete input 0

client.close()
```

### Continuous Baseline Loop

`modbus_loop.py` runs continuously, toggling coil 0 on and off every second to simulate normal SCADA polling behavior:
```python
while True:
    cycle += 1
    client.write_coil(0, cycle % 2 == 0)  # Toggle ON/OFF
    client.read_coils(0)
    client.read_discrete_inputs(0)
    time.sleep(1)
```

### Capturing Baseline with Wireshark

Installed Wireshark and captured loopback traffic with filter `modbus`.

**Baseline characteristics established:**
- Function codes present: **FC1, FC2, FC5 only**
- Write rate: **1 FC5 write per second**
- Coil addresses accessed: **address 0 only**
- Connection behavior: **clean open and close**
- Timing: **regular 1 second intervals**

This baseline becomes the detection ruleset for the anomaly detector.

### Screenshot — Baseline Traffic in Wireshark

![Baseline Traffic](screenshots/wireshark_baseline.png)

*Wireshark capture showing normal Modbus baseline traffic. FC5 Write Single Coil, FC1 Read Coils, and FC2 Read Discrete Inputs appear in a regular 1-second pattern, all targeting address 0. The packet detail pane shows Data: 0x0000 (coil OFF) on a Write Single Coil response. This predictable pattern is what legitimate SCADA polling looks like.*

---

## Step 5 — Attack Simulation

`modbus_attack.py` simulates four distinct attack patterns seen in real ICS malware and adversary activity.

### Modbus Protocol Background

Modbus TCP has no authentication mechanism. Any host with network access to port 502 can:
- Read any register or coil value
- Write to any coil or register
- Issue any function code

This is not a misconfiguration — it is how the protocol was designed. Security relies entirely on network segmentation, which is why the Purdue Model and IEC 62443 zone/conduit architecture exist.

**Modbus Function Codes:**
| FC | Name | Description |
|----|------|-------------|
| 1 | Read Coils | Read binary output status |
| 2 | Read Discrete Inputs | Read binary input status |
| 3 | Read Holding Registers | Read 16-bit output registers |
| 4 | Read Input Registers | Read 16-bit input registers |
| 5 | Write Single Coil | Set a single binary output |
| 6 | Write Single Register | Set a single 16-bit register |

### Anomaly 1 — Rapid Coil Writes
**MITRE ATT&CK for ICS: T0855 — Unauthorized Command Message**
```python
for i in range(20):
    client.write_coil(0, True)
    client.write_coil(0, False)
```

40 FC5 writes sent in under one second. In a real environment this rapidly cycles industrial equipment — motors, pumps, valves — on and off faster than mechanical systems are designed to handle, causing physical damage or destruction. This technique was used by the **Industroyer/Crashoverride malware** that attacked the Ukrainian power grid in December 2016, causing a blackout in Kyiv.

### Anomaly 2 — Coil Address Scanning
**MITRE ATT&CK for ICS: T0846 — Remote System Discovery**
```python
for addr in range(10):
    client.write_coil(addr, True)
```

Sequential FC5 writes to addresses 0 through 9. The PLC program only uses address 0 — writes to addresses 1-9 target undefined coils. In a real PLC these undefined addresses may map to physical outputs. This is reconnaissance — an attacker mapping what outputs they can control before launching a targeted destructive command.

### Anomaly 3 — Register Enumeration
**MITRE ATT&CK for ICS: T0801 — Monitor Process State**
```python
for addr in range(10):
    client.read_holding_registers(addr)
```

FC3 Read Holding Registers across sequential addresses. FC3 **never appears in the baseline traffic** — this PLC program uses no holding registers. Any FC3 packet is immediately anomalous. This is how attackers enumerate what process data (temperatures, pressures, flow rates) a PLC is storing before deciding how to manipulate it.

### Anomaly 4 — Dirty Disconnect
**MITRE ATT&CK for ICS: T0855 — Unauthorized Command Message**
```python
client.write_coil(0, True)
# No client.close() - connection dropped abruptly
```

Forces coil ON then drops the TCP connection without a clean FIN handshake. Legitimate SCADA software always closes connections cleanly. In Wireshark this appears as a TCP RST instead of a FIN/ACK exchange. The coil is left in an unknown forced state.

### Screenshot — Attack Traffic in Wireshark

![Attack Traffic](screenshots/wireshark_attack.png)

*Wireshark capture during attack simulation. The FC3 Read Holding Registers flood is clearly visible — sequential reads across addresses 0-9. FC3 was completely absent from baseline traffic, making every one of these packets immediately suspicious. The packet detail pane shows the full Modbus/TCP header dissection including Transaction ID, Unit ID, and function code. The rapid sequential timing (note timestamps) distinguishes this from legitimate polling.*

---

## Step 6 — Building the Anomaly Detector

`modbus_detector.py` is a passive network-based intrusion detection system (NIDS) purpose-built for Modbus TCP. It uses Scapy to capture live packets and applies three detection rules derived from the established baseline.

### Installation
```bash
sudo pip install scapy --break-system-packages
```

Note: Must install as root because the detector runs with `sudo` to access the network interface for raw packet capture.

### How It Works

**Packet capture:**
```python
sniff(
    iface="lo",          # Listen on loopback interface
    filter="tcp port 502", # BPF filter - only Modbus traffic
    prn=analyze_packet,  # Callback for each packet
    store=False          # Don't buffer packets in memory
)
```

Scapy uses Berkeley Packet Filter (BPF) at the kernel level — only Modbus packets are passed to the application. This is how Wireshark, tcpdump, and commercial IDS tools all work at their core.

**Modbus packet parsing:**
```python
def parse_modbus(payload):
    fc = payload[7]                              # Byte 7 = function code
    addr = struct.unpack('>H', payload[8:10])[0] # Bytes 8-9 = address
    return fc, addr
```

Modbus TCP has a fixed 7-byte header (MBAP header). The function code is always at byte offset 7, and the data address starts at byte 8. `struct.unpack('>H')` converts two bytes to a 16-bit unsigned integer in big-endian byte order — the format Modbus uses.

**Detection 1 — Unknown Function Code:**
```python
BASELINE_FC = {1, 2, 5}
if fc not in BASELINE_FC:
    alert(f"Unexpected Function Code FC{fc}")
```
Any function code not in the established baseline triggers an alert. Catches FC3 register enumeration immediately.

**Detection 2 — Rapid Write Rate (Sliding Window):**
```python
write_times.append(now)
write_times = [t for t in write_times if now - t < 1.0]
if len(write_times) > WRITE_RATE_LIMIT:
    alert(f"Rapid coil writes: {len(write_times)} FC5 writes in last second")
```
Maintains a sliding one-second window of FC5 write timestamps. If more than 5 writes occur within any one-second window an alert fires. This is the same sliding window algorithm used in Snort and Suricata rate-based detection rules.

**Detection 3 — Address Scanning:**
```python
written_addrs.add(addr)
if len(written_addrs) >= SCAN_THRESHOLD:
    alert(f"Coil scanning: writes to addresses {sorted(written_addrs)}")
```
Tracks unique coil addresses written to in a Python set (automatically deduplicates). When 3 or more distinct addresses have been written to, an alert fires. Writing to multiple addresses is not normal for a PLC with a single-address program.

### Running the Detector

Terminal 1:
```bash
sudo python3 ~/modbus_detector.py
```

Terminal 2:
```bash
python3 ~/modbus_attack.py
```

### Screenshot — Anomaly Detector Live Alerts

![Detector Alerts](screenshots/detector_alerts.png)

*Real-time output from the anomaly detector during attack simulation. Three detection rules fired simultaneously: (1) Rapid coil writes reaching 100 FC5 writes in one second against a threshold of 5, (2) Coil scanning detected across addresses 0-9, and (3) Unexpected FC3 function codes firing repeatedly as the register enumeration attack ran. The detector caught all attack patterns automatically with no human analysis required. At the bottom FC1 and FC2 packets from the baseline loop are visible — correctly passing through without alerts.*

---

## Screenshot — OpenPLC Dashboard

![OpenPLC Dashboard](screenshots/openplc_dashboard.png)

*OpenPLC v3 web interface showing the PLC in Running state executing the webserver program. The runtime logs confirm the full startup sequence: Modbus server started on port 502, DNP3 stopped, EtherNet/IP started on port 44818, and Snap7 server started. The log entry "Client accepted! Creating thread for new client ID: 3" shows the PLC actively accepting Modbus connections from the Python test scripts.*

---

## Detection Summary

| Attack | Technique | MITRE ID | Detected |
|--------|-----------|----------|---------|
| Rapid coil writes | Sliding window rate limit | T0855 | ✅ |
| Address scanning | Unique address tracking | T0846 | ✅ |
| Register enumeration | Baseline FC comparison | T0801 | ✅ |
| Dirty disconnect | TCP session analysis | T0855 | ⚠️ Partial |

---

## Key Security Findings

1. **Modbus TCP has no authentication** — any host with network access to port 502 can send arbitrary commands to a PLC with no credentials required

2. **Normal ICS traffic is highly predictable** — legitimate SCADA polling produces consistent function codes, addresses, and timing that is straightforward to baseline

3. **Attack traffic is clearly distinguishable** — anomalous function codes, high write rates, and sequential address scanning stand out immediately against a known baseline

4. **Passive detection has zero impact on operations** — the Scapy-based detector captures and analyzes packets without injecting any traffic or touching the PLC, critical for OT environments where availability is paramount

5. **Network segmentation is the primary control** — since Modbus cannot be secured at the protocol level, keeping it isolated to trusted network segments is the most important defensive measure

---

## Frameworks Referenced

- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
- [NIST SP 800-82 Rev 3](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final) — Guide to OT Security
- [IEC 62443](https://www.iec.ch/iec62443) — Industrial Cybersecurity Standard
- [OpenPLC Runtime](https://autonomylogic.com/)

---

## Next Steps

- [ ] Forward alerts to a SIEM (Wazuh or Splunk)
- [ ] Add DNP3 protocol monitoring
- [ ] Build detection rules in Zeek
- [ ] Export attack PCAPs for evidence preservation
- [ ] Extend to EtherNet/IP protocol (also running on this PLC on port 44818)
