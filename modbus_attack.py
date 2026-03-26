from pymodbus.client import ModbusTcpClient
import time

client = ModbusTcpClient('127.0.0.1', port=502)
client.connect()

print("[*] Starting anomalous Modbus activity...")

# 1. Rapid coil writes - abnormal write frequency
print("[!] ANOMALY 1: Rapid coil writes")
for i in range(20):
    client.write_coil(0, True)
    client.write_coil(0, False)

# 2. Writing to unexpected coil addresses - recon/scanning behavior
print("[!] ANOMALY 2: Scanning coil addresses 0-10")
for addr in range(10):
    client.write_coil(addr, True)
    time.sleep(0.1)

# 3. Read all registers - enumeration behavior
print("[!] ANOMALY 3: Enumerating holding registers")
for addr in range(10):
    client.read_holding_registers(addr)
    time.sleep(0.1)

# 4. Force coil to dangerous state and leave it
print("[!] ANOMALY 4: Forcing coil ON and abandoning connection")
client.write_coil(0, True)

# Don't close cleanly - just drop
print("[*] Done. Connection dropped.")
