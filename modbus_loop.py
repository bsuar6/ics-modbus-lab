from pymodbus.client import ModbusTcpClient
import time

client = ModbusTcpClient('127.0.0.1', port=502)
client.connect()

print("Starting continuous Modbus polling... Ctrl+C to stop")

cycle = 0
while True:
    cycle += 1
    
    # Toggle coil on/off every cycle
    client.write_coil(0, cycle % 2 == 0)
    
    # Read coil back
    result = client.read_coils(0)
    print(f"Cycle {cycle} | Coil 0: {result.bits[0]}")
    
    # Read discrete input
    result = client.read_discrete_inputs(0)
    print(f"Cycle {cycle} | Discrete Input 0: {result.bits[0]}")
    
    time.sleep(1)

client.close()
