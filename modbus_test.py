from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('127.0.0.1', port=502)
client.connect()

# Write TRUE to coil 0 (var_out)
client.write_coil(0, True)
print("Written TRUE to coil 0")

# Read coil 0 back
result = client.read_coils(0)
print(f"Coil 0 value: {result.bits[0]}")

# Read discrete input 0 (var_in)
result = client.read_discrete_inputs(0)
print(f"Discrete Input 0 value: {result.bits[0]}")

client.close()
print("Done.")
