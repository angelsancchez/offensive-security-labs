## Use Case: Reverse Shell

### Query
index=sysmon process_name=nc OR process_name=bash 
| stats count by dest_ip, dest_port

### Qué detecta
- Conexiones salientes sospechosas

### Por qué importa
- Posible shell remota

### Relación con lab
- TODOS
