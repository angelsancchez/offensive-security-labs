## Use Case: DCSync Attack

### Query
index=wineventlog EventCode=4662 
| search "Replicating Directory Changes"

### Qué detecta
- Acceso a replicación de Active Directory

### Por qué importa
- Robo de hashes del dominio

### Relación con lab
- Forest
