# Network Topology Diagrams

## Logical Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         INTERNET                                 │
└────────────────────┬──────────────────────────────────────────────┘
                     │
              ┌──────▼──────┐
              │   ISP Modem  │
              │  (Bridge Mode)│
              └──────┬──────┘
                     │
              ┌──────▼──────┐
              │   pfSense    │  ← Firewall / Router / DHCP / IDS
              │    CE 2.7    │     5 VLAN interfaces + WAN
              │  10.10.10.1  │
              └──────┬──────┘
                     │
              ┌──────▼──────┐
              │  L2 Managed  │  ← VLAN trunk (802.1q)
              │    Switch     │     24-port Gigabit
              │  10.10.10.2  │
              └──────┬──────┘
                     │
      ┌──────────────┼──────────────┬──────────────┐
      │              │              │              │
  ┌───▼───┐    ┌────▼────┐   ┌────▼────┐   ┌────▼────┐
  │  AP-1  │    │  AP-2   │   │  AP-3   │   │ Server  │
  │Guest/BYOD│   │Clinical │   │ Medical │   │  Rack   │
  │ VLAN 40 │    │ VLAN 20 │   │ IoT VLAN│   │VLAN 10/20│
  │ 2.4+5GHz│    │ 5GHz only│   │ 2.4GHz  │   │         │
  └─────────┘    └─────────┘   └─────────┘   └─────────┘
```

## Detailed Mermaid Diagram

```mermaid
graph TB
    Internet["🌐 Internet"]
    ISP["📡 ISP Modem<br/>(Bridge Mode)"]
    FW["🛡️ pfSense CE 2.7<br/>10.10.10.1<br/>Firewall + DHCP + IDS"]
    SW["🔀 L2 Managed Switch<br/>10.10.10.2<br/>24-Port Gigabit<br/>802.1q Trunk"]

    subgraph VLAN_10["🔧 VLAN 10: Management<br/>10.10.10.0/24"]
        MGMT1["Firewall Web UI"]
        MGMT2["Switch Admin UI"]
        MGMT3["AP Admin Panels"]
        MGMT4["SIEM / Syslog VM<br/>10.10.10.10"]
    end

    subgraph VLAN_20["🏥 VLAN 20: Clinical<br/>10.10.20.0/24"]
        DOC1["Provider Workstation 1<br/>10.10.20.11"]
        DOC2["Provider Workstation 2<br/>10.10.20.12"]
        DOC3["Provider Tablet<br/>10.10.20.13"]
        NURSE["Nurse Station PC<br/>10.10.20.21"]
        EHR["EHR Server<br/>10.10.20.100"]
    end

    subgraph VLAN_30["💓 VLAN 30: Medical IoT<br/>10.10.30.0/24"]
        BP["BP Cuff (WiFi)<br/>10.10.30.51"]
        OX["Pulse Oximeter<br/>10.10.30.52"]
        EKG["EKG Monitor<br/>10.10.30.53"]
        IMAGING["Imaging Modality<br/>10.10.30.60"]
        IOT_GW["IoT Gateway<br/>10.10.30.1<br/>(Stateful Proxy)"]
    end

    subgraph VLAN_40["📱 VLAN 40: Guest / BYOD<br/>10.10.40.0/24"]
        GUEST1["Patient Phone"]
        GUEST2["Patient Laptop"]
        GUEST3["Personal Staff Phone"]
    end

    subgraph VLAN_50["💼 VLAN 50: Admin / Billing<br/>10.10.50.0/24"]
        BILL1["Billing Workstation<br/>10.10.50.11"]
        BILL2["Office Manager PC<br/>10.10.50.12"]
        PAYROLL["Payroll / HR Portal<br/>10.10.50.100"]
        INSURANCE["Insurance Clearinghouse<br/>10.10.50.101"]
    end

    Internet --> ISP
    ISP --> FW
    FW --> SW

    SW --> VLAN_10
    SW --> VLAN_20
    SW --> VLAN_30
    SW --> VLAN_40
    SW --> VLAN_50

    style VLAN_10 fill:#e1f5fe
    style VLAN_20 fill:#e8f5e9
    style VLAN_30 fill:#fff3e0
    style VLAN_40 fill:#ffebee
    style VLAN_50 fill:#f3e5f5
    style FW fill:#ffccbc
    style Internet fill:#fafafa
```

## Physical Layout (Clinic Floor Plan Reference)

```
┌─────────────────────────────────────────────────────────────┐
│                    VALLEY VIEW FAMILY MEDICINE                 │
│                         (3,200 sq ft)                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│   ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐   │
│   │ Exam 1  │    │ Exam 2  │    │ Exam 3  │    │  Lab   │   │
│   │(VLAN 20)│    │(VLAN 20)│    │(VLAN 20)│    │(VLAN 30)│   │
│   │ BP, OX  │    │ BP, OX  │    │ BP, OX  │    │ Imaging│   │
│   └────┬────┘    └────┬────┘    └────┬────┘    └────┬────┘   │
│        │              │              │              │         │
│        └──────────────┴──────────────┘              │         │
│                     │                              │         │
│   ┌──────────────────────────────────────────────────────┐  │
│   │              HALLWAY (AP-2: Clinical 5GHz)              │  │
│   │                    + AP-3: Medical IoT                  │  │
│   └──────────────────────────────────────────────────────┘  │
│        │              │              │              │         │
│   ┌────▼────┐    ┌────▼────┐    ┌────▼────┐    ┌────▼────┐   │
│   │Nurse Stn│    │ Provider│    │Provider │    │Provider │   │
│   │(VLAN 20)│    │ Office 1│    │ Office 2│    │ Office 3│   │
│   │         │    │(VLAN 20)│    │(VLAN 20)│    │(VLAN 20)│   │
│   └─────────┘    └─────────┘    └─────────┘    └─────────┘   │
│                                                               │
│   ┌──────────────────────────────────────────────────────┐    │
│   │              WAITING ROOM / RECEPTION                  │    │
│   │          (AP-1: Guest/BYOD 2.4GHz + 5GHz)            │    │
│   │                                                        │    │
│   │   [Front Desk] ──(VLAN 20 + VLAN 50 shared jack)───  │    │
│   │                                                        │    │
│   └──────────────────────────────────────────────────────┘    │
│                                                               │
│   ┌──────────────────┐      ┌──────────────────────────────┐ │
│   │   ADMIN OFFICE   │      │      SERVER / IT CLOSET      │ │
│   │  (VLAN 50 only)  │      │   (VLAN 10 + Mgmt Switch)  │ │
│   │  Billing + HR    │      │   Firewall + SIEM + Rack     │ │
│   └──────────────────┘      └──────────────────────────────┘ │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Traffic Flow Summary

| Source Zone | Destination Zone | Allowed? | Path / Justification |
|-------------|-----------------|----------|---------------------|
| Clinical (20) | EHR Server (20) | ✅ Yes | Direct L2 within VLAN — no firewall traversal needed |
| Clinical (20) | Medical IoT (30) | ✅ Yes | tcp/443 only to IoT Gateway (10.10.30.1) for device data ingest |
| Medical IoT (30) | Clinical (20) | ❌ No | Devices are data producers, not consumers. Prevents lateral movement. |
| Guest (40) | Any internal RFC1918 | ❌ No | Internet-only. DNS + DHCP only. |
| Admin (50) | EHR Server (20) | ✅ Yes | tcp/443 via firewall + bastion jump host. RBAC enforced at EHR app layer. |
| Any | Management (10) | ❌ No | Mgmt VLAN is "out of band" — physical switchport access only. |
| All zones | Internet | ✅ Yes | NAT + stateful inspection. Egress filtering applies (see firewall-rules.md). |

## Key Design Decisions

1. **Medical IoT Gateway (10.10.30.1)** — Not a router; a **stateful application-layer proxy**. IoT devices push data to the gateway over mTLS. The gateway forwards aggregated, normalized data to the EHR server. Devices never initiate sessions directly to VLAN 20.

2. **Management VLAN is "air-gapped" logically** — No routing from any user VLAN into VLAN 10. Administrative access requires physically plugging into a dedicated switchport or connecting via a VPN concentrator on a separate interface.

3. **Front Desk Dual-VLAN** — The front-desk jack is an **802.1x port** with dynamic VLAN assignment. If the device authenticates as a domain-joined clinical workstation → VLAN 20. If unknown/unauthenticated → VLAN 40 (guest). Prevents accidental clinical data leakage from personal devices.
