graph TB
    subgraph WAN["Internet"]
        ISP["ISP / Modem"]
    end

    subgraph EDGE["Edge Firewall (OPNsense)"]
        FW["pfSense/OPNsense<br/>L3 Gateway + IDS/IPS"]
        DMZ["DMZ Segment<br/>10.254.0.0/24"]
    end

    subgraph CORE["Core Switch (L3)"]
        SW["L3 Switch<br/>Inter-VLAN Routing<br/>ACLs + Port Security"]
    end

    subgraph VLAN10["VLAN 10 — Admin/IT (10.10.0.0/24)"]
        AD1["Admin PC 1<br/>10.10.0.11"]
        AD2["Admin PC 2<br/>10.10.0.12"]
        SRV_ADMIN["Jump Host / AD<br/>10.10.0.10"]
    end

    subgraph VLAN20["VLAN 20 — Clinical / PHI (10.20.0.0/24)"]
        EHR1["EHR Workstation 1<br/>10.20.0.21"]
        EHR2["EHR Workstation 2<br/>10.20.0.22"]
        LAB["Lab Interface PC<br/>10.20.0.23"]
        EHR_SRV["EHR Server<br/>10.20.0.10"]
    end

    subgraph VLAN30["VLAN 30 — Medical IoT (10.30.0.0/24)"]
        MON["Patient Monitor<br/>10.30.0.31"]
        PUMP["Infusion Pump<br/>10.30.0.32"]
        IMAG["Imaging DICOM<br/>10.30.0.33"]
        IOT_GW["IoT Gateway<br/>10.30.0.1"]
    end

    subgraph VLAN40["VLAN 40 — Guest WiFi (10.40.0.0/24)"]
        G1["Patient Phone"]
        G2["Visitor Laptop"]
        G3["Guest Tablet"]
    end

    subgraph VLAN50["VLAN 50 — Security / Logs (10.50.0.0/24)"]
        SIEM["SIEM / Wazuh<br/>10.50.0.10"]
        NIDS["NIDS Sensor<br/>10.50.0.11"]
        LOG["Syslog Collector<br/>10.50.0.12"]
    end

    subgraph VLAN100["VLAN 100 — Management (10.100.0.0/24)"]
        MGT_SW["Switch Mgmt<br/>10.100.0.2"]
        MGT_FW["Firewall Mgmt<br/>10.100.0.1"]
        MGT_AP["AP Mgmt<br/>10.100.0.3"]
    end

    ISP --> FW
    FW --> DMZ
    FW --> SW

    SW --> VLAN10
    SW --> VLAN20
    SW --> VLAN30
    SW --> VLAN40
    SW --> VLAN50
    SW --> VLAN100

    DMZ -.->|"HIDS logs"| VLAN50
    VLAN10 -.->|"Mgmt"| VLAN100
    VLAN20 -.->|"EHR TLS 443"| DMZ
    VLAN30 -.->|"IoT telemetry"| IOT_GW
    IOT_GW -.->|"Filtered"| VLAN20
    VLAN50 -.->|"Mirror / TAP"| SW
