# 📡 WiFi Security Analyzer — ESP8266/ESP32 Tool

> **Career Stage:** OT Cybersecurity Engineer  
> **Author:** Mohammed Satar (HBLACKH0)  
> **Hardware:** ESP8266 / ESP32 | Custom PCB | OLED Display  
> **Instagram:** [@hblackh0](https://www.instagram.com/hblackh0/)

---

## 📋 Overview

A **portable 2.4GHz WiFi security analysis tool** built on a custom PCB with:
- ESP8266/ESP32 microcontroller
- 0.96" OLED display (128×64)
- 4 navigation buttons
- USB-C power input
- Web interface (access via phone or browser)

This project was built from scratch — including the **custom PCB design** and **firmware**.

> 🔒 **Educational Purpose Only** — This tool is intended for use on networks you own or have explicit permission to test.  
> Relevant to: **OT/ICS Cybersecurity**, **Industrial Network Security**, **Wireless Protocol Analysis**

---

## 📷 Hardware Demo

```
┌─────────────────────────────────┐
│  ┌─────────────────────────┐    │
│  │  CH:10  PKts:151        │    │
│  │  ████████░░  Scanning   │    │
│  │  APs: 8   Stations: 3   │    │
│  └─────────────────────────┘    │
│                                 │
│  [▲ UP]  [▼ DN]  [OK] [BACK]   │
└─────────────────────────────────┘
   Custom PCB — ESP8266 + OLED
```

---

## ⚡ Features

| Feature | Description |
|---------|-------------|
| 📊 **WiFi Scanner** | Scan all 2.4GHz channels (1-14), list APs & STAs |
| 📦 **Packet Monitor** | Count packets per channel, show RSSI |
| 📡 **Channel Analyzer** | Display channel usage, interference map |
| 🌐 **Web Interface** | Control via browser (STA or AP mode) |
| 💾 **Data Logging** | Log scan results to SPIFFS/SD |
| ⚙️ **Settings Menu** | Configure via OLED menu system |

---

## 🔧 Hardware

```
Components:
- ESP8266 (NodeMCU / Wemos D1 Mini) or ESP32
- OLED Display: 0.96" SSD1306 (I2C, 128×64)
- 4x Tactile push buttons
- Custom PCB (designed in KiCad)
- USB-C connector (5V input)
- 3.7V LiPo battery + TP4056 charger (optional)
- LED status indicator

Pin Connections (ESP8266):
  OLED SDA  → D2 (GPIO4)
  OLED SCL  → D1 (GPIO5)
  BTN_UP    → D3 (GPIO0)
  BTN_DOWN  → D4 (GPIO2)
  BTN_OK    → D5 (GPIO14)
  BTN_BACK  → D6 (GPIO12)
  LED_STATUS → D7 (GPIO13)
```

---

## 📁 Project Structure

```
wifi-security-analyzer/
├── firmware/
│   ├── wifi_analyzer.ino      # Main firmware (Arduino)
│   ├── display_manager.h      # OLED menu system
│   ├── wifi_scanner.h         # WiFi scanning functions
│   ├── web_interface.h        # Web server / API
│   └── config.h               # Pin definitions
├── hardware/
│   ├── schematic.pdf          # Circuit schematic
│   ├── pcb_layout.png         # PCB layout preview
│   └── bom.csv                # Bill of materials
├── web/
│   ├── index.html             # Web dashboard
│   └── style.css              # Dashboard styling
└── README.md
```

---

## 🚀 Quick Start

### 1. Flash Firmware
```bash
# Install Arduino IDE + ESP8266 board package
# Board: "LOLIN(WeMos) D1 R2 & mini" or "NodeMCU 1.0"
# Flash Speed: 115200
# Open firmware/wifi_analyzer.ino and upload
```

### 2. Connect
```bash
# Device creates WiFi AP: "WiFiAnalyzer"
# Password: "analyzer123"
# Open browser: http://192.168.4.1
```

### 3. Navigate with Buttons
```
UP/DOWN   → Navigate menu
OK        → Select / confirm
BACK      → Go back / cancel
Long BACK → Return to main menu
```

---

## 🔐 OT Cybersecurity Context

This tool is relevant to **Operational Technology (OT) Security** in industrial environments:

| Industrial Use | How This Tool Helps |
|---------------|---------------------|
| **Rogue AP Detection** | Identify unauthorized access points in plant WiFi |
| **Industrial WiFi Audit** | Verify WPA2-Enterprise on SCADA HMI systems |
| **ISA/IEC 62443** | Support wireless security assessment per standard |
| **Packet Analysis** | Baseline traffic patterns for anomaly detection |

---

## 📜 Legal Notice

> This tool must only be used on networks you own or have written authorization to test.  
> Unauthorized network scanning is illegal in most jurisdictions.

---

## 📜 License

MIT License — Mohammed Satar (HBLACKH0), 2024  
🔗 Instagram: [@hblackh0](https://www.instagram.com/hblackh0/)
