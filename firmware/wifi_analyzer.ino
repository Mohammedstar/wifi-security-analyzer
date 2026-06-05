/*
 * =========================================================
 * WiFi Security Analyzer — ESP8266 Firmware
 * =========================================================
 * Author:   Mohammed Satar (HBLACKH0)
 * Hardware: ESP8266 + SSD1306 OLED + 4 Buttons (Custom PCB)
 * Version:  2.4
 *
 * Features:
 *  - WiFi AP/Station scanner (all 2.4GHz channels 1-14)
 *  - Packet monitor with per-channel packet counting
 *  - Channel analyzer (RSSI heatmap per channel)
 *  - OLED menu navigation (4 buttons)
 *  - Web interface (STA mode or AP mode)
 *  - JSON API for external tools
 *
 * OT Security relevance:
 *  - Rogue AP detection in industrial facilities
 *  - ISA/IEC 62443 wireless security assessments
 *  - Baseline wireless traffic profiling
 * =========================================================
 */

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <ArduinoJson.h>
#include "config.h"
#include "display_manager.h"
#include "wifi_scanner.h"

// ─── OLED Setup ──────────────────────────────────────────
#define SCREEN_W 128
#define SCREEN_H 64
Adafruit_SSD1306 oled(SCREEN_W, SCREEN_H, &Wire, -1);

// ─── Web Server ──────────────────────────────────────────
ESP8266WebServer server(80);

// ─── Menu System ─────────────────────────────────────────
enum MenuState {
  MENU_MAIN,
  MENU_SCANNER,
  MENU_PACKET_MONITOR,
  MENU_CHANNEL_ANALYZER,
  MENU_SETTINGS,
  MENU_AP_DETAILS,
};

const char* mainMenuItems[] = {
  "WiFi Scanner",
  "Packet Monitor",
  "Channel Analyzer",
  "Settings",
};
const int MAIN_MENU_COUNT = 4;

MenuState currentMenu = MENU_MAIN;
int       menuCursor  = 0;
int       selectedAP  = 0;

// ─── Button State ────────────────────────────────────────
bool btnUp, btnDown, btnOK, btnBack;
bool lastBtnUp, lastBtnDown, lastBtnOK, lastBtnBack;
unsigned long lastButtonTime = 0;
const unsigned long DEBOUNCE_MS = 50;

// ─── Scanner Data ────────────────────────────────────────
struct APInfo {
  String ssid;
  uint8_t bssid[6];
  int32_t rssi;
  int     channel;
  uint8_t encType;
  bool    hidden;
};

APInfo apList[32];
int    apCount = 0;

// Packet counts per channel (1-14)
volatile uint32_t channelPackets[15] = {0};
int currentScanChannel = 1;
unsigned long lastChannelSwitch = 0;
const unsigned long CHANNEL_DWELL_MS = 200; // 200ms per channel

// ─────────────────────────────────────────────────────────
// WiFi Promiscuous Mode callback (packet sniffer)
// Counts packets per channel without decryption
// ─────────────────────────────────────────────────────────
struct RxPacketHeader {
  int16_t buf_len;
  uint8_t buf[];
};

void ICACHE_RAM_ATTR packetSnifferCallback(uint8_t *buf, uint16_t len) {
  if (currentScanChannel >= 1 && currentScanChannel <= 14) {
    channelPackets[currentScanChannel]++;
  }
}

// ─────────────────────────────────────────────────────────
// BUTTON READING with debounce
// ─────────────────────────────────────────────────────────
void readButtons() {
  if (millis() - lastButtonTime < DEBOUNCE_MS) return;
  lastButtonTime = millis();

  bool rawUp   = (digitalRead(BTN_UP)   == LOW);
  bool rawDown = (digitalRead(BTN_DOWN) == LOW);
  bool rawOK   = (digitalRead(BTN_OK)   == LOW);
  bool rawBack = (digitalRead(BTN_BACK) == LOW);

  btnUp   = rawUp   && !lastBtnUp;
  btnDown = rawDown && !lastBtnDown;
  btnOK   = rawOK   && !lastBtnOK;
  btnBack = rawBack && !lastBtnBack;

  lastBtnUp   = rawUp;
  lastBtnDown = rawDown;
  lastBtnOK   = rawOK;
  lastBtnBack = rawBack;
}

// ─────────────────────────────────────────────────────────
// WIFI SCANNING
// ─────────────────────────────────────────────────────────
void performWifiScan() {
  oled.clearDisplay();
  oled.setTextSize(1);
  oled.setCursor(0, 0);
  oled.println("Scanning...");
  oled.display();

  int n = WiFi.scanNetworks(false, true); // include hidden
  apCount = min(n, 32);

  for (int i = 0; i < apCount; i++) {
    apList[i].ssid    = WiFi.SSID(i);
    apList[i].rssi    = WiFi.RSSI(i);
    apList[i].channel = WiFi.channel(i);
    apList[i].encType = WiFi.encryptionType(i);
    apList[i].hidden  = (WiFi.SSID(i).length() == 0);
    WiFi.BSSID(i, apList[i].bssid);
  }
  WiFi.scanDelete();
}

// ─────────────────────────────────────────────────────────
// DISPLAY FUNCTIONS
// ─────────────────────────────────────────────────────────
void drawMainMenu() {
  oled.clearDisplay();
  oled.setTextSize(1);
  oled.setCursor(0, 0);
  oled.println("=WiFi Analyzer 2.4=");

  for (int i = 0; i < MAIN_MENU_COUNT; i++) {
    oled.setCursor(0, 12 + i * 12);
    if (i == menuCursor) {
      oled.print("> ");
    } else {
      oled.print("  ");
    }
    oled.println(mainMenuItems[i]);
  }
  oled.display();
}

void drawScannerResults() {
  oled.clearDisplay();
  oled.setTextSize(1);
  oled.setCursor(0, 0);
  oled.print("APs: "); oled.print(apCount);
  oled.print(" CH:"); oled.println(currentScanChannel);
  oled.drawLine(0, 9, 127, 9, WHITE);

  int startIdx = (selectedAP / 3) * 3;
  for (int i = startIdx; i < min(startIdx + 4, apCount); i++) {
    oled.setCursor(0, 12 + (i - startIdx) * 12);
    if (i == selectedAP) oled.print(">");
    else oled.print(" ");

    String ssid = apList[i].hidden ? "[Hidden]" : apList[i].ssid;
    if (ssid.length() > 9) ssid = ssid.substring(0, 9);
    oled.print(ssid);
    oled.print(" ");
    oled.print(apList[i].rssi);
    oled.print("dB");
  }
  oled.display();
}

void drawPacketMonitor() {
  oled.clearDisplay();
  oled.setTextSize(1);
  oled.setCursor(0, 0);
  oled.print("CH:"); oled.print(currentScanChannel);
  oled.print(" PKts:");
  oled.println(channelPackets[currentScanChannel]);
  oled.drawLine(0, 9, 127, 9, WHITE);

  // Bar chart of packets per channel (1-14)
  uint32_t maxPkts = 1;
  for (int i = 1; i <= 13; i++) maxPkts = max(maxPkts, channelPackets[i]);

  for (int ch = 1; ch <= 13; ch++) {
    int x = (ch - 1) * 9 + 2;
    int barH = (channelPackets[ch] * 40) / maxPkts;
    oled.drawRect(x, 54 - barH, 7, barH, WHITE);
    if (ch == currentScanChannel) oled.fillRect(x, 54 - barH, 7, barH, WHITE);
  }

  oled.setCursor(0, 56);
  oled.print("1  2  3  4  5  6  7 ...");
  oled.display();
}

void drawAPDetails(int idx) {
  if (idx >= apCount) return;
  oled.clearDisplay();
  oled.setTextSize(1);

  String enc;
  switch (apList[idx].encType) {
    case ENC_TYPE_WEP:  enc = "WEP"; break;
    case ENC_TYPE_TKIP: enc = "WPA"; break;
    case ENC_TYPE_CCMP: enc = "WPA2"; break;
    case ENC_TYPE_NONE: enc = "OPEN"; break;
    default:            enc = "WPA3"; break;
  }

  oled.setCursor(0, 0);
  oled.println(apList[idx].hidden ? "[Hidden Network]" : apList[idx].ssid);
  oled.drawLine(0, 9, 127, 9, WHITE);
  oled.setCursor(0, 12);
  oled.print("BSSID: ");
  char bssidStr[18];
  snprintf(bssidStr, sizeof(bssidStr), "%02X:%02X:%02X:%02X:%02X:%02X",
           apList[idx].bssid[0], apList[idx].bssid[1], apList[idx].bssid[2],
           apList[idx].bssid[3], apList[idx].bssid[4], apList[idx].bssid[5]);
  oled.println(bssidStr);
  oled.print("CH: "); oled.print(apList[idx].channel);
  oled.print("  RSSI: "); oled.print(apList[idx].rssi); oled.println("dB");
  oled.print("Security: "); oled.println(enc);

  // RSSI bar
  int rssiBar = map(apList[idx].rssi, -100, -30, 0, 80);
  rssiBar = constrain(rssiBar, 0, 80);
  oled.print("Signal: [");
  for (int i = 0; i < 10; i++) {
    oled.print(i < (rssiBar / 8) ? "=" : " ");
  }
  oled.println("]");
  oled.display();
}

// ─────────────────────────────────────────────────────────
// WEB SERVER API
// ─────────────────────────────────────────────────────────
void handleRoot() {
  String html = F(
    "<!DOCTYPE html><html><head>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>WiFi Analyzer</title>"
    "<style>body{background:#111;color:#0f0;font-family:monospace;padding:20px}"
    "h1{color:#0ff}.card{background:#1a1a1a;border:1px solid #0f0;padding:15px;margin:10px 0;border-radius:8px}"
    ".badge-open{color:#f00}.badge-wpa2{color:#0f0}.badge-wpa{color:#ff0}"
    "table{width:100%;border-collapse:collapse}td,th{padding:8px;border:1px solid #333;text-align:left}"
    "th{background:#0f0;color:#000}</style></head><body>"
    "<h1>&#128225; WiFi Security Analyzer</h1>"
    "<div class='card'>"
    "<p>Device: ESP8266 Custom PCB | Author: Mohammed Satar (HBLACKH0)</p>"
    "<button onclick='scan()' style='background:#0f0;color:#000;padding:10px;border:none;cursor:pointer'>Scan Now</button>"
    "</div>"
    "<div class='card'><h2>Detected Networks</h2>"
    "<div id='results'>Loading...</div></div>"
    "<div class='card'><h2>Packet Monitor</h2>"
    "<div id='packets'>Loading...</div></div>"
    "<script>"
    "function scan(){fetch('/api/scan').then(r=>r.json()).then(d=>{"
    "let html='<table><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>RSSI</th><th>Security</th></tr>';"
    "d.aps.forEach(ap=>{"
    "let cls=ap.enc=='OPEN'?'badge-open':ap.enc=='WPA2'?'badge-wpa2':'badge-wpa';"
    "html+=`<tr><td>${ap.ssid||'[Hidden]'}</td><td>${ap.bssid}</td><td>${ap.channel}</td>"
    "<td>${ap.rssi}dBm</td><td class='${cls}'>${ap.enc}</td></tr>`;"
    "});html+='</table>';"
    "document.getElementById('results').innerHTML=html;});}"
    "function updatePackets(){fetch('/api/packets').then(r=>r.json()).then(d=>{"
    "let html='<table><tr><th>CH</th><th>Packets</th><th>Activity</th></tr>';"
    "d.channels.forEach((p,i)=>{"
    "if(i===0)return;"
    "let bar=''.padStart(Math.min(Math.round(p/10),20),'█');"
    "html+=`<tr><td>${i}</td><td>${p}</td><td style='color:#0f0'>${bar}</td></tr>`;"
    "});html+='</table>';"
    "document.getElementById('packets').innerHTML=html;});}"
    "scan();setInterval(updatePackets,1000);"
    "</script></body></html>"
  );
  server.send(200, "text/html", html);
}

void handleApiScan() {
  performWifiScan();
  StaticJsonDocument<4096> doc;
  JsonArray aps = doc.createNestedArray("aps");

  for (int i = 0; i < apCount; i++) {
    JsonObject ap = aps.createNestedObject();
    ap["ssid"]    = apList[i].ssid;
    char bssidStr[18];
    snprintf(bssidStr, sizeof(bssidStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             apList[i].bssid[0], apList[i].bssid[1], apList[i].bssid[2],
             apList[i].bssid[3], apList[i].bssid[4], apList[i].bssid[5]);
    ap["bssid"]   = bssidStr;
    ap["rssi"]    = apList[i].rssi;
    ap["channel"] = apList[i].channel;
    const char* encNames[] = {"AUTO","WEP","TKIP","","CCMP","","","NONE"};
    ap["enc"]     = apList[i].encType < 8 ? encNames[apList[i].encType] : "UNK";
  }
  doc["count"] = apCount;

  String response;
  serializeJson(doc, response);
  server.send(200, "application/json", response);
}

void handleApiPackets() {
  StaticJsonDocument<512> doc;
  JsonArray channels = doc.createNestedArray("channels");
  for (int i = 0; i <= 14; i++) channels.add(channelPackets[i]);
  doc["current_channel"] = currentScanChannel;

  String response;
  serializeJson(doc, response);
  server.send(200, "application/json", response);
}

// ─────────────────────────────────────────────────────────
// SETUP
// ─────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);

  // Initialize OLED
  Wire.begin(SDA_PIN, SCL_PIN);
  if (!oled.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println("ERROR: OLED init failed");
    while (1);
  }
  oled.clearDisplay();
  oled.setTextSize(2);
  oled.setCursor(10, 15);
  oled.println("HBLACKH0");
  oled.setTextSize(1);
  oled.setCursor(20, 40);
  oled.println("WiFi Analyzer 2.4");
  oled.display();
  delay(2000);

  // Button pins
  pinMode(BTN_UP,   INPUT_PULLUP);
  pinMode(BTN_DOWN, INPUT_PULLUP);
  pinMode(BTN_OK,   INPUT_PULLUP);
  pinMode(BTN_BACK, INPUT_PULLUP);
  pinMode(LED_STATUS, OUTPUT);

  // WiFi: start as Access Point
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID, AP_PASS);
  Serial.print("AP IP: "); Serial.println(WiFi.softAPIP());

  // Enable promiscuous mode for packet monitoring
  wifi_set_opmode(STATION_MODE);
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(packetSnifferCallback);
  wifi_promiscuous_enable(1);
  wifi_set_channel(1);

  // Setup web server
  server.on("/",            handleRoot);
  server.on("/api/scan",    handleApiScan);
  server.on("/api/packets", handleApiPackets);
  server.begin();

  digitalWrite(LED_STATUS, HIGH);
  Serial.println("WiFi Analyzer ready!");
}

// ─────────────────────────────────────────────────────────
// MAIN LOOP
// ─────────────────────────────────────────────────────────
void loop() {
  server.handleClient();
  readButtons();

  // Cycle through channels for packet monitoring
  if (millis() - lastChannelSwitch >= CHANNEL_DWELL_MS) {
    lastChannelSwitch = millis();
    currentScanChannel++;
    if (currentScanChannel > 13) currentScanChannel = 1;
    wifi_set_channel(currentScanChannel);
  }

  // ── Menu Navigation ──────────────────────────────────
  switch (currentMenu) {

    case MENU_MAIN:
      drawMainMenu();
      if (btnUp   && menuCursor > 0)              menuCursor--;
      if (btnDown && menuCursor < MAIN_MENU_COUNT - 1) menuCursor++;
      if (btnOK) {
        switch (menuCursor) {
          case 0: performWifiScan(); currentMenu = MENU_SCANNER; break;
          case 1: currentMenu = MENU_PACKET_MONITOR; break;
          case 2: currentMenu = MENU_CHANNEL_ANALYZER; break;
          case 3: currentMenu = MENU_SETTINGS; break;
        }
      }
      break;

    case MENU_SCANNER:
      drawScannerResults();
      if (btnUp   && selectedAP > 0) selectedAP--;
      if (btnDown && selectedAP < apCount - 1) selectedAP++;
      if (btnOK)   currentMenu = MENU_AP_DETAILS;
      if (btnBack) { currentMenu = MENU_MAIN; menuCursor = 0; }
      break;

    case MENU_AP_DETAILS:
      drawAPDetails(selectedAP);
      if (btnBack) currentMenu = MENU_SCANNER;
      break;

    case MENU_PACKET_MONITOR:
      drawPacketMonitor();
      if (btnBack) { currentMenu = MENU_MAIN; menuCursor = 1; }
      break;

    default:
      currentMenu = MENU_MAIN;
      break;
  }

  delay(50);
}
