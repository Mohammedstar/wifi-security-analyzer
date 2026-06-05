/*
 * config.h - WiFi Security Analyzer Configuration
 * Author: Mohammed Satar (HBLACKH0)
 */
#pragma once

// ─── OLED PINS (I2C) ─────────────────────────────────────
#define SDA_PIN   4   // GPIO4 (D2 on NodeMCU)
#define SCL_PIN   5   // GPIO5 (D1 on NodeMCU)

// ─── BUTTON PINS ─────────────────────────────────────────
#define BTN_UP    0   // GPIO0 (D3)
#define BTN_DOWN  2   // GPIO2 (D4)
#define BTN_OK    14  // GPIO14 (D5)
#define BTN_BACK  12  // GPIO12 (D6)

// ─── LED ─────────────────────────────────────────────────
#define LED_STATUS 13  // GPIO13 (D7)

// ─── WIFI AP CREDENTIALS ─────────────────────────────────
#define AP_SSID  "WiFiAnalyzer"
#define AP_PASS  "analyzer123"

// ─── SCAN SETTINGS ───────────────────────────────────────
#define MAX_APS           32    // Maximum APs to store
#define CHANNEL_DWELL_MS  200   // Time per channel (ms)
#define MAX_CHANNEL       13    // 2.4GHz channels 1-13
