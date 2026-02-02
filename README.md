# What The Flock (WTF)
What The Flock is an ESP32 based scanner built on the Espressif IoT Development Framework (ESP-IDF). It is designed to identify and log radio signatures associated with Flock Surveillance cameras.
This project is an ESP-IDF port of the original "Flock You" program.
# Key Technical Improvements
Concurrent Scanning: Uses the NimBLE stack and Promiscuous WiFi mode simultaneously.
Persistent Storage: A dedicated 1MB SPIFFS partition stores detections that persist across reboots.

# XIAO C6 Optimized:
Developed Primarily on the Seeed Studio ESP32C6 hardware. It should work for the ESP32C6, C5, C3, or S3. (The C5 will also scan 5Ghz networks. This has not been extensively tested in the field to be better or worse.)

# Hardware Requirements
- Primary Hardware: Seeed Studio XIAO ESP32-C6.
- Antenna: External 2.4GHz antenna (u.FL/IPEX) for maximum range.
- Indicators: 
  * User LED: GPIO 15. (C6, 21 for S3, 27 for C5)
  * Active Buzzer: GPIO 0 (Triggered High).

# Setting up ESP-IDF Framework
```
git clone -b v5.5.2 --recursive https://github.com/espressif/esp-idf.git esp-idf-v5.5.2
cd esp-idf-v5.5.2/
chmod +x ./install.sh && ./install.sh
. ./export.sh
```
# Navigate back to the project directory and build
# For XIAO S3:
```
idf.py set-target esp32s3
```
# For XIAO C6:
```
idf.py set-target esp32c6
```
# For XIAO C3:
```
idf.py set-target esp32c3
```
# For XIAO C5:
```
idf.py set-target esp32c5
```
# Build, Flash, and Monitor
```
idf.py build flash monitor
```

# Usage and Data Extraction
The firmware is designed to be "headless." Once flashed, it will begin scanning immediately. Detections are signaled by a flash of the LED and a short beep from the active buzzer. When there is a detection, the detection will be written to the SPIFFS partition.
# Reading Logs
Every time the device boots, it will automatically dump the entire contents of the flash log to the serial console.
Connect the device to your PC and run:
```
idf.py monitor
```
# Press the Reset button on the device.

The logs will appear between the --- START OF FLASH LOGS --- and --- END OF FLASH LOGS --- markers.
# Acknowledgments
This project is a port and expansion of the work found in the "Flock You" repository. It is intended for educational and research only. Don't break the law.
