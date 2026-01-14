#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

// BLE Headers
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "services/gap/ble_svc_gap.h"

// SPIFFS
#include "esp_spiffs.h"
#include "esp_timer.h"

// Hardware Definitions - Conditional on Target Chip
#if CONFIG_IDF_TARGET_ESP32C6
    #define USER_LED_GPIO 15
    #define USER_BUZZER_GPIO 0
    #define HAS_LED 1

    // External antenna setup for C6
    #define ENABLE_EXT_ANTENNA 1
    #define EXT_ANT_PIN1 3
    #define EXT_ANT_PIN2 14

#elif CONFIG_IDF_TARGET_ESP32S3
    #define USER_LED_GPIO 21
    #define USER_BUZZER_GPIO 1
    #define HAS_LED 1
    #define ENABLE_EXT_ANTENNA 0

#elif CONFIG_IDF_TARGET_ESP32C3
    #define USER_BUZZER_GPIO 2
    #define HAS_LED 0
    #define ENABLE_EXT_ANTENNA 0

#else
    #error "Unsupported target chip"
#endif

// Common definitions
#define LED_ON  0
#define LED_OFF 1
#define BUZZER_ON  1
#define BUZZER_OFF 0

static const char *TAG = "WHAT_THE_FLOCK";

static TaskHandle_t led_task_handle = NULL;

static void dump_logs_to_console(void) {
    ESP_LOGI(TAG, "--- START OF FLASH LOGS ---");

    // Open the file for reading
    FILE* f = fopen("/spiffs/detections.txt", "r");
    if (f == NULL) {
        ESP_LOGW(TAG, "No detection log found on flash.");
        ESP_LOGW(TAG, "--- END OF FLASH LOGS ---");
        return;
    }

    char line[160];
    // Read line by line until end of file
    while (fgets(line, sizeof(line), f)) {
        // Print the line; printf is used to avoid TAG prefixes for raw data
        printf("%s", line);
    }

    fclose(f);
    ESP_LOGI(TAG, "--- END OF FLASH LOGS ---");
}

static void init_spiffs(void) {
    ESP_LOGI(TAG, "Initializing SPIFFS");

    esp_vfs_spiffs_conf_t conf = {
      .base_path = "/spiffs",
      .partition_label = "storage",
      .max_files = 5,
      .format_if_mount_failed = true
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount or format filesystem");
        } else if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to find SPIFFS partition");
        } else {
            ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        }
        return;
    }

    size_t total = 0, used = 0;
    ret = esp_spiffs_info("storage", &total, &used);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
    }
}

static void append_log(const char* log_line) {
    FILE* f = fopen("/spiffs/detections.txt", "a");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open log file for writing");
        return;
    }
    fprintf(f, "%s\n", log_line);
    fclose(f);
}

// WiFi SSID patterns to detect (case-insensitive)
static const char* wifi_ssid_patterns[] = {
    "flock", "Flock", "FLOCK", "FS Ext Battery", "Penguin", "Pigvision"
};

// Device name patterns for BLE advertisement detection
static const char* device_name_patterns[] = {
    "FS Ext Battery", "Penguin", "Flock", "Pigvision"
};

/**
 * @brief Structure to define MAC patterns (OUIs) to filter for.
 */
typedef struct {
    uint8_t oui[3];     /* The first 3 bytes of the MAC address */
    const char *label;  /* Manufacturer or device label */
} mac_filter_t;

/**
 * @brief List of MAC address patterns to match against.
 */
static const mac_filter_t TARGET_VENDORS[] = {
    {{0x70, 0xC9, 0x4E}, "Flock WiFi"},
    {{0x3C, 0x91, 0x80}, "Flock WiFi"},
    {{0xD8, 0xF3, 0xBC}, "Flock WiFi"},
    {{0x80, 0x30, 0x49}, "Flock WiFi"},
    {{0x14, 0x5A, 0xFC}, "Flock WiFi"},
    {{0x74, 0x4C, 0xA1}, "Flock WiFi"},
    {{0x08, 0x3A, 0x88}, "Flock WiFi"},
    {{0x9C, 0x2F, 0x9D}, "Flock WiFi"},
    {{0x94, 0x08, 0x53}, "Flock WiFi"},
    {{0xE4, 0xAA, 0xEA}, "Flock WiFi"},
    {{0x58, 0x8E, 0x81}, "Flock Battery"},
    {{0xCC, 0xCC, 0xCC}, "Flock Battery"},
    {{0xEC, 0x1B, 0xBD}, "Flock Battery"},
    {{0x90, 0x35, 0xEA}, "Flock Battery"},
    {{0x04, 0x0D, 0x84}, "Flock Battery"},
    {{0xF0, 0x82, 0xC0}, "Flock Battery"},
    {{0x1C, 0x34, 0xF1}, "Flock Battery"},
    {{0x38, 0x5B, 0x44}, "Flock Battery"},
    {{0x94, 0x34, 0x69}, "Flock Battery"},
    {{0xB4, 0xE3, 0xF9}, "Flock Battery"}
};

/**
 * @brief Searches for a MAC match in the TARGET_VENDORS array.
 * @param src_mac The 6-byte source MAC address.
 * @return Pointer to the matching mac_filter_t entry, or NULL if no match found.
 */
static const mac_filter_t* get_mac_filter(const uint8_t *src_mac)
{
    size_t count = sizeof(TARGET_VENDORS) / sizeof(TARGET_VENDORS[0]);

    for (size_t i = 0; i < count; i++) {
        // Compare only the first 3 bytes (the OUI)
        if (memcmp(src_mac, TARGET_VENDORS[i].oui, 3) == 0) {
            return &TARGET_VENDORS[i];
        }
    }
    return NULL;
}

/**
 * @brief Extract the source MAC address from an 802.11 frame.
 */
static bool extract_source_mac(const uint8_t *frame, uint8_t *src_mac)
{
    // Frame Control field (2 bytes)
    uint16_t fc = frame[0] | (frame[1] << 8);

    // ToDS / FromDS flags
    bool to_ds   = fc & (1 << 8);
    bool from_ds = fc & (1 << 9);

    if (!to_ds && !from_ds) {
        memcpy(src_mac, frame + 10, 6);
        return true;
    }

    if (to_ds && !from_ds) {
        memcpy(src_mac, frame + 10, 6);
        return true;
    }

    if (!to_ds && from_ds) {
        memcpy(src_mac, frame + 16, 6);
        return true;
    }

    return false;
}

static void indicator_task(void *pvParameters) {
    ESP_LOGI(TAG, "Indicator task running on core %d", xPortGetCoreID());
    while (1) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

#if HAS_LED
        gpio_set_level(USER_LED_GPIO, LED_ON);
#endif
        gpio_set_level(USER_BUZZER_GPIO, BUZZER_ON);

        vTaskDelay(pdMS_TO_TICKS(80));

#if HAS_LED
        gpio_set_level(USER_LED_GPIO, LED_OFF);
#endif
        gpio_set_level(USER_BUZZER_GPIO, BUZZER_OFF);
    }
}

static int ble_monitor_event(struct ble_gap_event *event, void *arg) {
    if (event->type == BLE_GAP_EVENT_DISC) {
        struct ble_hs_adv_fields fields;
        int rc = ble_hs_adv_parse_fields(&fields, event->disc.data, event->disc.length_data);
        if (rc != 0) return 0;

        bool is_target = false;
        char name[33] = {0};
        const char* match_type = "None";

        // Verbose Logging when any BLE is discovered.
        ESP_LOGV(TAG, "BLE Discovered: %02X:%02X:%02X:%02X:%02X:%02X | RSSI: %d",
                 event->disc.addr.val[5], event->disc.addr.val[4], event->disc.addr.val[3],
                 event->disc.addr.val[2], event->disc.addr.val[1], event->disc.addr.val[0],
                 event->disc.rssi);

        // --- SIGNATURE 1: MAC PREFIX CHECK ---
        for (int i = 0; i < sizeof(TARGET_VENDORS)/sizeof(mac_filter_t); i++) {
            // Compare OUI[0,1,2] to addr.val[5,4,3]
            if (event->disc.addr.val[5] == TARGET_VENDORS[i].oui[0] &&
                event->disc.addr.val[4] == TARGET_VENDORS[i].oui[1] &&
                event->disc.addr.val[3] == TARGET_VENDORS[i].oui[2]) {

                ESP_LOGW(TAG, "MATCH: MAC Prefix (%s)", TARGET_VENDORS[i].label);
                is_target = true;
                match_type = TARGET_VENDORS[i].label;
            }
        }

        // --- SIGNATURE 2: ADVANCED NAME CHECK ---
        if (fields.name != NULL) {
            size_t name_len = fields.name_len > 32 ? 32 : fields.name_len;
            memcpy(name, fields.name, name_len);
            name[name_len] = '\0';

            // Debug Log All BLE Devices with names to know it is working
            ESP_LOGD(TAG, "BLE Device Name: %s, %d", name, event->disc.rssi);

            for (int i = 0; i < sizeof(device_name_patterns)/sizeof(char*); i++) {
                if (strcasestr(name, device_name_patterns[i]) != NULL) {
                    ESP_LOGW(TAG, "MATCH: Name Pattern (%s)", name);
                    is_target = true;
                    match_type = "Name Match";
                }
            }

            if (name_len == 10) {
                bool all_digits = true;
                for(int i=0; i<10; i++) if(name[i] < '0' || name[i] > '9') all_digits = false;
                if (all_digits) {
                    ESP_LOGW(TAG, "MATCH: 10-Digit Serial (%s)", name);
                    is_target = true;
                    match_type = "Serial Number";
                }
            }
        }

        // --- SIGNATURE 3: MANUFACTURER ID (0x09C8) ---
        if (fields.mfg_data != NULL && fields.mfg_data_len >= 2) {
            uint16_t company_id = fields.mfg_data[0] | (fields.mfg_data[1] << 8);
            if (company_id == 0x09C8) {
                ESP_LOGW(TAG, "MATCH: Hardware ID 0x09C8 (Xuntong/Flock)");
                is_target = true;
                match_type = "Hardware ID";
            }
        }

        if (is_target) {
            char log_buf[150];
            snprintf(log_buf, sizeof(log_buf), "[BLE %s] MAC: %02X:%02X:%02X:%02X:%02X:%02X Name: %s RSSI: %d",
                     match_type,
                     event->disc.addr.val[5], event->disc.addr.val[4], event->disc.addr.val[3],
                     event->disc.addr.val[2], event->disc.addr.val[1], event->disc.addr.val[0],
                     name[0] ? name : "N/A", event->disc.rssi);

            ESP_LOGW("DETECTION", ">>> %s <<<", log_buf);
            append_log(log_buf); // Write to Flash

            if (led_task_handle != NULL) xTaskNotifyGive(led_task_handle);
        }
    }
    return 0;
}

static void wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;
    uint8_t src_mac[6];
    bool has_mac = extract_source_mac(payload, src_mac);

    // 1. SSID SEARCHING (Beacons and Probe Responses)
    if (type == WIFI_PKT_MGMT && (payload[0] == 0x80 || payload[0] == 0x50)) {
        uint8_t tag_type = payload[36];
        uint8_t tag_len = payload[37];

        if (tag_type == 0 && tag_len > 0) {
            char ssid[33] = {0};
            memcpy(ssid, &payload[38], tag_len > 32 ? 32 : tag_len);

            // Debug logging to verify WIFI Scanning
            ESP_LOGD(TAG, "WiFi SSID Seen: %s", ssid);

            for (int i = 0; i < sizeof(wifi_ssid_patterns)/sizeof(char*); i++) {
                if (strstr(ssid, wifi_ssid_patterns[i]) != NULL) {
                    ESP_LOGI(TAG, "WIFI SSID MATCH: %s", ssid);

                    // Prepare the detailed string for both Log and Flash
                    char log_buf[160];
                    snprintf(log_buf, sizeof(log_buf),
                             "[WIFI SSID] %s | MAC: %02X:%02X:%02X:%02X:%02X:%02X | RSSI: %d",
                             ssid,
                             has_mac ? src_mac[0]:0, has_mac ? src_mac[1]:0, has_mac ? src_mac[2]:0,
                             has_mac ? src_mac[3]:0, has_mac ? src_mac[4]:0, has_mac ? src_mac[5]:0,
                             pkt->rx_ctrl.rssi);

                    ESP_LOGW("DETECTION", ">>> %s <<<", log_buf);

                    append_log(log_buf);

                    if (led_task_handle != NULL) xTaskNotifyGive(led_task_handle);
                }
            }
        }
    }

    // 2. MAC MATCHING
    if (has_mac) {
        // Verbose logging to catch all WIFI Packets
        ESP_LOGV(TAG, "WiFi Packet from: %02X:%02X:%02X:%02X:%02X:%02X",
                 src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

        const mac_filter_t *match = get_mac_filter(src_mac);
        if (match != NULL) {
            // Prepare the detailed string for both Log and Flash
            char log_buf[160];
            snprintf(log_buf, sizeof(log_buf),
                     "[WIFI MAC] %s | MAC: %02X:%02X:%02X:%02X:%02X:%02X | RSSI: %d",
                     match->label,
                     src_mac[0], src_mac[1], src_mac[2],
                     src_mac[3], src_mac[4], src_mac[5],
                     pkt->rx_ctrl.rssi);

            ESP_LOGW("DETECTION", ">>> %s <<<", log_buf);

            append_log(log_buf);

            if (led_task_handle != NULL) xTaskNotifyGive(led_task_handle);
        }
    }
}

static void wifi_init_sniffer(void)
{
    esp_netif_init();
    esp_event_loop_create_default();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    ESP_LOGI(TAG, "WiFi promiscuous mode enabled with MAC filtering");
}

static void ble_host_task(void *param) {
    ESP_LOGI(TAG, "BLE host task running on core %d", xPortGetCoreID());
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static void ble_init_monitor(void) {
    ESP_ERROR_CHECK(nimble_port_init());

    struct ble_gap_disc_params disc_params = {0};
    disc_params.filter_duplicates = 1;
    disc_params.passive = 0;
    disc_params.itvl = 128;
    disc_params.window = 40;

    nimble_port_freertos_init(ble_host_task);

    // Start discovery
    ble_gap_disc(BLE_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params, ble_monitor_event, NULL);
}

static void channel_hop_task(void *arg)
{
    ESP_LOGI(TAG, "Channel hop task running on core %d", xPortGetCoreID());
    uint8_t channel = 1;

    while (1) {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        channel = (channel % 13) + 1;
        ESP_LOGD(TAG, ">> CHANNEL: %d <<", channel);
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

void app_main(void)
{
    #if ENABLE_EXT_ANTENNA
        // External antenna for C6
        gpio_reset_pin(EXT_ANT_PIN1);
        gpio_reset_pin(EXT_ANT_PIN2);
        gpio_set_direction(EXT_ANT_PIN1, GPIO_MODE_OUTPUT);
        gpio_set_direction(EXT_ANT_PIN2, GPIO_MODE_OUTPUT);
        gpio_set_level(EXT_ANT_PIN1, 0);
        vTaskDelay(pdMS_TO_TICKS(10));
        gpio_set_level(EXT_ANT_PIN2, 1);
    #endif
    // Conservative NVS Initialization (no auto-erase)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGE(TAG, "NVS Error (%s): Flash was NOT erased to preserve data.", esp_err_to_name(ret));
    } else {
        ESP_ERROR_CHECK(ret);
    }

    init_spiffs();

    // Dump all previous detections to Serial
    dump_logs_to_console();

    // Initialize GPIOs for indicators
    #if HAS_LED
        gpio_reset_pin(USER_LED_GPIO);
        gpio_set_direction(USER_LED_GPIO, GPIO_MODE_OUTPUT);
        gpio_set_level(USER_LED_GPIO, LED_OFF);
    #endif
    gpio_reset_pin(USER_BUZZER_GPIO);
    gpio_set_direction(USER_BUZZER_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(USER_BUZZER_GPIO, BUZZER_OFF);

    xTaskCreate(indicator_task, "indicator_task", 2048, NULL, 10, &led_task_handle);

    // Start scanning systems
    wifi_init_sniffer();
    ble_init_monitor();

    // Start background channel hopping
    xTaskCreate(channel_hop_task, "channel_hop", 2048, NULL, 5, NULL);

    // Boot Complete Signal (Double Flash/Beep)
    if (led_task_handle != NULL) {
        xTaskNotifyGive(led_task_handle);
        vTaskDelay(pdMS_TO_TICKS(200));
        xTaskNotifyGive(led_task_handle);
    }
    ESP_LOGW(TAG, "Beep Beep, we're good to go.");
}
