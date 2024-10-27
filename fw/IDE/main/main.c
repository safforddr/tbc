/*
 * Demonstration program for Trusted Business Card
 * (SLB9672 attached to an ESP32-S3-WROOM)
 *
 * TPM is attached to HOST_SPI2, since other SPI are used for flash and ram.
 * An activity LED is attached to pin 2.
 *
 * Copyright (C) 2024
 * Author:  David Safford <david.safford@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

/* Espressif */
#include <esp_log.h>

/* wolfSSL */
#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
    #ifndef WOLFSSL_ESPIDF
        #warning "Problem with wolfSSL user_settings."
        #warning "Check components/wolfssl/include"
    #endif
    #include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#else
    #error "Missing WOLFSSL_USER_SETTINGS in CMakeLists or Makefile:\
    CFLAGS +=-DWOLFSSL_USER_SETTINGS"
#endif

/* wolfTPM */
#ifdef WOLFTPM_USER_SETTINGS
    /* See wolfSSL user_settings.h for wolfTPM configuration */
#else
    #include <wolftpm/options.h>
#endif
#include <wolftpm/version.h>

/* project */
#include "main.h"
#include <wolftpm/tpm2_wrap.h>
#include <hal/tpm_io.h>
#include <driver/gpio.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include "esp_partition.h"
#include "esp_check.h"
#include "tinyusb.h"
#include "tusb_msc_storage.h"
#include "tusb_cdc_acm.h"
#include <wolftpm/tpm2_tis.h>
#include "tusb_console.h"

/* Main Application Defines
   NOTE: Card's FAT partition is strictly 8.3 case insensitive */
#define PIN_NUM_LED   2
#define BASE_PATH     "/data"
#define TPM2_CMD_MAX  4096
#define EK_CERT       "/data/esp/ek.crt"   
#define EK_PUB        "/data/esp/ek.der"
#define AK_PUB        "/data/esp/ak.der"
#define QUOTE_DATA    "/data/esp/quote.dat"
#define QUOTE_SIG     "/data/esp/quote.sig"
#define PCR_SIG       "/data/esp/pcr.sig"
#define PCR_FILE      "/data/esp/pcr.bin"
#define RESUME_FILE   "/data/esp/safford.pdf"
#define LOG_FILE      "/data/esp/log.bin"
#define CHALLENGE     "/data/esp/chall.bin"
#define CARD_FILE     "/data/esp/card.jpg"
#define PCR_INDEX     10
#define EK_NV_HANDLE  0x1c00002
#define EK_HANDLE     0x81010001
#define AK_HANDLE     0x81010002
#define SRK_HANDLE    0x81000001

/* Globals */
WOLFTPM2_DEV dev;
WOLFTPM2_KEY ak_key;

/* Using ACM0 for stdout/stder */
void tinyusb_cdc_rx_callback_console(int itf, cdcacm_event_t *event)
{
    uint8_t *buf;
    buf = malloc(CONFIG_TINYUSB_CDC_RX_BUFSIZE + 1);
    size_t rx_size = 0;

    /* read */
    tinyusb_cdcacm_read(itf, buf, CONFIG_TINYUSB_CDC_RX_BUFSIZE, &rx_size);

    /* write back */
    tinyusb_cdcacm_write_queue(itf, buf, rx_size);
    tinyusb_cdcacm_write_flush(itf, 0);
}

void tinyusb_cdc_line_state_changed_callback(int itf, cdcacm_event_t *event)
{
    int dtr = event->line_state_changed_data.dtr;
    int rts = event->line_state_changed_data.rts;
    printf("Line state changed on channel %d: DTR:%d, RTS:%d", itf, dtr, rts);
}

/* use tinyusb to create serial ttyACM0 */
void init_acm()
{
    printf("USB ACM initialization\n");
    const tinyusb_config_t tusb_cfg = {
        .device_descriptor = NULL,
        .string_descriptor = NULL,
        .external_phy = false,
        .configuration_descriptor = NULL,
    };
    ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));

    tinyusb_config_cdcacm_t acm_cfg = {
        .usb_dev = TINYUSB_USBDEV_0,
        .cdc_port = TINYUSB_CDC_ACM_0,
        .rx_unread_buf_sz = TPM2_CMD_MAX,
        .callback_rx = &tinyusb_cdc_rx_callback_console,
        .callback_rx_wanted_char = NULL,
        .callback_line_state_changed = NULL,
        .callback_line_coding_changed = NULL
    };

    ESP_ERROR_CHECK(tusb_cdc_acm_init(&acm_cfg));
    ESP_ERROR_CHECK(tinyusb_cdcacm_register_callback(
                        TINYUSB_CDC_ACM_0,
                        CDC_EVENT_LINE_STATE_CHANGED,
                        &tinyusb_cdc_line_state_changed_callback));
}

static bool file_exists(const char *file_path)
{
    struct stat buffer;
    return stat(file_path, &buffer) == 0;
}

static esp_err_t storage_init_spiflash(wl_handle_t *wl_handle)
{
    printf("Initializing wear levelling\n");

    const esp_partition_t *data_partition = 
        esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_FAT, NULL);
    if (data_partition == NULL) {
        printf("Failed to find FATFS partition. Check the partition table.");
        return ESP_ERR_NOT_FOUND;
    }

    return wl_mount(data_partition, wl_handle);
}

static void file_ops_init(void)
{
    const char *directory = "/data/esp";
    struct stat s = {0};
    bool directory_exists = stat(directory, &s) == 0;
    
    if (!directory_exists) {
        mkdir(directory, 0775);
    }
}

void init_storage()
{
    printf("Initializing storage.\n");

    static wl_handle_t wl_handle = WL_INVALID_HANDLE;
    ESP_ERROR_CHECK(storage_init_spiflash(&wl_handle));

    const tinyusb_msc_spiflash_config_t config_spi = {
        .wl_handle = wl_handle
    };
    ESP_ERROR_CHECK(tinyusb_msc_storage_init_spiflash(&config_spi));
    ESP_ERROR_CHECK(tinyusb_msc_storage_mount(BASE_PATH));
    file_ops_init();  
}

/*  
 *  The following wolfTPM2_GetKeyTemplate_EKIndex() is copied directly
 *  from the latest wolfTPM repo, as it is not in the older version I am
 *  using. If you have the latest wolfTPM, you should simply delete this.
 */

/* EK (High Range) */
#define TPM2_NV_EK_RSA2048             (TPM_20_TCG_NV_SPACE + 0x12)
#define TPM2_NV_EK_ECC_P256            (TPM_20_TCG_NV_SPACE + 0x14)
#define TPM2_NV_EK_ECC_P384            (TPM_20_TCG_NV_SPACE + 0x16)
#define TPM2_NV_EK_ECC_P521            (TPM_20_TCG_NV_SPACE + 0x18)
#define TPM2_NV_EK_ECC_SM2             (TPM_20_TCG_NV_SPACE + 0x1A)
#define TPM2_NV_EK_RSA3072             (TPM_20_TCG_NV_SPACE + 0x1C)
#define TPM2_NV_EK_RSA4096             (TPM_20_TCG_NV_SPACE + 0x1E)

/* SHA256 (PolicyB - High Range) */
static const BYTE TPM_20_EK_AUTH_POLICY_SHA256[] = {
    0xCA, 0x3D, 0x0A, 0x99, 0xA2, 0xB9, 0x39, 0x06,
    0xF7, 0xA3, 0x34, 0x24, 0x14, 0xEF, 0xCF, 0xB3,
    0xA3, 0x85, 0xD4, 0x4C, 0xD1, 0xFD, 0x45, 0x90,
    0x89, 0xD1, 0x9B, 0x50, 0x71, 0xC0, 0xB7, 0xA0
};
#ifdef WOLFSSL_SHA384
/* SHA384 (PolicyB - High Range) */
static const BYTE TPM_20_EK_AUTH_POLICY_SHA384[] = {
    0xB2, 0x6E, 0x7D, 0x28, 0xD1, 0x1A, 0x50, 0xBC,
    0x53, 0xD8, 0x82, 0xBC, 0xF5, 0xFD, 0x3A, 0x1A,
    0x07, 0x41, 0x48, 0xBB, 0x35, 0xD3, 0xB4, 0xE4,
    0xCB, 0x1C, 0x0A, 0xD9, 0xBD, 0xE4, 0x19, 0xCA,
    0xCB, 0x47, 0xBA, 0x09, 0x69, 0x96, 0x46, 0x15,
    0x0F, 0x9F, 0xC0, 0x00, 0xF3, 0xF8, 0x0E, 0x12
};
#endif
#ifdef WOLFSSL_SHA512
/* SHA512 (PolicyB - High Range) */
static const BYTE TPM_20_EK_AUTH_POLICY_SHA512[] = {
    0xB8, 0x22, 0x1C, 0xA6, 0x9E, 0x85, 0x50, 0xA4,
    0x91, 0x4D, 0xE3, 0xFA, 0xA6, 0xA1, 0x8C, 0x07,
    0x2C, 0xC0, 0x12, 0x08, 0x07, 0x3A, 0x92, 0x8D,
    0x5D, 0x66, 0xD5, 0x9E, 0xF7, 0x9E, 0x49, 0xA4,
    0x29, 0xC4, 0x1A, 0x6B, 0x26, 0x95, 0x71, 0xD5,
    0x7E, 0xDB, 0x25, 0xFB, 0xDB, 0x18, 0x38, 0x42,
    0x56, 0x08, 0xB4, 0x13, 0xCD, 0x61, 0x6A, 0x5F,
    0x6D, 0xB5, 0xB6, 0x07, 0x1A, 0xF9, 0x9B, 0xEA
};
#endif

static int wolfTPM2_GetKeyTemplate_EK(TPMT_PUBLIC* publicTemplate, TPM_ALG_ID alg,
    int keyBits, TPM_ECC_CURVE curveID, TPM_ALG_ID nameAlg, int highRange)
{
    int rc;
    TPMA_OBJECT objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_adminWithPolicy |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt);
    if (highRange) {
        /* High range requires userWithAuth=1 */
        objectAttributes |= TPMA_OBJECT_userWithAuth;
    }

    if (alg == TPM_ALG_RSA) {
        rc = GetKeyTemplateRSA(publicTemplate, nameAlg,
            objectAttributes, keyBits, 0, TPM_ALG_NULL, TPM_ALG_NULL);
        if (rc == 0 && highRange) { /* high range uses 0 unique size */
            publicTemplate->unique.rsa.size = 0;
        }
    }
    else if (alg == TPM_ALG_ECC) {
        rc = GetKeyTemplateECC(publicTemplate, nameAlg,
            objectAttributes, curveID, TPM_ALG_NULL, TPM_ALG_NULL);
        if (rc == 0 && highRange) { /* high range uses 0 unique size */
            publicTemplate->unique.ecc.x.size = 0;
            publicTemplate->unique.ecc.y.size = 0;
        }

    }
    else {
        rc = BAD_FUNC_ARG; /* not supported */
    }

    if (rc == 0) {
        if (nameAlg == TPM_ALG_SHA256 && !highRange) {
            publicTemplate->authPolicy.size = sizeof(TPM_20_EK_AUTH_POLICY);
            XMEMCPY(publicTemplate->authPolicy.buffer,
                TPM_20_EK_AUTH_POLICY, publicTemplate->authPolicy.size);
        }
        else if (nameAlg == TPM_ALG_SHA256) {
            publicTemplate->authPolicy.size = sizeof(TPM_20_EK_AUTH_POLICY_SHA256);
            XMEMCPY(publicTemplate->authPolicy.buffer,
                TPM_20_EK_AUTH_POLICY_SHA256, publicTemplate->authPolicy.size);
        }
    #ifdef WOLFSSL_SHA384
        else if (nameAlg == TPM_ALG_SHA384) {
            publicTemplate->authPolicy.size = sizeof(TPM_20_EK_AUTH_POLICY_SHA384);
            XMEMCPY(publicTemplate->authPolicy.buffer,
                TPM_20_EK_AUTH_POLICY_SHA384, publicTemplate->authPolicy.size);
        }
    #endif
    #ifdef WOLFSSL_SHA512
        else if (nameAlg == TPM_ALG_SHA512) {
            publicTemplate->authPolicy.size = sizeof(TPM_20_EK_AUTH_POLICY_SHA512);
            XMEMCPY(publicTemplate->authPolicy.buffer,
                TPM_20_EK_AUTH_POLICY_SHA512, publicTemplate->authPolicy.size);
        }
    #endif
    }

    return rc;
}

static int wolfTPM2_GetKeyTemplate_EKIndex(word32 nvIndex,
    TPMT_PUBLIC* publicTemplate)
{
    TPM_ALG_ID alg = TPM_ALG_NULL;
    TPM_ALG_ID nameAlg = TPM_ALG_NULL;
    TPM_ECC_CURVE curveID = TPM_ECC_NONE;
    uint32_t keyBits = 0;
    int highRange = 0;

    /* validate index is in NV EK range */
    if (nvIndex < TPM_20_TCG_NV_SPACE ||
        nvIndex > TPM_20_TCG_NV_SPACE + 0x1FF) {
        return BAD_FUNC_ARG;
    }

    /* determine if low or high range */
    if (nvIndex >= TPM2_NV_EK_RSA2048) {
        highRange = 1;
    }

    /* Determine algorithm based on index */
    switch (nvIndex) {
        case TPM2_NV_RSA_EK_CERT: /* EK (Low Range): RSA 2048 */
        case TPM2_NV_EK_RSA2048:  /* EK (High Range) */
            alg = TPM_ALG_RSA;
            nameAlg = TPM_ALG_SHA256;
            keyBits = 2048;
            break;
        case TPM2_NV_EK_RSA3072:
            alg = TPM_ALG_RSA;
            nameAlg = TPM_ALG_SHA384;
            keyBits = 3072;
            break;
        case TPM2_NV_EK_RSA4096:
            alg = TPM_ALG_RSA;
            nameAlg = TPM_ALG_SHA512;
            keyBits = 4096;
            break;
        case TPM2_NV_ECC_EK_CERT: /* EK (Low Range): ECC P256 */
        case TPM2_NV_EK_ECC_P256: /* EK (High Range) */
            alg = TPM_ALG_ECC;
            curveID = TPM_ECC_NIST_P256;
            nameAlg = TPM_ALG_SHA256;
            keyBits = 256;
            break;
        case TPM2_NV_EK_ECC_P384:
            alg = TPM_ALG_ECC;
            curveID = TPM_ECC_NIST_P384;
            nameAlg = TPM_ALG_SHA384;
            keyBits = 384;
            break;
        case TPM2_NV_EK_ECC_P521:
            alg = TPM_ALG_ECC;
            curveID = TPM_ECC_NIST_P521;
            nameAlg = TPM_ALG_SHA512;
            keyBits = 521;
            break;
        case TPM2_NV_EK_ECC_SM2:
            alg = TPM_ALG_SM2;
            curveID = TPM_ECC_SM2_P256;
            nameAlg = TPM_ALG_SHA256;
            keyBits = 256;
            break;
        default:
            alg = TPM_ALG_NULL;
            curveID = TPM_ECC_NONE;
            nameAlg = TPM_ALG_NULL;
            keyBits = 0;
            break;
    }

    return wolfTPM2_GetKeyTemplate_EK(publicTemplate, alg, keyBits, curveID,
            nameAlg, highRange);
}

static int wolfTPM2_CreateEKfromNV(WOLFTPM2_DEV *dev, WOLFTPM2_KEY *ekKey, TPM_HANDLE handle)
{
    int rc;
    TPMT_PUBLIC publicTemplate;

    /* get ek template from NV ek cert */
    rc = wolfTPM2_GetKeyTemplate_EKIndex(handle, &publicTemplate);
    rc = wolfTPM2_CreatePrimaryKey(dev, ekKey, TPM_RH_ENDORSEMENT, &publicTemplate, NULL, 0);

    return rc;
}

void init_tpm()
{
    TPM_RC rc;
    
    union {
        Startup_In startup;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    
    /* Initialize wolfTPM and SPI IO */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%lx: %s\n", rc, TPM2_GetRCString(rc));
        return;
    }
  
    printf("wolfTPM2_Init success\n");
    printf("TPM2 Caps 0x%08x, Did 0x%04x, Vid 0x%04x, Rid 0x%2x \n",
        dev.ctx.caps,
        dev.ctx.did_vid >> 16,
        dev.ctx.did_vid & 0xFFFF,
        dev.ctx.rid);
        
    /* Start TPM with unwrapped function */
    XMEMSET(&cmdIn.startup, 0, sizeof(cmdIn.startup));
    cmdIn.startup.startupType = TPM_SU_CLEAR;
    rc = TPM2_Startup(&cmdIn.startup);
    if (rc != TPM_RC_SUCCESS && rc != TPM_RC_INITIALIZE ) {
        printf("TPM2_Startup failed 0x%lx: %s\n", rc, TPM2_GetRCString(rc));
        return;
    }
    printf("TPM2_Startup pass\n");
}
    
/* if ek.crt does not exist, try reading it from nv */
static void tpm_get_ekcert(void) {            
    if (!file_exists(EK_CERT)) {
        uint8_t *buf = malloc(4096);
        uint32_t len = 4096;
        TPM_RC rc;
        rc = wolfTPM2_NVReadCert(&dev, EK_NV_HANDLE, buf, &len);
        if (rc == TPM_RC_SUCCESS) {  
            FILE *f = fopen(EK_CERT, "w");
            if (f) {
                rc = fwrite(buf, 1, len, f);
                fclose(f);
            }   
        } else
            printf("NVReadCert returned %lX %s\n", rc, TPM2_GetRCString(rc));
        free(buf);
    } 
}

static void tpm_create_ek(void) {  
    if (!file_exists(EK_PUB)) {          
        word32 len = 4096;
        uint8_t *buf = malloc(4096);
        WOLFTPM2_KEY ek_key;
        TPM_RC rc;
        
        /* make sure we use the same template as TPM vendor used */
        rc = wolfTPM2_CreateEKfromNV(&dev, &ek_key, EK_NV_HANDLE);
        if (rc != TPM_RC_SUCCESS)
            printf("CreatEk returned %lX %s\n", rc, TPM2_GetRCString(rc));
        rc = wolfTPM2_ExportPublicKeyBuffer(&dev, &ek_key, ENCODING_TYPE_ASN1, buf, &len);
        if (rc == TPM_RC_SUCCESS) {
            FILE *f = fopen(EK_PUB, "w");
            if (f) {
                fwrite(buf, 1, len, f);
                fclose(f);  
            }  else {
                printf("ExportPublic returned %lX %s\n", rc, TPM2_GetRCString(rc));   
            }
        }
        free(buf);
    } 
}

static void tpm_create_ak(void) {
    WOLFTPM2_KEY srk_key;
    TPM_RC rc;
    
    /* if needed create srk */
    rc = wolfTPM2_ReadPublicKey(&dev, &srk_key, SRK_HANDLE);
    if (rc == TPM_RC_SUCCESS) {
        printf("Loaded SRK\n");
    } else {
        TPM_ALG_ID alg = TPM_ALG_RSA;   
        printf("Read SRK returned %lX %s\n", rc, TPM2_GetRCString(rc));
        /* Create primary storage key */
        rc = wolfTPM2_CreateSRK(&dev, &srk_key, alg, NULL, 0);
        if (rc == TPM_RC_SUCCESS) {
            rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &srk_key, SRK_HANDLE);
        } else {
            printf("CreateSRK returned %lX %s\n", rc, TPM2_GetRCString(rc));
        }
    }    
   
    /* if needed, create AK and make persistent at 0x81010002 */
    rc = wolfTPM2_ReadPublicKey(&dev, &ak_key, AK_HANDLE);
    if (rc == TPM_RC_SUCCESS) {
            printf("Read ak success\n");
    } else {
        TPM_RH hierarchy = TPM_RH_OWNER;  
        TPM_ALG_ID alg = TPM_ALG_RSA;
        printf("Read AK returned %lX %s\n", rc, TPM2_GetRCString(rc));
        
        /* create AK */
        rc = wolfTPM2_CreateAndLoadAIK(&dev, &ak_key, alg, &srk_key, NULL, 0);
        if (rc != TPM_RC_SUCCESS)
            printf("Create AIK returned %lX %s\n", rc, TPM2_GetRCString(rc));
            
        /* Make AK persistent */
        rc = wolfTPM2_NVStoreKey(&dev, hierarchy, &ak_key, AK_HANDLE);
        if (rc != TPM_RC_SUCCESS)
            printf("NVStore AK returned %lX %s\n", rc, TPM2_GetRCString(rc));
    } 
    
    /* ak_key exists, If needed, write it to file */
    if (!file_exists(AK_PUB)) {  
        uint8_t *buf = malloc(4096);
        word32 len = 4096;
        rc = wolfTPM2_ExportPublicKeyBuffer(&dev, &ak_key, ENCODING_TYPE_ASN1, buf, &len);
        if (rc == TPM_RC_SUCCESS) {
            FILE *f = fopen(AK_PUB, "w");
            if (f) {  
                fwrite(buf, 1, len, f);
                fclose(f);         
            }           
        } else {
            printf("Export AIK returned %lX %s\n", rc, TPM2_GetRCString(rc));
        }
    }  
}

/* CEL-TLV Types */
#define CEL_SEQNUM	  0
#define CEL_PCR 	  1
#define CEL_DIGESTS 	  3
#define TPM_ALG_SHA256	 11
#define CEL_IMA_TLV	  8
#define IMA_TLV_PATH	  0
#define IMA_TLV_DATAHASH  1

/* hash filename, extend hash into pcr-10, and log in IMA-TLV!! */
static void tpm_measure(char *filename) {
    TPM_RC rc = -1;
    FILE *f = NULL;
    size_t len;
    BYTE file_hash[TPM_SHA256_DIGEST_SIZE];
    BYTE content[256];
    BYTE digest[TPM_SHA256_DIGEST_SIZE];
    BYTE buf[1024];
    uint32_t l;
    byte t;

    wc_Sha256 sha256;
    static int first = 1, seq = 0;

    union {
        PCR_Extend_In pcrExtend;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    
    /* Prepare the hash from user file */
    f = fopen(filename, "r");    
    if (!f) 
        return;     
    printf("Hashing file %s\n", filename);
    wc_InitSha256(&sha256);
    while (!feof(f)) {
        len = fread(buf, 1, sizeof(buf), f);
        if (len) {
            wc_Sha256Update(&sha256, buf, (int)len);
        }
    }
    wc_Sha256Final(&sha256, file_hash);
    fclose(f);
     
    /*  prepare IMA_TLV content field [ima-tlv( tlv(filename), tlv(file_hash))]
     *  filename tlv starts at content+5, file_hash tlv at content+5+5+strlen(filename)
     *  e.g. t l [ t l [filename] t l [hash] ]
     */
    content[0] = CEL_IMA_TLV;
    len = l = strlen(filename) + 32 + 5 + 5;
    *(uint32_t *)(content + 1) = htonl(l);
    
    content[5] = IMA_TLV_PATH;
    l = strlen(filename);
    *(uint32_t *)(content + 6) = htonl(l);
    memcpy((content + 10), filename, l);
    
    content[10 + l] = IMA_TLV_DATAHASH;
    *(uint32_t *)(content + 11 + l) = htonl(32);    
    memcpy((content + 15 + l), file_hash, 32);      
    
    /* hash content, len into record digest */
    wc_InitSha256(&sha256);
    wc_Sha256Update(&sha256, content, (int)len + 5);
    wc_Sha256Final(&sha256, digest);    
    
    /* write entire record to log [seq, pcr, digest, content] */
    if (first) {
        first = 0;
        f = fopen(LOG_FILE, "w");
    } else {
        f = fopen(LOG_FILE, "a");
    }
    if (f) {
        /* write SEQNUM tlv */
        t = CEL_SEQNUM;
        fwrite(&t, 1, 1, f);
        l = htonl(sizeof(seq));
        fwrite(&l, 1, 4, f);
        l = htonl(seq++);
        fwrite(&l, 1, 4, f);
    
        /* write PCR tlv */
        t = CEL_PCR;
        fwrite(&t, 1, 1, f);
        l = htonl(sizeof(uint32_t));
        fwrite(&l, 1, 4, f);
        l = htonl(PCR_INDEX);
        fwrite(&l, 1, 4, f);        
        
        /* write digests tlv */
        t = CEL_DIGESTS;
        fwrite(&t, 1, 1, f);
        l = htonl(32 + 5);
        fwrite(&l, 1, 4, f); 
        t = TPM_ALG_SHA256;
        fwrite(&t, 1, 1, f);
        l = htonl(32);
        fwrite(&l, 1, 4, f);        
        fwrite(digest, 1, 32, f);
        
        /* write content tlv */    
        fwrite(content, 1, len+5, f);
        
        fclose(f); 
    }
               
    /* Prepare PCR Extend command - we extend with the digest */
    memset(&cmdIn.pcrExtend, 0, sizeof(cmdIn.pcrExtend));
    cmdIn.pcrExtend.pcrHandle = PCR_INDEX;
    cmdIn.pcrExtend.digests.count = 1;   
    cmdIn.pcrExtend.digests.digests[0].hashAlg = TPM_ALG_SHA256;
    memcpy(cmdIn.pcrExtend.digests.digests[0].digest.H, digest, TPM_SHA256_DIGEST_SIZE);     

    /* do the extend */
    rc = TPM2_PCR_Extend(&cmdIn.pcrExtend);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Extend failed %lX: %s\n", rc, TPM2_GetRCString(rc));
    } else {
        printf("TPM2_PCR_Extend success\n");
    }
           
}    

static void tpm_create_quote(void) {
    /* ak_key is already loaded */
    TPMS_ATTEST attestedData;    
    union {
        PCR_Read_In pcrRead;        
        Quote_In quoteAsk;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        PCR_Read_Out pcrRead;    
        Quote_Out quoteResult;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;
    FILE *f;   
    TPM_RC rc;
    int dataSz;
    BYTE *data;

    /* First read pcr */
    memset(&cmdIn.pcrRead, 0, sizeof(cmdIn.pcrRead));
    TPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn, TPM_ALG_SHA256, PCR_INDEX);
    rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
    if (rc == TPM_RC_SUCCESS) {
        f = fopen(PCR_FILE, "w");
        if (f) {
            printf("writing pcr data\n");
            fwrite(cmdOut.pcrRead.pcrValues.digests[0].buffer, 1, cmdOut.pcrRead.pcrValues.digests[0].size, f);
            fclose(f);
        } else {
            printf("open pcr file failed\n");  
        }
        
    } else
        printf("TPM2_PCR_Read failed 0x%lx: %s\n", rc, TPM2_GetRCString(rc));
    
    /* Prepare Quote request */
    XMEMSET(&cmdIn.quoteAsk, 0, sizeof(cmdIn.quoteAsk));
    XMEMSET(&cmdOut.quoteResult, 0, sizeof(cmdOut.quoteResult));
    cmdIn.quoteAsk.signHandle = ak_key.handle.hndl;
    printf("Quoting with handle %lX\n",ak_key.handle.hndl);
    cmdIn.quoteAsk.inScheme.scheme = TPM_ALG_RSASSA;
    cmdIn.quoteAsk.inScheme.details.any.hashAlg = TPM_ALG_SHA256;
    cmdIn.quoteAsk.qualifyingData.size = 0; /* optional */
    /* Choose PCR for signing */
    TPM2_SetupPCRSel(&cmdIn.quoteAsk.PCRselect, TPM_ALG_SHA256, PCR_INDEX);

    /* Get the PCR measurement signed by the TPM using the AIK key */
    rc = TPM2_Quote(&cmdIn.quoteAsk, &cmdOut.quoteResult);
    if ( rc == TPM_RC_SUCCESS ) {
        rc = TPM2_ParseAttest(&cmdOut.quoteResult.quoted, &attestedData);
        if ((rc == TPM_RC_SUCCESS) && (attestedData.magic == TPM_GENERATED_VALUE)) {         
            /* Save quoted data to the disk */
            data = (UINT8*)&cmdOut.quoteResult.quoted;
            dataSz = *(UINT16 *)data;
            printf("Quoted data %d bytes\n", dataSz);
            data += sizeof(UINT16); /* skip the size field of TPMS_ATTEST */           
            f = fopen(QUOTE_DATA, "w");
            if (f) {
                fwrite(data, 1, dataSz, f);
                fclose(f);
            }    
            
            /* save signature blob */
            f = fopen(QUOTE_SIG, "w");
            if (f) {
                fwrite(cmdOut.quoteResult.signature.signature.rsassa.sig.buffer, 1, 
                    cmdOut.quoteResult.signature.signature.rsassa.sig.size, f);   
                printf("Wrote %d bytes to %s\n", cmdOut.quoteResult.signature.signature.rsassa.sig.size, QUOTE_SIG);
                fclose(f);
            } else {
                printf("Unable to open %s\n", QUOTE_SIG);
            }
        }    
    } else {
        printf("Quote returned %lx %s\n", rc , TPM2_GetRCString(rc));
    }
    wolfTPM2_Cleanup(&dev);
}

/* Sleeps for the specified amount of milliseconds */
void platform_sleep_ms (int32_t milliseconds)
{
    vTaskDelay(milliseconds / portTICK_PERIOD_MS);
}

void led_task(void *pvParameters)
{
        /* flash the activity LED */
        gpio_reset_pin(PIN_NUM_LED);
        gpio_set_direction(PIN_NUM_LED, GPIO_MODE_OUTPUT);
        while(1) {
                gpio_set_level(PIN_NUM_LED, 1);
                platform_sleep_ms(1000);
                gpio_set_level(PIN_NUM_LED, 0);
                platform_sleep_ms(1000);                        
        }
}

void app_main(void)
{
    init_tpm();      
    init_storage();
    tpm_get_ekcert();
    tpm_create_ek();
    tpm_create_ak();
    tpm_measure(RESUME_FILE);
    tpm_measure(CARD_FILE);
    tpm_measure(CHALLENGE);
    tpm_create_quote();
    printf("Finished initialization\n");
    init_acm();
     
    /* blink led to show we are alive */
    xTaskCreate(&led_task, "led_task", 4096, NULL, 3, NULL);
}

