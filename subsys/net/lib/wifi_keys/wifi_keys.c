/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdint.h>
#include "wifi_keys.h"

static const uint32_t WIFI_KEYS_KMU_SLOT_ID = 181;

static bool wifi_keys_is_mic(wifi_keys_type_t type)
{
	return type == PEER_UCST_MIC || type == PEER_BCST_MIC || type == VIF_MIC;
}

uint32_t wifi_keys_get_key_start_addr(wifi_keys_type_t type, uint32_t db_id, uint32_t key_index)
{
	const uint32_t ram_base = 0x28400000;
	uint32_t db_base;
	uint32_t offset;
	bool mic = wifi_keys_is_mic(type);

	if (type == VIF_ENC || type == VIF_MIC) {
		if (db_id >= 4) {
			return WIFI_KEYS_ADDR_INVALID;
		}
		db_base = 0x1000 + db_id * 0xC0;
		if (key_index >= 4) {
			return WIFI_KEYS_ADDR_INVALID;
		}
		if (mic) {
			offset = key_index * 0x10;
		} else {
			offset = 0x40 + key_index * 0x20;
		}
	} else { /* PEER */
		if (db_id >= 8) {
			return WIFI_KEYS_ADDR_INVALID;
		}
		db_base = db_id * 0xF0;
		if (type == PEER_UCST_ENC || type == PEER_UCST_MIC) {
			offset = mic ? 0x0 : 0x10;
		} else { /* PEER_BCST */
			if (key_index >= 4) {
				return WIFI_KEYS_ADDR_INVALID;
			}
			if (mic) {
				offset = 0x30 + key_index * 0x10;
			} else {
				offset = 0x70 + key_index * 0x20;
			}
		}
	}

	return ram_base + db_base + offset;
}

uint32_t wifi_keys_get_key_size_in_bytes(wifi_keys_type_t type)
{
	return wifi_keys_is_mic(type) ? 16 : 32;
}

uint32_t wifi_keys_get_key_size_in_bits(wifi_keys_type_t type)
{
	return wifi_keys_get_key_size_in_bytes(type) * 8;
}

psa_key_attributes_t wifi_keys_key_attributes_init(void)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

	/* Arbitrary key ID scheme - non-builtin key. */
	psa_key_id_t id = 0x3F000000 | ('W' << 16) | ('C' << 8) | WIFI_KEYS_KMU_SLOT_ID;

	psa_set_key_id(&attr, id);

	psa_key_persistence_t persistence = PSA_KEY_PERSISTENCE_DEFAULT;

	psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
		persistence, PSA_KEY_LOCATION_WIFI_KEYS);

	psa_set_key_lifetime(&attr, lifetime);
	psa_set_key_type(&attr, PSA_KEY_TYPE_VENDOR_FLAG);

	return attr;

	/* Note: Usage flags and algorithm are deliberately not set (kept at 0),
	 * because software has no permission to use this key for any purpose
	 * (only Wi-Fi Crypto hardware can use it), and because Wi-Fi Crypto
	 * key locations can be reused for different algorithms).
	 */
}
