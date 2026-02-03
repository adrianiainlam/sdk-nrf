/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef WIFI_KEYS_PSA_H
#define WIFI_KEYS_PSA_H

#include <psa/crypto.h>

static const psa_key_location_t PSA_KEY_LOCATION_WIFI_KEYS =
	(psa_key_location_t)(PSA_KEY_LOCATION_VENDOR_FLAG | ('N' << 8) | 'W');

typedef struct {
	uint32_t dst_addr;
	uint8_t key_buffer[32];
	size_t key_size_bytes; /* Note: only 16 and 32 supported */
} wifi_keys_buffer_t;

psa_status_t wifi_keys_import_key(const psa_key_attributes_t *attr, const uint8_t *data,
				  size_t data_length, uint8_t *key_buffer, size_t key_buffer_size,
				  size_t *key_buffer_length, size_t *key_bits);

#endif
