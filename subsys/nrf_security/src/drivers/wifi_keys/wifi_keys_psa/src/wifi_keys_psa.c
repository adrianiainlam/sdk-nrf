/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(wifi_keys, CONFIG_WIFI_KEYS_LOG_LEVEL);

#include <stdint.h>
#include <cracen/lib_kmu.h>

#include <zephyr/sys/__assert.h>

#include "wifi_keys_psa.h"

static int wifi_keys_kmu_provision_and_push(const wifi_keys_buffer_t *keybuf, uint32_t key_slot)
{
	struct kmu_src src;

	memcpy(&src.value, keybuf->key_buffer, 16);
	src.rpolicy = LIB_KMU_REV_POLICY_ROTATING;
	src.dest = keybuf->dst_addr;
	src.metadata = 0;
	int ret = lib_kmu_provision_slot(key_slot, &src);

	if (ret) {
		LOG_ERR("Failed to provision key (dest: %08X): %d", src.dest, ret);
		return ret;
	}
	ret = lib_kmu_push_slot(key_slot);
	if (ret) {
		LOG_ERR("Failed to push key (dest: %08X): %d", src.dest, ret);
		return ret;
	}

	if (keybuf->key_size_bytes == 32) {
		memcpy(&src.value, keybuf->key_buffer + 16, 16);
		src.dest += 16;

		ret = lib_kmu_provision_slot(key_slot + 1, &src);
		if (ret) {
			return ret;
		}
		ret = lib_kmu_push_slot(key_slot + 1);
		if (ret) {
			return ret;
		}
	}
	return 0;
}

psa_status_t wifi_keys_import_key(const psa_key_attributes_t *attr, const uint8_t *data,
				  size_t data_length, uint8_t *key_buffer, size_t key_buffer_size,
				  size_t *key_buffer_length, size_t *key_bits)
{
	__ASSERT_NO_MSG(key_buffer);
	__ASSERT_NO_MSG(key_buffer_length);
	__ASSERT_NO_MSG(key_bits);

	if (key_buffer_size == 0) {
		LOG_ERR("Invalid key buffer size: %d", key_buffer_size);
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	psa_key_lifetime_t lifetime = psa_get_key_lifetime(attr);
	psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(lifetime);
	psa_key_persistence_t persistence = PSA_KEY_LIFETIME_GET_PERSISTENCE(lifetime);
	psa_key_id_t id = psa_get_key_id(attr);

	LOG_INF("Importing key to PSA, location: %d, persistence: %d, lifetime: %d, id: 0x%08X",
		location, persistence, lifetime, id);

	if (location == PSA_KEY_LOCATION_WIFI_KEYS) {
		/* Output parameters not used, set to arbitrary values. */
		*key_buffer_length = 32; /* max key size in bytes */
		*key_bits = 32 * 8;
		memset(key_buffer, 0, *key_buffer_length);

		if (persistence == PSA_KEY_PERSISTENCE_DEFAULT) {
			uint32_t key_slot = id & 0xFF;
			int ret = wifi_keys_kmu_provision_and_push((const wifi_keys_buffer_t *)data,
								   key_slot);
			if (ret) {
				LOG_ERR("Failed to provision and push key: %d", ret);
			}
			return ret;
		}
		LOG_ERR("Invalid persistence: %d", persistence);
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return PSA_ERROR_NOT_SUPPORTED;
}
