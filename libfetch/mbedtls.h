#pragma once
#include <stdlib.h>

#include "fetch.h"
#include "common.h"

int fetch_mbedtls(conn_t *conn, const struct url *URL, int verbose, int permissive);
int fetch_mbedtls_close();
int mbedtls_set_read_timeout(uint32_t _timeout);
int mbedtls_set_mtu(uint16_t _mtu);