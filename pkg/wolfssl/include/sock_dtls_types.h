
/*
 * Copyright (C) todo
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#pragma once

/**
 * @{
 *
 * @file
 * @brief   wolfssl-specific types and functions definitions
 *
 * @author todco
 */

//#include "dtls.h"
#include "user_settings.h"
#include <wolfssl/ssl.h>
#include "net/sock/udp.h"
#include "net/credman.h"
#include "net/sock/dtls/creds.h"

#include <sys/socket.h>
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Information about DTLS sock
 */
struct sock_dtls {
	sock_udp_t 	*udp_sock;			/**< Underlying TCP sock to use */
	WOLFSSL_CTX *ctx;		/**< todo */
	WOLFSSL 	*ssl;				/**< todo */

	int closing;					//todo: what are those?
	sock_udp_ep_t peer_addr;		/** peer addr endpoint */
	uint role;

};
//int GNRC_ReceiveFrom(WOLFSSL* ssl, char* buf, int sz,
 //                                    void* ctx); /**< todo */
//int GNRC_SendTo(WOLFSSL* ssl, char* buf, int sz, void* ctx); /**> todo */

#ifdef __cplusplus
}
#endif

/** @} */
