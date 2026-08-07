
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
 * @author todo
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
//	WOLFSSL 	*ssl;				/**< todo */
	unsigned role;
	int closing;					//todo: what are those?
//	sock_udp_ep_t peer_addr;		/** peer addr endpoint */

    char psk_hint[CONFIG_DTLS_PSK_ID_HINT_MAX_SIZE]; /**< PSK Identity hint */
    credman_tag_t tags[CONFIG_DTLS_CREDENTIALS_MAX]; /**< Tags of the available credentials */
    unsigned tags_len;                      /**< Number of tags in the list 'tags' */
    sock_dtls_client_psk_cb_t client_psk_cb;/**< Callback to determine PSK credential for session */
    sock_dtls_rpk_cb_t rpk_cb;              /**< Callback to determine RPK credential for session */
	//raw public key
};

struct sock_dtls_session {
	WOLFSSL			*ssl;
	sock_udp_ep_t	ep;
	sock_udp_t 		*udp_sock;			/**< Underlying TCP sock to use */
	sock_dtls_t		*dtls_sock;
	bool          	handshake_successfull; /* Hack to know if Handshake was successfull */
	uint32_t 		deadline_us;
	bool			has_deadline;

};

#ifdef __cplusplus
}
#endif

/** @} */
