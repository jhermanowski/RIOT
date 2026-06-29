/*
 * SPDX-FileCopyrightText: 2026 Frankfurt University of Applied Sciences
 * SPDX-FileCopyrightText: 2026 Jakob Hermanowski <todo>
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @{
 *
 * @file
 * @brief   woldSSL implementation of @ref net_sock_dtls
 *
 * @author	Jakob Hermanowski <>
 */
#define LOG_LEVEL 4
//#define ENABLE_DEBUG 
#include <assert.h>

#include "log.h"
#include "user_settings.h"
#include <wolfssl/ssl.h>
#include "net/sock/dtls.h"
#include "net/credman.h"
#include <stdio.h>

/* private funcktions */


int _wolfssl_udp_send(WOLFSSL* ssl, char* buf, int sz, void* _ctx)
{
    (void)ssl;
    sock_dtls_t *ctx = (sock_dtls_t *)_ctx;

    if (!ctx) {
        return WOLFSSL_CBIO_ERR_GENERAL;
	}

    ssize_t ret = sock_udp_send(ctx->udp_sock, (unsigned char *)buf, sz, &ctx->peer_addr);
    if (ret <= 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
	}

    return (int)ret;
}

int _wolfssl_udp_receive(WOLFSSL *ssl, char *buf, int sz, void *_ctx)
{
    (void)ssl;
    sock_udp_ep_t ep;
    ssize_t ret;
	/* This function returns the current timeout value in seconds for the WOLFSSL object. When using non-blocking sockets, something in the user code needs to decide when to check for available recv data and how long it has been waiting. The value returned by this function indicates how long the application should wait. */
    word32 timeout = wolfSSL_dtls_get_current_timeout(ssl) * 1000000;
	/*todo angeblich habe ich hier probleme mit dem timeout*/
    sock_dtls_t *ctx = (sock_dtls_t *)_ctx;
    if (!ctx) {
        return WOLFSSL_CBIO_ERR_GENERAL;
	}

    if (wolfSSL_get_using_nonblock(ctx->ssl)) {
        timeout = 0;
    }

    ret = sock_udp_recv(ctx->udp_sock, buf, sz, timeout, &ep);
    if (ret > 0) {
        if (ctx->peer_addr.port == 0) {
            XMEMCPY(&ctx->peer_addr, &ep, sizeof(sock_udp_ep_t));
		}
    	return (int)ret;
    }
	/* all of those require to listen longer */
	if (ret == 0 || ret == -EAGAIN || ret == -EPROTO || ret == -ETIMEDOUT) {
		return WOLFSSL_CBIO_ERR_WANT_READ;
	}
	/* error */
	return WOLFSSL_CBIO_ERR_GENERAL;
}


void sock_dtls_init(void)
{
	puts("hallo");
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        LOG_DEBUG("Failed to initialize wolfSSL\n");
    }
	else {
		LOG_DEBUG("Initialized wolfSSL\n");
	}
}

/*Creates a new DTLS sock object.
*
*Takes an initialized UDP sock and uses it for the transport. Memory allocation functions required by the underlying DTLS stack can be called in this function.
*/

int sock_dtls_create(sock_dtls_t *sock, sock_udp_t *udp_sock,
		credman_tag_t tag, unsigned version, unsigned role)
{
	void(tag);
	if (!sock || !udp_sock){
		return -1;
	}

    if (role != SOCK_DTLS_CLIENT && role != SOCK_DTLS_SERVER) {
        LOG_DEBUG("sock_dtls: invalid role\n");
        return -1;
	}

	WOLFSSL_METHOD *method = NULL;
//todo:version 1_0 und 1_1
	/* Choosing the right tls method */	
	if (version == SOCK_DTLS_1_2) {
		if (role == SOCK_DTLS_CLIENT) {
			method = wolfDTLSv1_2_client_method();
		} 
		else if (role == SOCK_DTLS_SERVER) {
			method = wolfDTLSv1_2_server_method();
		}
	}	
//todo: schauen ob das funktionieren wird
//todo: not sure if this is the right define
#ifdef WOLFSSL_DTLS13
	else if (version == SOCK_DTLS_1_3) {
		if (role == SOCK_DTLS_CLIENT) {
			method = wolfDTLSv1_3_client_method();
		} 
		else if (role == SOCK_DTLS_SERVER) {
			method = wolfDTLSv1_3_server_method();
		}
	}		
#endif
	if (method == NULL ) {
		LOG_DEBUG("sock_dtls: unsupported DTLS version\n");
		return -1;
	}
	sock->ctx = wolfSSL_CTX_new(method);
	if (!sock->ctx) {
		LOG_DEBUG("sock_dtls: error getting DTLS context\n");
		return -1;
	}

	wolfSSL_CTX_SetIORecv(sock->ctx, _wolfssl_udp_receive);
	wolfSSL_CTX_SetIOSend(sock->ctx, _wolfssl_udp_send);

	sock->role = role;
	sock->udp_sock = udp_sock;


	return 0;
}
