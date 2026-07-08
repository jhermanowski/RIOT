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
	sock_dtls_session_t *session = (sock_dtls_session_t *)_ctx;

    if (!session) {
        return WOLFSSL_CBIO_ERR_GENERAL;
	}
    ssize_t ret = sock_udp_send(session->udp_sock, (unsigned char *)buf, sz, &session->ep);
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

	sock_dtls_session_t *session = (sock_dtls_session_t *)_ctx;
    if (!session || !session->udp_sock) {
        return WOLFSSL_CBIO_ERR_GENERAL;
	}

    //if (wolfSSL_get_using_nonblock(ctx->ssl)) {
    if (wolfSSL_get_using_nonblock(ssl)) {
        timeout = 0;
    }

    ret = sock_udp_recv(session->udp_sock, buf, sz, timeout, &ep);
    if (ret > 0) {
        if (session->ep.port == 0) {
            XMEMCPY(&session->ep, &ep, sizeof(sock_udp_ep_t));
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
	if (!sock || !udp_sock){
		return -1;
	}

	/* clean up sock object */
	memset(sock, 0, sizeof(*sock));
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
	LOG_INFO("dtls object initialized\n");

	return 0;
}

int sock_dtls_session_init(sock_dtls_t *sock, const sock_udp_ep_t *ep,
		sock_dtls_session_t *remote){
//todo: we store our remote in sock?	
	sock_udp_ep_t local;
	
	remote->handshake_successfull = false;
	/* error if udp_sock is not initialized or udp_sock not set */
	if (!sock || !sock->udp_sock || (sock_udp_get_local(sock->udp_sock, &local) < 0)) {
		LOG_ERROR("udp_sock not set\n");
		return -EADDRNOTAVAIL;
	}
	if (!ep) {
		LOG_ERROR("ep is NULL\n");
		/* todo: wrong return value because there is none specified */
		return -EINVAL;
	}
	if (ep->port == 0) {
		LOG_ERROR("the endpoint is invalid, port is set to 0\n");
		return -EINVAL;
	}
	puts("port is set");
    switch (ep->family) {
#ifdef SOCK_HAS_IPV4
    case AF_INET:
        break;
#endif
#ifdef SOCK_HAS_IPV6
    case AF_INET6:
        break;
#endif
    default:
		LOG_ERROR("the endpoint not properly initialized, not set to ipv4 or ipv6\n");
        return -EINVAL;
    }
	puts("test");
	/* prepare the remote party to connect to */	
	XMEMCPY(&remote->ep, ep, sizeof(sock_udp_ep_t));
	remote->udp_sock = sock->udp_sock;
	if (!sock->ctx) {
		LOG_ERROR("wolfSSL ctx is null\n");
		/* todo wrong return value */
		return -EINVAL;
	}
	
	/* checking if a session already exists */
	if (remote->ssl) {
		if (wolfSSL_is_init_finished(remote->ssl)) {
			LOG_DEBUG("session already exists\n");
			return 0;
		}
		LOG_DEBUG("handshake for session was already started but did not finish yet\n");
		return 1;
	}
	remote->ssl = wolfSSL_new(sock->ctx);
	if (!remote->ssl) {
		LOG_ERROR("Error allocating ssl session\n");
		return -ENOMEM;
	}
	wolfSSL_SetIOReadCtx(remote->ssl, remote);
	wolfSSL_SetIOWriteCtx(remote->ssl, remote);
	
	/* start the handshake */
#define TIMEOUT 5 
	wolfSSL_dtls_set_timeout_init(remote->ssl, TIMEOUT);
	LOG_INFO("starting handshake with server\n");
	ssize_t ret = wolfSSL_connect(remote->ssl);
	//todo: hier muss ich wie im alten code mich um resetten und neustarten der connection kümmern. auch fehlt in dieser funktion ein error mode
	
	int error;
	if (ret != SSL_SUCCESS) {
		error = wolfSSL_get_error(remote->ssl, (int)ret);
		if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
			LOG_INFO("Handshake was started\n");
			//todo:
			return 1;
		}
		LOG_ERROR("fatal error occured: %d\n",error);
		//todo: close session here
		return -EINVAL;
	}
	return 1;
}

ssize_t sock_dtls_recv_aux (sock_dtls_t *sock,
		sock_dtls_session_t *remote,
		void *data,
		size_t maxlen,
		uint32_t timeout,
		sock_dtls_aux_rx_t *aux){
//todo: brauchen wir mbox?
	if (!sock || !remote) {
		return -EINVAL;
	}	
	if (!sock->udp_sock) {
		return -EADDRNOTAVAIL;
		//todo: do i need to check for sock->local_ep or smth?
	}
	if (!wolfSSL_is_init_finished(remote->ssl) || !remote->handshake_successfull) {
		LOG_DEBUG("handshake is not finished\n");
		int ret = wolfSSL_connect(remote->ssl);
		if (ret == SSL_SUCCESS) {
			LOG_INFO("handshake was completed\n");
			remote->handshake_successfull = true;
			return -SOCK_DTLS_HANDSHAKE;
		}
		int error = wolfSSL_get_error(remote->ssl, ret);
		if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
			LOG_INFO("waiting for I/O\n");
			//here we should try again calling connect and wait or smth
			return -1;
		}
		return -1;
		//todo: close session here
		//todo: restliche fehler müssen wir nicht checken, da wir hier nur handshake fertig oder nicht haben
	}

	int ret = wolfSSL_read(remote->ssl, data, (int)maxlen);
	if (ret > 0) {
		LOG_INFO("data successfull read\n");
		/* returning bytes read */
		return ret;
	}
	int error = wolfSSL_get_error(remote->ssl, ret);
	if (timeout == 0 || error ==  WOLFSSL_ERROR_WANT_READ) {
		LOG_INFO("timeout is 0 and no data to read\n");
		return -EAGAIN;
	}
	// ich kann das timeout garnicht setzen...
	// vermutlich das timeout in der session speichern
		// WOLFSSL_ERROR_ZERO_RETURN wenn connection geschlossen

	return -1;

	//todo: close session here
}	
	
	
