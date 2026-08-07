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
#include "ztimer.h"

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
/* private functions */


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
	/*todo angeblich habe ich hier probleme mit dem timeout*/

	sock_dtls_session_t *session = (sock_dtls_session_t *)_ctx;
    if (!session || !session->udp_sock) {
        return WOLFSSL_CBIO_ERR_GENERAL;
	}
	
	
    uint32_t timeout = wolfSSL_dtls_get_current_timeout(ssl) * 1000000UL;
	if (session->has_deadline) {
		uint32_t now = ztimer_now(ZTIMER_USEC);
		if (now >= session->deadline_us) {
			/* force wolfssl to return */
			return WOLFSSL_CBIO_ERR_TIMEOUT;
		}
		/* find new timeout set by the API */
		timeout = session->deadline_us - now;
		LOG_INFO("timeout set %i\n", timeout);
	}

	/* if nonblocking */
    if (wolfSSL_get_using_nonblock(ssl)) {
        timeout = 0;
    } else {
		int dtls_sec = wolfSSL_dtls_get_current_timeout(session->ssl);
		if (dtls_sec > 0) {
			uint32_t dtls_us = (uint32_t)dtls_sec * 1000000UL;
			if (timeout == SOCK_NO_TIMEOUT || dtls_us < timeout) {
				timeout = dtls_us;
			}
		}
	
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

#ifdef CONFIG_DTLS_PSK
static unsigned int _wolfssl_psk_server_cb(WOLFSSL* ssl, const char* identity,
                       unsigned char* key, unsigned int key_max_len) {

	sock_dtls_session_t *remote = (sock_dtls_session_t *)wolfSSL_GetIOReadCtx(ssl);
	
    if (!remote || !remote->dtls_sock) {
        return 0; 
    }

	/* access dtls_sock */
    sock_dtls_t *sock = remote->dtls_sock;


    if (sock->tags_len == 0) {
        return 0;
    }

	credman_credential_t credential;	

	bool found_cb = false;
	size_t identity_len = strlen(identity);

	for (unsigned i = 0; i < sock->tags_len && !found_cb; i++) {
        int ret = credman_get(&credential, sock->tags[i], CREDMAN_TYPE_PSK);
        if (ret == CREDMAN_OK) {
            if (identity_len == credential.params.psk.id.len &&
                !strncmp((const char *)credential.params.psk.id.s, identity, identity_len)) {
                found_cb = true;
            }
        }
    }	
	if (found_cb) {
        if (credential.params.psk.key.len > key_max_len) {
            LOG_ERROR("WolfSSL buffer can't hold the key\n");
            return 0; 
        }

        memcpy(key, credential.params.psk.key.s, credential.params.psk.key.len);
        return credential.params.psk.key.len;
    }

    LOG_DEBUG("No matching PSK credential found for identity: %s\n", identity);
	return 0;


}
static unsigned int _wolfssl_psk_client_cb(WOLFSSL* ssl, const char* hint,
                                           char* identity, unsigned int max_id_len,
                                           unsigned char* key, unsigned int max_key_len)
{
	/* the hint variable is set by wolfssl if the server gave us a hint */
    sock_dtls_session_t *remote = (sock_dtls_session_t *)wolfSSL_GetIOReadCtx(ssl);
    
    if (!remote || !remote->dtls_sock) {
        return 0; 
    }

	/* access dtls_sock */
    sock_dtls_t *sock = remote->dtls_sock;

    if (sock->tags_len == 0) {
        return 0;
    }
	size_t hint_len = 0;
//todo: immer explizit mit NULL checken 
	if (hint != NULL) {
		hint_len = strlen(hint);
	}
	credman_credential_t credential;
	

//todo: immer explizit mit NULL checken 
	/* if the user has set his own callback in the application */	
		
	bool found_cb = false;

	if (sock->client_psk_cb != NULL) {
        LOG_DEBUG("sock_dtls: requesting the application\n");

		/* this must be set with the api function */
		credential.tag = sock->client_psk_cb(sock, &remote->ep, sock->tags,
							sock->tags_len,(const char *)hint, hint_len);
		if (credential.tag != CREDMAN_TAG_EMPTY) {
			int ret = credman_get(&credential, credential.tag, CREDMAN_TYPE_PSK);
			if (ret == CREDMAN_OK) {
				found_cb = true;	
			}
		}
	}
	if (found_cb != true){
		/* only the var tag is set, rest is nulled */
		credman_credential_t first = { .tag = CREDMAN_TAG_EMPTY};
		for (unsigned i = 0; i < sock->tags_len && found_cb == false; i++) {
			int ret =  credman_get(&credential, sock->tags[i], CREDMAN_TYPE_PSK);
			if (ret == CREDMAN_OK) {
				if (hint_len == 0) {
					LOG_DEBUG("No hint set, we take the first cred");
					found_cb = true;
				}
				else {
					/* setting the first cred in case we have no matching cred in the end */
					if (first.tag == CREDMAN_TAG_EMPTY) {
						memcpy(&first, &credential, sizeof(credman_credential_t));
					}
					/* Checking if we found the hint */
					if (hint_len == credential.params.psk.hint.len &&
                        !strncmp((const char *)credential.params.psk.hint.s, hint, hint_len)) {
                        found_cb = true;
                    }
				}
			}
		}
		/* No hit, using the first cred */
		if (!found_cb && first.tag != CREDMAN_TAG_EMPTY) {
            memcpy(&credential, &first, sizeof(credman_credential_t));
            found_cb = true;
        }
	}
	if (found_cb) {
		if ((credential.params.psk.id.len >= max_id_len) ||	(credential.params.psk.key.len > max_key_len)) {
			/* Wolfssl buffer cant hold the key */
			LOG_ERROR("Wolfssl buffer cant hold the key");
			return 0; 
		}
		/* move identity and key into wolfssl */
		memcpy(identity, credential.params.psk.id.s, credential.params.psk.id.len);
        identity[credential.params.psk.id.len] = '\0';
        memcpy(key, credential.params.psk.key.s, credential.params.psk.key.len);

        return credential.params.psk.key.len;
	}

	
	//todo: find out return values
	return 0;
}
#endif



/* public functions */
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
	
	//todo: just testing	
	/* NEU: Den übergebenen Tag im Backend speichern! */
	sock->tags[0] = tag;
	sock->tags_len = 1;
	///
	/* setting role */
	sock->role = role;
	WOLFSSL_METHOD *method = NULL;
//todo:version 1_0 und 1_1
	/* Choosing the right tls method */	
	if (version == SOCK_DTLS_1_2) {
		if (role == SOCK_DTLS_CLIENT) {
			method = wolfDTLSv1_2_client_method();
		} 
		else if (role == SOCK_DTLS_SERVER) {
			LOG_INFO("SERVER\n");
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


	/* enable the psk stuff */
#ifdef MODULE_WOLFSSL_PSK
	wolfSSL_CTX_set_psk_client_callback(sock->ctx, _wolfssl_psk_client_cb);
	wolfSSL_CTX_set_psk_server_callback(sock->ctx, _wolfssl_psk_server_cb);

	//todo erlaubt psk algos?
	if (wolfSSL_CTX_set_cipher_list(sock->ctx, "PSK-AES128-CCM-8") != WOLFSSL_SUCCESS) {
        puts("Error setting client cipher suite");
        return -1;
    }
#endif

#ifdef HAVE_SECURE_RENEGOTIATION
    if (wolfSSL_CTX_UseSecureRenegotiation(sock->ctx) != WOLFSSL_SUCCESS) {
        puts("Error enabling secure renegotiation");
    }
#endif

	sock->role = role;
	sock->udp_sock = udp_sock;
	LOG_INFO("dtls object initialized\n");

	return 0;
}

int _load_client_ecc_certs(sock_dtls_t *sock, credman_tag_t tag,
		sock_dtls_session_t *remote, const sock_udp_ep_t *ep)
{

#ifdef CONFIG_DTLS_ECC
	/* convert certs ig */
	(void)tag;	
    credman_credential_t credential;

    credential.tag = CREDMAN_TAG_EMPTY;
    LOG_DEBUG("sock_dtls: get ECDSA key\n");
	int ret;
    /* if the application set a callback , try to select credential from there */
    if (sock->rpk_cb) {
        LOG_DEBUG("sock_dtls: requesting the application\n");
        credential.tag = sock->rpk_cb(sock, (sock_udp_ep_t *)ep, sock->tags, sock->tags_len);
        if (credential.tag != CREDMAN_TAG_EMPTY) {
            ret = credman_get(&credential, credential.tag, CREDMAN_TYPE_ECDSA);
            if (ret != CREDMAN_OK) {
                credential.tag = CREDMAN_TAG_EMPTY;
            }
        }
    }
//todo: we have to choose the tag set in tag 
    if (credential.tag == CREDMAN_TYPE_EMPTY) {
        /* if could not get credential try to fetch the first valid credential */
        for (unsigned i = 0; i < sock->tags_len; i++) {
            ret = credman_get(&credential, sock->tags[i], CREDMAN_TYPE_ECDSA);
            if (ret == CREDMAN_OK) {
                break;
            }
        }

        if (ret != CREDMAN_OK) {
            LOG_DEBUG("sock_dtls: no valid credential registered\n");
			//todo: what return value
            return -1;
        }
    }
	/* load server public keys */
	for (size_t i = 0; i < credential.params.ecdsa.client_keys_size; i++) {

		ecc_key server_key;
		wc_ecc_init(&server_key);

		
		if (wc_ecc_import_unsigned(&server_key, 
                         (const byte *)credential.params.ecdsa.client_keys[i].x,
                         (const byte *)credential.params.ecdsa.client_keys[i].y,
                         NULL,
                         ECC_SECP256R1) == 0) {

			byte server_der_buf[150];
			
			word32 server_der_size = wc_EccPublicKeyToDer(&server_key, server_der_buf, sizeof(server_der_buf),1);
			if (server_der_size > 0) {
				if (sock->role == SOCK_DTLS_SERVER) {
					wolfSSL_CTX_set_expected_rpk(sock->ctx, server_der_buf, server_der_size);
				} else {
					wolfSSL_set_expected_rpk(remote->ssl, server_der_buf, server_der_size);
				}
			}
		}
		wc_ecc_free(&server_key);

	}

	ecc_key my_key;
	//https://www.wolfssl.com/documentation/manuals/wolfssl/group__ECC.html#function-wc_ecc_init
    wc_ecc_init(&my_key);
	//https://www.wolfssl.com/documentation/manuals/wolfssl/group__ECC.html#function-wc_ecc_import_raw	
	//
	//todo: wir nehmen den rawen key und machen dem zu einem ecc key. 
	//da schein priv und pub inkludiert zu sein
	//dann machen wir aus dem einen der pub und einen der key?
	// wir freenen den ecc key
	// und laden dann den key an wolfssl
	if (wc_ecc_import_unsigned(&my_key, 
                         (const byte *)credential.params.ecdsa.public_key.x,
                         (const byte *)credential.params.ecdsa.public_key.y,
                         (const byte *)credential.params.ecdsa.private_key,
                         ECC_SECP256R1) == 0) {

		byte der_buf[150];
		//Distinguished Encoding Rules
		//https://www.wolfssl.com/documentation/manuals/wolfssl/group__ASN.html#function-wc_ecckeytoder

		word32 der_sz = wc_EccKeyToDer(&my_key, der_buf, sizeof(der_buf));
		if (der_sz > 0) {
			if (sock->role == SOCK_DTLS_SERVER) {
				wolfSSL_CTX_use_PrivateKey_buffer(sock->ctx, der_buf, der_sz, WOLFSSL_FILETYPE_ASN1);
			} else {
				wolfSSL_use_PrivateKey_buffer(remote->ssl, der_buf, der_sz, WOLFSSL_FILETYPE_ASN1);
			}
		}

		word32 pub_sz = wc_EccPublicKeyToDer(&my_key, der_buf, sizeof(der_buf), 1);
		if (pub_sz > 0) {
			if (sock->role == SOCK_DTLS_SERVER) {
				wolfSSL_CTX_use_certificate_buffer(sock->ctx, der_buf, pub_sz, WOLFSSL_FILETYPE_ASN1);
			} else {
				wolfSSL_use_certificate_buffer(remote->ssl, der_buf, pub_sz, WOLFSSL_FILETYPE_ASN1);
			}
		}
	}
	wc_ecc_free(&my_key);
	if (sock->role == SOCK_DTLS_SERVER) {
		if (wolfSSL_CTX_set_cipher_list(sock->ctx, "ECDHE-ECDSA-AES128-CCM-8") != WOLFSSL_SUCCESS) {
			LOG_ERROR("could not set cipher\n");
			return -1;
		}
	} else {
		if (wolfSSL_set_cipher_list(remote->ssl, "ECDHE-ECDSA-AES128-CCM-8") != WOLFSSL_SUCCESS) {
			LOG_ERROR("could not set cipher\n");
			return -1;
		}
	}
	/* enables verifying */
	if (sock->role == SOCK_DTLS_SERVER) {
		wolfSSL_CTX_set_verify(sock->ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
	} else {
		wolfSSL_set_verify(remote->ssl, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
	}
//	wolfSSL_set_verify(remote->ssl, WOLFSSL_VERIFY_NONE, NULL);
#ifdef HAVE_RPK
    char cert_type = WOLFSSL_CERT_TYPE_RPK;
    /* Fordert an, dass der Client ein RPK senden darf */
	if (sock->role == SOCK_DTLS_SERVER) {
		wolfSSL_CTX_set_client_cert_type(sock->ctx, &cert_type, 1);
		wolfSSL_CTX_set_server_cert_type(sock->ctx , &cert_type, 1);
	} else {
		wolfSSL_set_client_cert_type(remote->ssl, &cert_type, 1);
		wolfSSL_set_server_cert_type(remote->ssl, &cert_type, 1);
	}
#endif
#endif
	return 0;
}

int sock_dtls_session_init(sock_dtls_t *sock, const sock_udp_ep_t *ep,
		sock_dtls_session_t *remote){ //todo: we store our remote in sock?	
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
	remote->dtls_sock = sock; //todo: hier abuse ich die i/o context um auf alles zuzugreifen können
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


	if (_load_client_ecc_certs(sock, 0, remote, ep) == -1 ){
		//todo: better errormanagement
		return -1;
	}

	if (!remote->ssl) {
		LOG_ERROR("Error allocating ssl session\n");
		return -ENOMEM;
	}
	wolfSSL_SetIOReadCtx(remote->ssl, remote);
	wolfSSL_SetIOWriteCtx(remote->ssl, remote);
	/* start the handshake */
#define TIMEOUT 5
	wolfSSL_dtls_set_timeout_init(remote->ssl, TIMEOUT);
	//wolfSSL_dtls_set_timeout_max(remote->ssl, 0);
	wolfSSL_set_using_nonblock(remote->ssl, 1);
	LOG_INFO("starting handshake with server\n");
	int ret = wolfSSL_connect(remote->ssl);
	wolfSSL_set_using_nonblock(remote->ssl, 0);
	
	if (ret != SSL_SUCCESS) { 
		int error; error = wolfSSL_get_error(remote->ssl, (int)ret);
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
	(void) aux;
	assert(sock);

	if (!sock || !remote) {
		return -EINVAL;
	}	
	if (!sock->udp_sock) {
		return -EADDRNOTAVAIL;
		//todo: do i need to check for sock->local_ep or smth?
	}
	if (timeout == SOCK_NO_TIMEOUT) {
		remote->has_deadline = false;
		remote->deadline_us = 0;
	} else {
		remote->has_deadline = true;
		remote->deadline_us = ztimer_now(ZTIMER_USEC) + timeout;
	}

	if (sock->role == SOCK_DTLS_SERVER) {
		if (remote->ssl == NULL) {
			_load_client_ecc_certs(sock, 0, remote, &remote->ep);

			LOG_INFO("Setting up server session\n");
			remote->ssl = wolfSSL_new(sock->ctx);
			
			if (remote->ssl == NULL) {
				LOG_ERROR("SSL object is null\n");	
				return -ENOMEM; 
			}
			
			remote->udp_sock = sock->udp_sock;
			remote->dtls_sock = sock;
			wolfSSL_SetIOReadCtx(remote->ssl, remote);
			wolfSSL_SetIOWriteCtx(remote->ssl, remote);
			wolfSSL_dtls_set_timeout_init(remote->ssl, 5);
			wolfSSL_set_using_nonblock(remote->ssl, 1);
			remote->handshake_successfull = false;
		}

		while (!wolfSSL_is_init_finished(remote->ssl) || !remote->handshake_successfull){
			
			if (remote->has_deadline && ztimer_now(ZTIMER_USEC) >= remote->deadline_us) {
				return -ETIMEDOUT;
			}
			ssize_t ret = wolfSSL_accept(remote->ssl);
			if (ret == SSL_SUCCESS) {
				LOG_INFO("New connection accepted\n");
				remote->handshake_successfull = true;
				return -SOCK_DTLS_HANDSHAKE;
			}
			
			int error = wolfSSL_get_error(remote->ssl, (int)ret);
			if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE) {
				LOG_ERROR("Critical while accepting: %d\n", wolfSSL_get_error(remote->ssl, ret));
				return -1;
			}
		}
	}



	while (sock->role != SOCK_DTLS_SERVER && (!wolfSSL_is_init_finished(remote->ssl) || !remote->handshake_successfull)){
		puts("loop");
		// und dann auch das timeout in die die jjk
		if (remote->has_deadline && ztimer_now(ZTIMER_USEC) >= remote->deadline_us) {
			return -ETIMEDOUT;
		}
		/* wolfssl must be set to nonblocking so we can use our own timer */
		int ret = wolfSSL_connect(remote->ssl);
		if (ret == SSL_SUCCESS) {
			LOG_INFO("handshake was completed\n");
			remote->handshake_successfull = true;
			return -SOCK_DTLS_HANDSHAKE;
		}
		int error = wolfSSL_get_error(remote->ssl, ret);
		if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE) {
			/* critical error */
			LOG_ERROR("Critical while connecting: %d\n", error);
			sock_dtls_close(sock);
			sock_dtls_session_destroy(sock, remote);
			return -1;
		}

	}

	
	int ret;
	while (remote->deadline_us == 0 || ztimer_now(ZTIMER_USEC) >= remote->deadline_us) {
		
		ret = wolfSSL_read(remote->ssl, data, (int)maxlen);
		if (ret > 0) {
			LOG_INFO("data successfull read\n");
			/* returning bytes read */
			return ret;
		}
		int error = wolfSSL_get_error(remote->ssl, ret);
		if (timeout == 0 || error ==  WOLFSSL_ERROR_WANT_READ) {
			//LOG_INFO("timeout is 0 and no data to read\n");
			return -EAGAIN;
		}
		// ich kann das timeout garnicht setzen...
		// vermutlich das timeout in der session speichern
	}
			// WOLFSSL_ERROR_ZERO_RETURN wenn connection geschlossen
	

	return -1;

	//todo: close session here
}
void sock_dtls_close(sock_dtls_t *sock) {
	assert(sock);
	assert(sock->ctx);

	wolfSSL_CTX_free(sock->ctx);
	sock->ctx = NULL;
	LOG_INFO("Closed dtls\n");
	
}
void sock_dtls_session_destroy(sock_dtls_t *sock, sock_dtls_session_t *remote) {
	assert(sock);
	assert(remote);
	assert(remote->ssl);


	wolfSSL_shutdown(remote->ssl);
	wolfSSL_free(remote->ssl);
	
	remote->ssl = NULL;
	LOG_INFO("Closed dtls session\n");
}

ssize_t sock_dtls_sendv_aux (sock_dtls_t *sock, 
		sock_dtls_session_t *remote,
		const iolist_t *snips,
	   	uint32_t timeout,
	   	sock_dtls_aux_tx_t *aux){
	assert(sock);
	assert(remote);
	assert(remote->ssl);

	/* EADDRINUSE */
	if (!sock->udp_sock){
		//todo: check if we need to check for speciality the ep
		return -EADDRINUSE;
	}
	//todo: check for return value flag errors here as in the api
	
	if (!wolfSSL_is_init_finished(remote->ssl) || !remote->handshake_successfull){
		LOG_INFO("Trying to send data while the handshake is not finished. Starting handshake");
		ssize_t res = sock_dtls_recv(sock, remote, NULL, 0, timeout);
		if (res < 0) {
			//todo error checking
			return -1;
		}	
	}


	if (snips == NULL) {
		//todo: error logging
		return -1;
	}
	

	if (snips->iol_next != NULL) {
//		LOG_ERROR("Wolfssl doesn not support vectored I/O");
		//todo: build one big message
		//und auch vielleicht in der docu
#define WOLFSSL_MAX_PAYLOAD_OR_SOMETHING 1280	
		static uint8_t buffer[WOLFSSL_MAX_PAYLOAD_OR_SOMETHING];
		//todo: make this a settable variable in the makefile	
		//todo: testen
		size_t buffer_len = 0;
		
		
		for (; snips; snips = snips->iol_next) {
			if (buffer_len + snips->iol_len > sizeof(buffer)) {
				LOG_ERROR("Message too big for our message buffer with size: %d", WOLFSSL_MAX_PAYLOAD_OR_SOMETHING);
        		return -1; /* Abbruch bei Überlauf, statt Speicher zu korrumpieren */
    		}
			memcpy(&buffer[buffer_len], snips->iol_base, snips->iol_len);
			buffer_len += snips->iol_len;
		}
				
		ssize_t res = wolfSSL_write(remote->ssl, buffer, (int)buffer_len);
		if (res == 0) {
			return -1;
			//todo: error handling
		}
		
		return -1;
	}

	ssize_t res = wolfSSL_write(remote->ssl, snips->iol_base, (int)snips->iol_len);
	if (res == 0) {
		if (res == SSL_ERROR_WANT_READ || res == SSL_ERROR_WANT_WRITE) {
			LOG_ERROR("The I/O is not ready");
			//todo: deal with it?
			return -1;
		}
		LOG_ERROR("Critical error occured: %d", wolfSSL_get_error(remote->ssl, res));
		return -1;

	}
	return 0;
}
	
