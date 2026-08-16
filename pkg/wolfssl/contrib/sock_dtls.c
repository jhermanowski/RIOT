/*
 * SPDX-FileCopyrightText: 2026 Frankfurt University of Applied Sciences
 * SPDX-FileCopyrightText: 2026 Jakob Hermanowski <todo>
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @{
 *
 * @file
 * @brief   WolfSSL implementation of @ref net_sock_dtls
 *
 * @author  Jakob Hermanowski <>
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


int _wolfssl_udp_send(WOLFSSL *ssl, char *buf, int sz, void *_ctx)
{
    (void)ssl;
    sock_dtls_session_t *session = (sock_dtls_session_t *)_ctx;
    if (session == NULL) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    ssize_t ret = sock_udp_send(session->udp_sock, (unsigned char *)buf, sz, &session->ep);

    if (ret <= 0) {
        /* HIER IST DER SCHLÜSSEL: Wir geben den exakten Fehler von RIOT aus
           UND wir prüfen, ob die IP-Daten im session-Struct noch leben! */
        LOG_ERROR("\n>>> UDP SEND FAILED! ret_code: %d, family: %d, port: %d, netif: %d <<<\n",
                  (int)ret, session->ep.family, session->ep.port, session->ep.netif);

        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    return (int)ret;
}

int _wolfssl_udp_receive(WOLFSSL *ssl, char *buf, int sz, void *_ctx)
{
    (void)ssl;
    sock_udp_ep_t ep;
    ssize_t ret;

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
        LOG_DEBUG("Nonblocking\n");
        timeout = 0;
    }
    else {
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
static unsigned int _wolfssl_psk_server_cb(WOLFSSL *ssl, const char *identity,
                                           unsigned char *key, unsigned int key_max_len)
{

    sock_dtls_session_t *remote = (sock_dtls_session_t *)wolfSSL_GetIOReadCtx(ssl);

    if (remote == NULL || remote->dtls_sock == NULL) {
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
static unsigned int _wolfssl_psk_client_cb(WOLFSSL *ssl, const char *hint,
                                           char *identity, unsigned int max_id_len,
                                           unsigned char *key, unsigned int max_key_len)
{
    /* the hint variable is set by wolfssl if the server gave us a hint */
    sock_dtls_session_t *remote = (sock_dtls_session_t *)wolfSSL_GetIOReadCtx(ssl);

    if (remote == NULL || remote->dtls_sock == NULL) {
        return 0;
    }

    /* access dtls_sock */
    sock_dtls_t *sock = remote->dtls_sock;

    if (sock->tags_len == 0) {
        LOG_DEBUG("No credman tags set\n");
        return 0;
    }
    size_t hint_len = 0;
    if (hint != NULL) {
        hint_len = strlen(hint);
        LOG_DEBUG("Hint given from server\n");
    }

    credman_credential_t credential;

    /* if the user has set his own callback in the application */
    bool found_cb = false;
    if (sock->client_psk_cb != NULL) {
        LOG_DEBUG("sock_dtls: requesting the application\n");

        /* this must be set with the api function */
        credential.tag = sock->client_psk_cb(sock, &remote->ep, sock->tags, sock->tags_len,
                                             (const char *)hint, hint_len);
        if (credential.tag != CREDMAN_TAG_EMPTY) {
            int ret = credman_get(&credential, credential.tag, CREDMAN_TYPE_PSK);
            if (ret == CREDMAN_OK) {
                found_cb = true;
            }
        }
    }
    if (found_cb != true) {
        /* only the var tag is set, rest is nulled */
        credman_credential_t first = { .tag = CREDMAN_TAG_EMPTY };
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
        if ((credential.params.psk.id.len >= max_id_len) ||
            (credential.params.psk.key.len > max_key_len)) {
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
 * Takes an initialized UDP sock and uses it for the transport. Memory allocation functions required by the underlying DTLS stack can be called in this function.
 */

int sock_dtls_create(sock_dtls_t *sock, sock_udp_t *udp_sock,
                     credman_tag_t tag, unsigned version, unsigned role)
{
    if (!sock || !udp_sock) {
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
    if (method == NULL) {
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


#ifdef MODULE_WOLFSSL_PSK
    /* set psk callbacks */
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

#ifdef CONFIG_DTLS_ECC
int _load_client_ecc_certs(sock_dtls_t *sock, credman_tag_t tag,
                           sock_dtls_session_t *remote, const sock_udp_ep_t *ep)
{

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
            LOG_ERROR("sock_dtls: no valid credential registered\n");
            //todo: what return value
            return -EINVAL;
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

            word32 server_der_size = wc_EccPublicKeyToDer(&server_key, server_der_buf,
                                                          sizeof(server_der_buf), 1);
            if (server_der_size > 0) {
                if (sock->role == SOCK_DTLS_SERVER) {
                    wolfSSL_CTX_set_expected_rpk(sock->ctx, server_der_buf, server_der_size);
                }
                else {
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
                wolfSSL_CTX_use_PrivateKey_buffer(sock->ctx, der_buf, der_sz,
                                                  WOLFSSL_FILETYPE_ASN1);
            }
            else {
                wolfSSL_use_PrivateKey_buffer(remote->ssl, der_buf, der_sz, WOLFSSL_FILETYPE_ASN1);
            }
        }

        word32 pub_sz = wc_EccPublicKeyToDer(&my_key, der_buf, sizeof(der_buf), 1);
        if (pub_sz > 0) {
            if (sock->role == SOCK_DTLS_SERVER) {
                wolfSSL_CTX_use_certificate_buffer(sock->ctx, der_buf, pub_sz,
                                                   WOLFSSL_FILETYPE_ASN1);
            }
            else {
                wolfSSL_use_certificate_buffer(remote->ssl, der_buf, pub_sz, WOLFSSL_FILETYPE_ASN1);
            }
        }
    }
    wc_ecc_free(&my_key);
    if (sock->role == SOCK_DTLS_SERVER) {
        if (wolfSSL_CTX_set_cipher_list(sock->ctx, "ECDHE-ECDSA-AES128-CCM-8") != WOLFSSL_SUCCESS) {
            LOG_ERROR("could not set cipher\n");
            return -EINVAL;
        }
    }
    else {
        if (wolfSSL_set_cipher_list(remote->ssl, "ECDHE-ECDSA-AES128-CCM-8") != WOLFSSL_SUCCESS) {
            LOG_ERROR("could not set cipher\n");
            return -EINVAL;
        }
    }
    /* enables verifying */
    if (sock->role == SOCK_DTLS_SERVER) {
        wolfSSL_CTX_set_verify(sock->ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                               0);
    }
    else {
        wolfSSL_set_verify(remote->ssl, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           0);
    }

    //todo: we can only use rpk rn?
#ifdef HAVE_RPK
    char cert_type = WOLFSSL_CERT_TYPE_RPK;
    /* Fordert an, dass der Client ein RPK senden darf */
    if (sock->role == SOCK_DTLS_SERVER) {
        wolfSSL_CTX_set_client_cert_type(sock->ctx, &cert_type, 1);
        wolfSSL_CTX_set_server_cert_type(sock->ctx, &cert_type, 1);
    }
    else {
        wolfSSL_set_client_cert_type(remote->ssl, &cert_type, 1);
        wolfSSL_set_server_cert_type(remote->ssl, &cert_type, 1);
    }
#endif

    return 0;
}
#endif

/* this function is only called by the client */
int sock_dtls_session_init(sock_dtls_t *sock, const sock_udp_ep_t *ep,
                           sock_dtls_session_t *remote)
{
    int ret;
    sock_udp_ep_t local;

    remote->handshake_successfull = false;


    if (sock == NULL || sock->udp_sock == NULL || (sock_udp_get_local(sock->udp_sock,
                                                                      &local) < 0)) {
        LOG_ERROR("udp_sock not set\n");
        return -EADDRNOTAVAIL;
    }
    if (ep == NULL) {
        LOG_ERROR("Endpoint is NULL\n");
        return -EINVAL;
    }
    if (ep->port == 0) {
        LOG_ERROR("The endpoint is invalid, port is set to 0\n");
        return -EINVAL;
    }
    if (sock->ctx == NULL) {
        LOG_ERROR("wolfSSL ctx is null\n");
        return -EINVAL;
    }

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

    /* prepare the remote party to connect to */
    if (&remote->ep != ep) {
        XMEMCPY(&remote->ep, ep, sizeof(sock_udp_ep_t));
    }
    remote->udp_sock = sock->udp_sock;
    /* we store the sockalso in the remote, to access it in the callback functions */
    remote->dtls_sock = sock;

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
    if (remote->ssl == NULL) {
        LOG_ERROR("Error allocating ssl session\n");
        return -ENOMEM;
    }

//todo: mit einem besseren define checken wenn makefile läuft
#ifdef CONFIG_DTLS_ECC
    ret = _load_client_ecc_certs(sock, 0, remote, ep);
    if (ret < 0) {
        return ret;
    }
#endif

    wolfSSL_SetIOReadCtx(remote->ssl, remote);
    wolfSSL_SetIOWriteCtx(remote->ssl, remote);

    /* start the handshake */
    LOG_INFO("starting handshake with server\n");

    /* we enable nonblocking so we only send out the client hello as specified in the sock_dtls api */
    wolfSSL_set_using_nonblock(remote->ssl, 1);
    ret = wolfSSL_connect(remote->ssl);
    /* disable nonblocking */
    wolfSSL_set_using_nonblock(remote->ssl, 0);

    /* 5 is set as standart dtls timeout */
    wolfSSL_dtls_set_timeout_init(remote->ssl, 5);

    if (ret != SSL_SUCCESS) {
        int error; error = wolfSSL_get_error(remote->ssl, (int)ret);
        if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
            LOG_INFO("Handshake was started\n");
            /* 1 is returned is handshake is started */
            return 1;
        }
        LOG_ERROR("fatal error occured: %d\n", error);
        return -EINVAL;
    }
    return 1;
}

int _handle_server_recv(sock_dtls_t *sock, sock_dtls_session_t *remote)
{

    /* Set up the session for the server */
    if (remote->ssl == NULL) {

#ifdef CONFIG_DTLS_ECC

        _load_client_ecc_certs(sock, 0, remote, &remote->ep);

#endif

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
        remote->handshake_successfull = false;

        wolfSSL_set_using_nonblock(remote->ssl, 0);
    }

    while (!wolfSSL_is_init_finished(remote->ssl) || !remote->handshake_successfull) {
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
    return 1;
}

int _finish_client_handshake(sock_dtls_t *sock, sock_dtls_session_t *remote)
{

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
    return 1;
}
ssize_t sock_dtls_recv_aux(sock_dtls_t *sock,
                           sock_dtls_session_t *remote, void *data,
                           size_t maxlen,
                           uint32_t timeout,
                           sock_dtls_aux_rx_t *aux)
{
    //fertig
    (void)aux;
    assert(sock);

    if (sock == NULL || remote == NULL) {
        return -EINVAL;
    }
    if (sock->udp_sock == NULL) {
        return -EADDRNOTAVAIL;
        //todo: do i need to check for sock->local_ep or smth?
    }
    if (timeout == SOCK_NO_TIMEOUT) {
        remote->has_deadline = false;
        remote->deadline_us = 0;
    }
    else {
        remote->has_deadline = true;
        remote->deadline_us = ztimer_now(ZTIMER_USEC) + timeout;
    }

    /* handle server recv */
    if (sock->role == SOCK_DTLS_SERVER) {
        int ret = _handle_server_recv(sock, remote);
        if (ret < 0) {
            return ret;
        }

    }

    /* finish handshake as client */
    while (sock->role != SOCK_DTLS_SERVER &&
           (!wolfSSL_is_init_finished(remote->ssl) || !remote->handshake_successfull)) {

        int ret = _finish_client_handshake(sock, remote);
        if (ret < 0) {
            return ret;
        }
    }

    /* recv message */
    while (true) {
        int ret = wolfSSL_read(remote->ssl, data, (int)maxlen);
        if (ret > 0) {
            LOG_DEBUG("Data successfull read\n");
            /* returning bytes read */
            return ret;
        }
        /* an error occured */
        int error = wolfSSL_get_error(remote->ssl, ret);
        if (error == SSL_ERROR_ZERO_RETURN) {
            LOG_INFO("Session was closed by peer\n");
            return -EINVAL;
        }
        if (error ==  WOLFSSL_ERROR_WANT_READ) {
            if (timeout == 0) {
                return -EAGAIN;
            }

            if (timeout != SOCK_NO_TIMEOUT) {
                if (ztimer_now(ZTIMER_USEC) >= remote->deadline_us) {
                    return -ETIMEDOUT;
                }
            }
            continue;
        }
        if (error == MEMORY_ERROR) {
            LOG_ERROR("wolfSSL memory error\n");
            return -ENOMEM;
        }
        if (error == BUFFER_ERROR) {
            LOG_ERROR("wolfSSL buffer error\n");
            return -ENOBUFS;
        }

        LOG_ERROR("wolfSSL_read error: %d\n", error);
        return -EINVAL;
    }
}
void sock_dtls_close(sock_dtls_t *sock)
{
    assert(sock);
    assert(sock->ctx);

    wolfSSL_CTX_free(sock->ctx);
    sock->ctx = NULL;
    LOG_INFO("Closed dtls\n");

}
void sock_dtls_session_destroy(sock_dtls_t *sock, sock_dtls_session_t *remote)
{
    assert(sock);
    assert(remote);
    assert(remote->ssl);


    wolfSSL_shutdown(remote->ssl);
    wolfSSL_free(remote->ssl);

    remote->ssl = NULL;
    memset(remote, 0, sizeof(sock_dtls_session_t));
    LOG_INFO("Closed dtls session\n");
}

ssize_t sock_dtls_sendv_aux(sock_dtls_t *sock,
                            sock_dtls_session_t *remote,
                            const iolist_t *snips,
                            uint32_t timeout,
                            sock_dtls_aux_tx_t *aux)
{
    (void)aux;
    assert(sock);

    if (sock->udp_sock == NULL) {
        return -EADDRINUSE;
    }
    if (remote == NULL) {
        return -ENOTCONN;
    }
    //todo: Stupid auto connect feature
    /*	Handshake timeout in microseconds. If timeout > 0, will start a new handshake if no session exists yet. The function will block until handshake completed or timed out. May be SOCK_NO_TIMEOUT to block indefinitely until handshake complete.
     *	Die applikation muss
     *  memset(&session, 0, sizeof(session));
     *  memcpy(&session.ep, &endpoint, sizeof(sock_udp_ep_t));
     */
    if (remote != NULL && remote->ep.port == 0) {
        LOG_DEBUG("If you are using the autoconnect feature from this function\n");
        LOG_DEBUG(
            "Set your session object to NULL and then copy in the endpoint with port and all configured\n");
        return -EINVAL;
    }

    if (remote->ep.family == AF_UNSPEC) {
        return -EAFNOSUPPORT;
    }
    //todo: check if address is valid? how?

    /* if the session is NULL init the session */
    if (remote->ssl == NULL) {
        if (sock->role == SOCK_DTLS_SERVER) {
            LOG_ERROR("Server cannot initiate session. Client must connect first.\n");
            return -ENOTCONN;
        }

        if (timeout == 0) {
            LOG_ERROR("No session and no timeout\n");
            return -ENOTCONN;
        }

        LOG_DEBUG("Session does not exists yet, initing session now.\n");
        int ret = sock_dtls_session_init(sock, &remote->ep, remote);
        if (ret < 0) {
            LOG_ERROR("sock_dtls_sendv_aux: error while initing session: %d", ret);
            return ret;
        }
    }



    /* if the handshake is not finished finish it */
    if (!wolfSSL_is_init_finished(remote->ssl) || !remote->handshake_successfull) {
        if (sock->role == SOCK_DTLS_SERVER) {
            /* to reach this code path, the server must have tried to send a message while the handshake was started already.
             * should not happen */
            LOG_ERROR("Server cannot finish handshake a. Client must connect first.\n");
            return -ENOTCONN;
        }

        if (timeout == 0) {
            LOG_ERROR("Handshake not started and no timeout\n");
            return -ENOTCONN;
        }

        int ret = sock_dtls_recv(sock, remote, NULL, 0, timeout);
        if (ret != -SOCK_DTLS_HANDSHAKE) {
            LOG_ERROR("Handshake did not finish in given timeout\n");
            return ret;
        }
    }


    if (snips == NULL) {
        //todo: error logging
        return -1;
    }


    if (snips->iol_next != NULL) {
        LOG_ERROR("Wolfssl doesn not support vectored I/O");
        return -EINVAL;
    }

    ssize_t res = wolfSSL_write(remote->ssl, snips->iol_base, (int)snips->iol_len);
    /* 0 is returned on failure */
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
