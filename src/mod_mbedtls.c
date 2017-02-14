#include "first.h"

#include <errno.h>
#include <string.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include <mbedtls/platform.h>
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_free       free
#define mbedtls_calloc    calloc
#endif

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#define CHUNKSIZE (MBEDTLS_SSL_MAX_CONTENT_LEN / 64)
#define STATE_HANDSHAKE 0x0001
#define STATE_RECV_COMPLETE 0x0002

#include "base.h"
#include "log.h"
#include "plugin.h"

typedef struct {
    int enabled;
    buffer *pers;
    buffer *pemfile;
    buffer *cachain;
    buffer *dhmfile;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config **config_storage;

	mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt srvcert;
    mbedtls_x509_crt cachain;
    mbedtls_pk_context pkey;
    mbedtls_dhm_context dhm;
} plugin_data;

typedef struct {
    mbedtls_ssl_context ssl;
	int state;
    buffer *tlsext_server_name;
    plugin_config conf;
} handler_ctx;

static int _mod_mbedtls_read(void *ctl, unsigned char *data, int size)
{
	connection *con = ctl;
	int ret = recv(con->fd, data, size, MSG_NOSIGNAL);
	if (ret < 0  && errno == EAGAIN)
	{
		ret = MBEDTLS_ERR_SSL_WANT_READ;
	}
	else if (ret < 0)
		ret = MBEDTLS_ERR_NET_RECV_FAILED;
	return ret;
}

static int _mod_mbedtls_write(void *ctl, unsigned char *data, int size)
{
	connection *con = ctl;
	int ret = send(con->fd, data, size, MSG_NOSIGNAL);
	if (ret < 0  && errno == EAGAIN)
	{
		ret = MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	else if (ret < 0)
		ret = MBEDTLS_ERR_NET_SEND_FAILED;
	return ret;
}

static handler_ctx *
handler_ctx_init (plugin_data *p)
{
    int ret = 0;
    handler_ctx *hctx = calloc(1, sizeof(*hctx));
    force_assert(hctx);
    mbedtls_ssl_init(&hctx->ssl);

    if( ( ret = mbedtls_ssl_setup( &hctx->ssl, &p->conf ) ) != 0 )
    {
		char error[256];
		mbedtls_strerror(ret, error, 255);
		fprintf(stderr, "mbedtls_ssl_setup %X %s\n", -ret, error);
		free(hctx);
		return NULL;
    }

    return hctx;
}


static void
handler_ctx_free (handler_ctx *hctx)
{
	int ret;
    while ((ret = mbedtls_ssl_close_notify(&hctx->ssl)) == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    mbedtls_ssl_free(&hctx->ssl);
    buffer_free(hctx->tlsext_server_name);
    free(hctx);
}


INIT_FUNC(mod_mbedtls_init)
{
	plugin_data *config;

	config = mbedtls_calloc(1, sizeof(*config));

	return config;
}


FREE_FUNC(mod_mbedtls_free)
{
    plugin_data *p = p_d;
    if (!p) return HANDLER_GO_ON;

    if (p->config_storage) {
        for (size_t i = 0; i < srv->config_context->used; ++i) {
            plugin_config *s = p->config_storage[i];
            if (NULL == s) continue;

            buffer_free(s->pers);
            buffer_free(s->pemfile);
            buffer_free(s->cachain);
            buffer_free(s->dhmfile);
            free(s);
        }
        free(p->config_storage);
    }

	mbedtls_dhm_free(&p->dhm);
	mbedtls_x509_crt_free(&p->srvcert);
	mbedtls_pk_free(&p->pkey);
	mbedtls_ctr_drbg_free(&p->ctr_drbg);
	mbedtls_entropy_free(&p->entropy);
	mbedtls_ssl_config_free(&p->conf);

	mbedtls_free(p);

    UNUSED(srv);
    return HANDLER_GO_ON;
}

void mod_mbedtls_set(plugin_data *config, plugin_config *modconfig)
{
	int ret;
	int is_set_pemkey = 0;

	if (!modconfig)
		return;

	mbedtls_x509_crt_init(&config->srvcert);
	mbedtls_x509_crt_init(&config->cachain);

	mbedtls_ssl_config_init(&config->conf);

	mbedtls_ctr_drbg_init(&config->ctr_drbg);
	mbedtls_entropy_init(&config->entropy);

	ret = mbedtls_ssl_config_defaults(&config->conf,
		MBEDTLS_SSL_IS_SERVER,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret)
		fprintf(stderr, "mbedtls_ssl_config_defaults %X\n", -ret);

	if (!buffer_string_is_empty(modconfig->pemfile))
	{
		ret = mbedtls_x509_crt_parse_file(&config->srvcert, (const char *) modconfig->pemfile->ptr);
		if (ret)
		{
			fprintf(stderr, "mbedtls_x509_crt_parse_file %X %s\n", -ret, modconfig->pemfile->ptr);
		}
		else
			is_set_pemkey++;
		mbedtls_pk_init(&config->pkey);

		ret =  mbedtls_pk_parse_keyfile(&config->pkey, (const char *) modconfig->pemfile->ptr, NULL);
		if (ret)
			fprintf(stderr, "mbedtls_pk_parse_keyfile %X\n", -ret);
		else
			is_set_pemkey++;
	}
	if (!buffer_string_is_empty(modconfig->cachain))
	{
		ret = mbedtls_x509_crt_parse_file(&config->cachain, modconfig->cachain->ptr);
		if (ret)
			fprintf(stderr, "mbedtls_x509_crt_parse_file cachain %X\n", -ret);
		else
			mbedtls_ssl_conf_ca_chain(&config->conf, &config->cachain, NULL);
	}

	if (!buffer_string_is_empty(modconfig->pers))
	{
		ret = mbedtls_ctr_drbg_seed(&config->ctr_drbg, mbedtls_entropy_func, &config->entropy,
			(const unsigned char *) modconfig->pers->ptr, strlen(modconfig->pers->ptr));
		if (ret)
			printf("mbedtls_ctr_drbg_seed %d\n", ret);
		else
			mbedtls_ssl_conf_rng(&config->conf, mbedtls_ctr_drbg_random, &config->ctr_drbg );
	}

	if (!buffer_string_is_empty(modconfig->pers))
	{
		ret = mbedtls_ctr_drbg_seed(&config->ctr_drbg, mbedtls_entropy_func, &config->entropy,
			(unsigned char *)modconfig->pers->ptr, strlen(modconfig->pers->ptr));
		if (ret)
			fprintf(stderr, "mbedtls_ctr_drbg_seed %X\n", -ret);
		else
			mbedtls_ssl_conf_rng(&config->conf, mbedtls_ctr_drbg_random, &config->ctr_drbg );
	}

	if (is_set_pemkey == 2)
	{
		ret = mbedtls_ssl_conf_own_cert(&config->conf, &config->srvcert, &config->pkey);
		if (ret)
			fprintf(stderr, "mbedtls_ssl_conf_own_cert %X\n", -ret);
	}

	if (!buffer_string_is_empty(modconfig->dhmfile))
	{
		mbedtls_dhm_init(&config->dhm);
		ret = mbedtls_dhm_parse_dhmfile(&config->dhm, modconfig->dhmfile->ptr);
		if (ret)
			fprintf(stderr, "mbedtls_dhm_parse_dhmfile %X\n", -ret);
	}
}

SETDEFAULTS_FUNC(mod_mbedtls_set_defaults)
{
    UNUSED(srv);
    plugin_data *p = p_d;
    config_values_t cv[] = {
        { "ssl.engine",    NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 1 */
        { "ssl.pemfile",   NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 2 */
        { "ssl.dh-file",   NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 4 */
        { "ssl.ca-file",   NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 3 */
        { NULL,            NULL, T_CONFIG_UNSET,   T_CONFIG_SCOPE_UNSET }
    };

    if (!p) return HANDLER_ERROR;
    p->config_storage = calloc(1, srv->config_context->used * sizeof(plugin_config *));

    for (size_t i = 0; i < srv->config_context->used; i++) {
        data_config const* config = (data_config const*)srv->config_context->data[i];
        plugin_config *s = calloc(1, sizeof(plugin_config));

        s->enabled   = 0;
        s->pers      = buffer_init();
        s->pemfile   = buffer_init();
		s->dhmfile   = buffer_init();
        s->cachain   = buffer_init();
        cv[0].destination = &(s->enabled);
        cv[1].destination = s->pemfile;
        cv[2].destination = s->dhmfile;
        cv[3].destination = s->cachain;
        p->config_storage[i] = s;

        if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
        }
    }

    for (size_t i = 0; i < srv->config_context->used; i++) {
        plugin_config *s = p->config_storage[i];
        if (!buffer_string_is_empty(s->pemfile))
			fprintf(stderr, "SSL %d config %s\n", i, s->pemfile->ptr);
        if (s->enabled)
        {
			if (buffer_string_is_empty(s->pers))
				buffer_copy_string_len(s->pers, CONST_STR_LEN("lighttpd-mbedtls"));

			fprintf(stderr, "SSL enabled for %d\n", i);
            mod_mbedtls_set(p, s);
		}
    }

    return HANDLER_GO_ON;
}


#define PATCH(x) \
    p->conf.x = s->x;
static int
mod_mbedtls_patch_connection (server *srv, connection *con, handler_ctx *p)
{
    UNUSED(srv);
    UNUSED(con);
    UNUSED(p);
    return 0;
}
#undef PATCH

static int
connection_read_cq_ssl (server *srv, connection *con,
                        chunkqueue *cq, off_t max_bytes)
{
	int ret;
	size_t mem_len = 0;
	plugin_data *p = con->network_data;
	handler_ctx *ctx = con->plugin_ctx[p->id];
	if (!(ctx->state & STATE_HANDSHAKE)) {
		ctx->state &= STATE_RECV_COMPLETE;
		while((ret = mbedtls_ssl_handshake(&ctx->ssl)) != 0 ) {
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
				break;
		}
		if (ret) {
			char error[256];
			mbedtls_strerror(ret, error, 255);
			fprintf(stderr, "mbedtls_ssl_handshake %X %s %d\n", -ret, error, p->id);
			return 0;
		}
		ctx->state |= STATE_HANDSHAKE;
	}
	if (ctx->state & STATE_RECV_COMPLETE)
		return 0;

	do {
		char *mem = NULL;
        chunkqueue_get_memory(con->read_queue, &mem, &mem_len, 0,
							CHUNKSIZE);
		ret = mbedtls_ssl_read(&ctx->ssl, (unsigned char *)mem, mem_len);
		if (ret > 0)
			chunkqueue_use_memory(con->read_queue, ret);
		else
			chunkqueue_use_memory(con->read_queue, 0);
	}
	while (ret == MBEDTLS_ERR_SSL_WANT_READ);
	if (ret < 0) {
		switch (ret)
		{
			case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
			case MBEDTLS_ERR_NET_CONN_RESET:
				return -2;
			default:
				return -1;
		}
	} else if (ret < mem_len)
		ctx->state |= STATE_RECV_COMPLETE;
	return 0;
}

static int
load_next_chunk (server *srv, chunkqueue *cq, off_t max_bytes,
                 const char **data, size_t *data_len)
{
    chunk * const c = cq->first;

#define LOCAL_SEND_BUFSIZE (64 * 1024)
    /* this is a 64k sendbuffer
     *
     * it has to stay at the same location all the time to satisfy the needs
     * of SSL_write to pass the SAME parameter in case of a _WANT_WRITE
     *
     * buffer is allocated once, is NOT realloced and is NOT freed at shutdown
     * -> we expect a 64k block to 'leak' in valgrind
     * */
    static char *local_send_buffer = NULL;

    force_assert(NULL != c);

    switch (c->type) {
    case MEM_CHUNK:
        {
            size_t have;

            force_assert(c->offset >= 0
                         && c->offset <= (off_t)buffer_string_length(c->mem));

            have = buffer_string_length(c->mem) - c->offset;
            if ((off_t) have > max_bytes) have = max_bytes;

            *data = c->mem->ptr + c->offset;
            *data_len = have;
        }
        return 0;

    case FILE_CHUNK:
        if (NULL == local_send_buffer) {
            local_send_buffer = malloc(LOCAL_SEND_BUFSIZE);
            force_assert(NULL != local_send_buffer);
        }

        if (0 != chunkqueue_open_file_chunk(srv, cq)) return -1;

        {
            off_t offset, toSend;

            force_assert(c->offset >= 0 && c->offset <= c->file.length);
            offset = c->file.start + c->offset;
            toSend = c->file.length - c->offset;

            if (toSend > LOCAL_SEND_BUFSIZE) toSend = LOCAL_SEND_BUFSIZE;
            if (toSend > max_bytes) toSend = max_bytes;

            if (-1 == lseek(c->file.fd, offset, SEEK_SET)) {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "lseek: ", strerror(errno));
                return -1;
            }
            if (-1 == (toSend = read(c->file.fd, local_send_buffer, toSend))) {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "read: ", strerror(errno));
                return -1;
            }

            *data = local_send_buffer;
            *data_len = toSend;
        }
        return 0;
    }

    return -1;
}

static int
connection_write_cq_ssl (server *srv, connection *con,
                         chunkqueue *cq, off_t max_bytes)
{
	int ret;
	plugin_data *p = con->network_data;
	handler_ctx *ctx = con->plugin_ctx[p->id];
    while (max_bytes > 0 && NULL != cq->first) {
        const char *data;
        size_t data_len;

        if (0 != load_next_chunk(srv,cq,max_bytes,&data,&data_len)) return -1;

		ret = mbedtls_ssl_write(&ctx->ssl, (unsigned char *)data, data_len);
		if (ret == MBEDTLS_ERR_SSL_WANT_READ)
		{
			con->is_readable = -1;
		}
		else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			con->is_writable = -1;
		}
		else if (ret == MBEDTLS_ERR_SSL_CLIENT_RECONNECT)
		{
		}
		else if (ret == 0)
		{
			return -2;
		}
		else if (ret > 0)
		{
			chunkqueue_mark_written(cq, ret);
			max_bytes -= ret;

			if ((size_t) ret < data_len) break;
		}
	}
	return ret;

}

CONNECTION_FUNC(mod_mbedtls_handle_con_accept) /*server *srv, connection *con, void *p_d*/
{
    server_socket *srv_sock = con->srv_socket;
    if (srv_sock->is_ssl)
    {
        plugin_data *p = p_d;
        handler_ctx *hctx = handler_ctx_init(p);
        con->plugin_ctx[p->id] = hctx;
		mbedtls_ssl_set_bio(&hctx->ssl, con, (mbedtls_ssl_send_t *)_mod_mbedtls_write, (mbedtls_ssl_recv_t *)_mod_mbedtls_read, NULL);

        fprintf(stderr, "p->id %d\n", p->id);
        mod_mbedtls_patch_connection(srv, con, hctx);

        con->network_read = connection_read_cq_ssl;
        con->network_write = connection_write_cq_ssl;
        con->network_data = p_d;
    }

    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_mbedtls_handle_con_shut_wr)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    UNUSED(srv);
    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_mbedtls_handle_con_close)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    handler_ctx_free(hctx);

    UNUSED(srv);
    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_mbedtls_handle_request_env)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    UNUSED(srv);
    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_mbedtls_handle_uri_raw)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

	mod_mbedtls_handle_request_env(srv, con, p);

    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_mbedtls_handle_request_reset)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    /*
     * XXX: preserve (for now) lighttpd historical behavior which resets
     * tlsext_server_name after each request, meaning SNI is valid only for
     * initial request, prior to reading request headers.  Probably should
     * instead validate that Host header (or authority in request line)
     * matches SNI server name for all requests on the connection on which
     * SNI extension has been provided.
     */
    buffer_reset(hctx->tlsext_server_name);

    UNUSED(srv);
    return HANDLER_GO_ON;
}


int mod_mbedtls_plugin_init (plugin *p);
int mod_mbedtls_plugin_init (plugin *p)
{
    p->version      = LIGHTTPD_VERSION_ID;
    p->name         = buffer_init_string("mbedtls");
    p->init         = mod_mbedtls_init;
    p->cleanup      = mod_mbedtls_free;
    p->set_defaults = mod_mbedtls_set_defaults;

    p->handle_connection_accept  = mod_mbedtls_handle_con_accept;
    p->handle_connection_shut_wr = mod_mbedtls_handle_con_shut_wr;
    p->handle_connection_close   = mod_mbedtls_handle_con_close;
    p->handle_uri_raw            = mod_mbedtls_handle_uri_raw;
    p->handle_request_env        = mod_mbedtls_handle_request_env;
    p->connection_reset          = mod_mbedtls_handle_request_reset;

    p->data         = NULL;

    return 0;
}
