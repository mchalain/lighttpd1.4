#include "first.h"

#include <errno.h>
#include <string.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>

#include "base.h"
#include "log.h"
#include "plugin.h"

typedef struct {
    buffer *pers;
    buffer *crtfile;
    buffer *pemfile;
    buffer *cachain;
    buffer *dhmfile;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config **config_storage;
} plugin_data;

typedef struct {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    buffer *tlsext_server_name;
    plugin_config conf;
} handler_ctx;


static handler_ctx *
handler_ctx_init (void)
{
    int ret = 0;
    handler_ctx *hctx = calloc(1, sizeof(*hctx));
    force_assert(hctx);
    mbedtls_ssl_init(&hctx->ssl);

    if( ( ret = mbedtls_ssl_setup( &hctx->ssl, &hctx->conf ) ) != 0 )
    {
		free(hctx);
		return NULL;
    }
    return hctx;
}


static void
handler_ctx_free (handler_ctx *hctx)
{
    while ((ret = mbedtls_ssl_close_notify(&ctx->ssl)) == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    mbedtls_ssl_free(&hctx->ssl);
    buffer_free(hctx->tlsext_server_name);
    free(hctx);
}


INIT_FUNC(mod_mbedtls_init)
{
	int ret;
	int is_set_pemkey = 0;
	plugin_data *config;

	config = mbedtls_calloc(1, sizeof(*config));
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
		printf("mbedtls_ssl_config_defaults %d\n", ret);

	if (modconfig->crtfile)
	{
		ret = mbedtls_x509_crt_parse_file(&config->srvcert, (const char *) modconfig->crtfile);
		if (ret)
			printf("mbedtls_x509_crt_parse_file %d\n", ret);
		else
			is_set_pemkey++;
		mbedtls_pk_init(&config->pkey);
		if (modconfig->pemfile)
		{
			ret =  mbedtls_pk_parse_keyfile(&config->pkey, (const char *) modconfig->pemfile, NULL);
			if (ret)
				printf("mbedtls_pk_parse_keyfile %d\n", ret);
			else
				is_set_pemkey++;
		}
		else
		{
			ret =  mbedtls_pk_parse_keyfile(&config->pkey, (const char *) modconfig->crtfile, NULL);
			if (ret)
				printf("mbedtls_pk_parse_keyfile %d\n", ret);
			else
				is_set_pemkey++;
		}
	}
	if (modconfig->cachain)
	{
		ret = mbedtls_x509_crt_parse_file(&config->cachain, (const char *) modconfig->cachain);
		if (ret)
			printf("mbedtls_x509_crt_parse_file cachain %d\n", ret);
		else
			mbedtls_ssl_conf_ca_chain(&config->conf, &config->cachain, NULL);
	}

	if (modconfig->pers)
	{
		ret = mbedtls_ctr_drbg_seed(&config->ctr_drbg, mbedtls_entropy_func, &config->entropy,
			(const unsigned char *) modconfig->pers, strlen(modconfig->pers));
		if (ret)
			printf("mbedtls_ctr_drbg_seed %d\n", ret);
		else
			mbedtls_ssl_conf_rng(&config->conf, mbedtls_ctr_drbg_random, &config->ctr_drbg );
	}

	if (is_set_pemkey == 2)
	{
		ret = mbedtls_ssl_conf_own_cert(&config->conf, &config->srvcert, &config->pkey);
		if (ret)
			printf("mbedtls_ssl_conf_own_cert %d\n", ret);
	}

	if (modconfig->dhmfile)
	{
		mbedtls_dhm_init(&config->dhm);
		ret = mbedtls_dhm_parse_dhmfile(&config->dhm, modconfig->dhmfile);
		if (ret)
			printf("mbedtls_dhm_parse_dhmfile %d\n", ret);
	}

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

            buffer_free(s->pemfile);
            buffer_free(s->crtfile);
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


SETDEFAULTS_FUNC(mod_mbedtls_set_defaults)
{
    UNUSED(srv);
    plugin_data *p = p_d;
    config_values_t cv[] = {
        { "ssl.engine",                        NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 1 */
        { "ssl.pemfile",                       NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 2 */
        { "ssl.ca-file",                       NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 3 */
        { "ssl.dh-file",                       NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 4 */
        { NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    if (!p) return HANDLER_ERROR;
    p->config_storage = calloc(1, srv->config_context->used * sizeof(plugin_config *));

    for (size_t i = 0; i < srv->config_context->used; i++) {
        data_config const* config = (data_config const*)srv->config_context->data[i];
        plugin_config *s = calloc(1, sizeof(plugin_config));

        s->enabled   = 0;
        s->pemfile   = buffer_init();
        s->crtfile   = buffer_init();
        s->dhmfile   = buffer_init();
        s->cachain   = buffer_init();
        cv[0].destination = &(s->ssl_enabled);
        cv[1].destination = s->pemfile;
        cv[2].destination = s->crtfile;
        cv[3].destination = s->dhmfile;
        cv[3].destination = s->cachain;
        p->config_storage[i] = s;

        if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
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
}
static int
connection_write_cq_ssl (server *srv, connection *con,
                         chunkqueue *cq, off_t max_bytes)
{
}

CONNECTION_FUNC(mod_mbedtls_handle_con_accept)
{
    server_socket *srv_sock = con->srv_socket;
    if (!srv_sock->is_ssl) return HANDLER_GO_ON;

    {
        plugin_data *p = p_d;
        handler_ctx *hctx = handler_ctx_init();
        con->plugin_ctx[p->id] = hctx;
        mod_mbedtls_patch_connection(srv, con, hctx);

        con->network_read = connection_read_cq_ssl;
        con->network_write = connection_write_cq_ssl;
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
    if (hctx->request_env_patched) return HANDLER_GO_ON;
    hctx->request_env_patched = 1;

    UNUSED(srv);
    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_mbedtls_handle_uri_raw)
{
    /* mod_mbedtls must be loaded prior to mod_auth
     * if mod_mbedtls is configured to set REMOTE_USER based on client cert */
    /* mod_mbedtls must be loaded after mod_extforward
     * if mod_mbedtls config is based on lighttpd.conf remote IP conditional
     * using remote IP address set by mod_extforward */
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    if (con->conf.ssl_verifyclient) {
        mod_mbedtls_handle_request_env(srv, con, p);
    }

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
    hctx->request_env_patched = 0;

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
