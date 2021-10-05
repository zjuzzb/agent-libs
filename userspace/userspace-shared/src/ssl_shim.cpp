#include "common_logger.h"
#include "configuration_manager.h"

/*
 * All the declarations will be provided by the actual headers.
 * The definitions will be the shim ones, wrapping the real ones
 * obtained via dlsym.
 */
#include <openssl/des.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>
#include <openssl/ui.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <array>
#include <atomic>
#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <dlfcn.h>
#include <stdexcept>
#include <string>

COMMON_LOGGER();

/**
 * OpenSSL shim, wrapping required libssl and libcrypto functions,
 * which are exposed with the very same signature to be found at link time.
 */

namespace
{

static std::atomic_bool dl_initialized{false};
static std::array<void*, 2> dl_handle = {nullptr, nullptr};
static std::array<const char*, 2> libs = {"libcrypto.so.1.1", "libssl.so.1.1"};

void ssl_shim_shutdown()
{
    for (void* p : dl_handle)
    {
        if (p != nullptr)
        {
            dlclose(p);
            p = nullptr;
        }
    }
}

void* dlopen_helper(const std::string& filename)
{
    LOG_INFO("Loading '%s'", filename.c_str());
    void* handle = dlopen(filename.c_str(), RTLD_NOW | RTLD_GLOBAL);
    if (handle != nullptr)
    {
        return handle;
    }

    auto err = dlerror();
    if (err == nullptr)
    {
        LOG_FATAL("Unable to dlopen libssl");
    }
    else
    {
        LOG_FATAL("Unable to dlopen libssl: '%s'", err);
    }

    return nullptr;
}

void ssl_shim_init()
{
    if (dl_initialized)
    {
        return;
    }

    //TODO have the config with the library path
    auto path = configuration_manager::instance()
        .get_config<std::string>("rootdir")->get_value() + "/lib/openssl/";

    LOG_INFO("Loading ssl libraries from " + path);

    //NOTE using version suffix because some systems (say UBI8) don't setup any link
    for (short i = 0; i < dl_handle.size(); ++i)
    {
        dl_handle[i] = dlopen_helper(path + libs[i]);
        assert(dl_handle[i] != nullptr);
        if (dl_handle[i] == nullptr)
        {
            std::abort();
        }
    }

    dl_initialized = true;
    atexit(ssl_shim_shutdown);
}


template<typename T>
void load_symbol(const char* symbol, T& fn)
{
    if (!dl_initialized)
    {
        ssl_shim_init();
    }

    assert(symbol != nullptr);
    if (symbol == nullptr)
    {
        LOGGED_THROW(std::invalid_argument, "invalid parameter");
        return;
    }

    char* err = nullptr;
    for(void* i : dl_handle)
    {
        *(void **)(&fn) = dlsym(i, symbol);
        err = dlerror();
        if (err == nullptr)
        {
            return;
        }
    }

    if (err != nullptr)
    {
        LOGGED_THROW(std::invalid_argument, "%s", err);
    }
}

} // end namespace


//
// Code GENERATED with the aid of scripts/ssl-fn-gen.py
//

int ASN1_INTEGER_set(ASN1_INTEGER *a, long v)
{
    static int (*ASN1_INTEGER_set_PTR)(ASN1_INTEGER *a, long v);
    if (ASN1_INTEGER_set_PTR == nullptr)
    {
        load_symbol("ASN1_INTEGER_set", ASN1_INTEGER_set_PTR);
    }
    return ASN1_INTEGER_set_PTR(a, v);
}

BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn)
{
    static BIGNUM *(*ASN1_INTEGER_to_BN_PTR)(const ASN1_INTEGER *ai, BIGNUM *bn);
    if (ASN1_INTEGER_to_BN_PTR == nullptr)
    {
        load_symbol("ASN1_INTEGER_to_BN", ASN1_INTEGER_to_BN_PTR);
    }
    return ASN1_INTEGER_to_BN_PTR(ai, bn);
}

unsigned char *ASN1_STRING_data(ASN1_STRING *x)
{
    static unsigned char *(*ASN1_STRING_data_PTR)(ASN1_STRING *x);
    if (ASN1_STRING_data_PTR == nullptr)
    {
        load_symbol("ASN1_STRING_data", ASN1_STRING_data_PTR);
    }
    return ASN1_STRING_data_PTR(x);
}

void ASN1_STRING_free(ASN1_STRING *a)
{
    static void (*ASN1_STRING_free_PTR)(ASN1_STRING *a);
    if (ASN1_STRING_free_PTR == nullptr)
    {
        load_symbol("ASN1_STRING_free", ASN1_STRING_free_PTR);
    }
    return ASN1_STRING_free_PTR(a);
}

const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x)
{
    static const unsigned char *(*ASN1_STRING_get0_data_PTR)(const ASN1_STRING *x);
    if (ASN1_STRING_get0_data_PTR == nullptr)
    {
        load_symbol("ASN1_STRING_get0_data", ASN1_STRING_get0_data_PTR);
    }
    return ASN1_STRING_get0_data_PTR(x);
}

int ASN1_STRING_length(const ASN1_STRING *x)
{
    static int (*ASN1_STRING_length_PTR)(const ASN1_STRING *x);
    if (ASN1_STRING_length_PTR == nullptr)
    {
        load_symbol("ASN1_STRING_length", ASN1_STRING_length_PTR);
    }
    return ASN1_STRING_length_PTR(x);
}

ASN1_STRING *ASN1_STRING_new()
{
    static ASN1_STRING *(*ASN1_STRING_new_PTR)();
    if (ASN1_STRING_new_PTR == nullptr)
    {
        load_symbol("ASN1_STRING_new", ASN1_STRING_new_PTR);
    }
    return ASN1_STRING_new_PTR();
}

int ASN1_STRING_print(BIO *bp, const ASN1_STRING *v)
{
    static int (*ASN1_STRING_print_PTR)(BIO *bp, const ASN1_STRING *v);
    if (ASN1_STRING_print_PTR == nullptr)
    {
        load_symbol("ASN1_STRING_print", ASN1_STRING_print_PTR);
    }
    return ASN1_STRING_print_PTR(bp, v);
}

int ASN1_STRING_to_UTF8(unsigned char **out, const ASN1_STRING *in)
{
    static int (*ASN1_STRING_to_UTF8_PTR)(unsigned char **out, const ASN1_STRING *in);
    if (ASN1_STRING_to_UTF8_PTR == nullptr)
    {
        load_symbol("ASN1_STRING_to_UTF8", ASN1_STRING_to_UTF8_PTR);
    }
    return ASN1_STRING_to_UTF8_PTR(out, in);
}

int ASN1_STRING_type(const ASN1_STRING *x)
{
    static int (*ASN1_STRING_type_PTR)(const ASN1_STRING *x);
    if (ASN1_STRING_type_PTR == nullptr)
    {
        load_symbol("ASN1_STRING_type", ASN1_STRING_type_PTR);
    }
    return ASN1_STRING_type_PTR(x);
}

int ASN1_TIME_print(BIO *fp, const ASN1_TIME *a)
{
    static int (*ASN1_TIME_print_PTR)(BIO *fp, const ASN1_TIME *a);
    if (ASN1_TIME_print_PTR == nullptr)
    {
        load_symbol("ASN1_TIME_print", ASN1_TIME_print_PTR);
    }
    return ASN1_TIME_print_PTR(fp, a);
}

long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg)
{
    static long (*BIO_ctrl_PTR)(BIO *bp, int cmd, long larg, void *parg);
    if (BIO_ctrl_PTR == nullptr)
    {
        load_symbol("BIO_ctrl", BIO_ctrl_PTR);
    }
    return BIO_ctrl_PTR(bp, cmd, larg, parg);
}

int BIO_free(BIO *a)
{
    static int (*BIO_free_PTR)(BIO *a);
    if (BIO_free_PTR == nullptr)
    {
        load_symbol("BIO_free", BIO_free_PTR);
    }
    return BIO_free_PTR(a);
}

void BIO_free_all(BIO *a)
{
    static void (*BIO_free_all_PTR)(BIO *a);
    if (BIO_free_all_PTR == nullptr)
    {
        load_symbol("BIO_free_all", BIO_free_all_PTR);
    }
    return BIO_free_all_PTR(a);
}

const BIO_METHOD *BIO_f_ssl()
{
    static const BIO_METHOD *(*BIO_f_ssl_PTR)();
    if (BIO_f_ssl_PTR == nullptr)
    {
        load_symbol("BIO_f_ssl", BIO_f_ssl_PTR);
    }
    return BIO_f_ssl_PTR();
}

long BIO_int_ctrl(BIO *bp, int cmd, long larg, int iarg)
{
    static long (*BIO_int_ctrl_PTR)(BIO *bp, int cmd, long larg, int iarg);
    if (BIO_int_ctrl_PTR == nullptr)
    {
        load_symbol("BIO_int_ctrl", BIO_int_ctrl_PTR);
    }
    return BIO_int_ctrl_PTR(bp, cmd, larg, iarg);
}

BIO *BIO_new(const BIO_METHOD *type)
{
    static BIO *(*BIO_new_PTR)(const BIO_METHOD *type);
    if (BIO_new_PTR == nullptr)
    {
        load_symbol("BIO_new", BIO_new_PTR);
    }
    return BIO_new_PTR(type);
}

BIO *BIO_new_fd(int fd, int close_flag)
{
    static BIO *(*BIO_new_fd_PTR)(int fd, int close_flag);
    if (BIO_new_fd_PTR == nullptr)
    {
        load_symbol("BIO_new_fd", BIO_new_fd_PTR);
    }
    return BIO_new_fd_PTR(fd, close_flag);
}

BIO *BIO_new_file(const char *filename, const char *mode)
{
    static BIO *(*BIO_new_file_PTR)(const char *filename, const char *mode);
    if (BIO_new_file_PTR == nullptr)
    {
        load_symbol("BIO_new_file", BIO_new_file_PTR);
    }
    return BIO_new_file_PTR(filename, mode);
}

BIO *BIO_new_mem_buf(const void *buf, int len)
{
    static BIO *(*BIO_new_mem_buf_PTR)(const void *buf, int len);
    if (BIO_new_mem_buf_PTR == nullptr)
    {
        load_symbol("BIO_new_mem_buf", BIO_new_mem_buf_PTR);
    }
    return BIO_new_mem_buf_PTR(buf, len);
}

BIO *BIO_new_ssl(SSL_CTX *ctx, int client)
{
    static BIO *(*BIO_new_ssl_PTR)(SSL_CTX *ctx, int client);
    if (BIO_new_ssl_PTR == nullptr)
    {
        load_symbol("BIO_new_ssl", BIO_new_ssl_PTR);
    }
    return BIO_new_ssl_PTR(ctx, client);
}

BIO *BIO_new_ssl_connect(SSL_CTX *ctx)
{
    static BIO *(*BIO_new_ssl_connect_PTR)(SSL_CTX *ctx);
    if (BIO_new_ssl_connect_PTR == nullptr)
    {
        load_symbol("BIO_new_ssl_connect", BIO_new_ssl_connect_PTR);
    }
    return BIO_new_ssl_connect_PTR(ctx);
}

BIO *BIO_push(BIO *b, BIO *append)
{
    static BIO *(*BIO_push_PTR)(BIO *b, BIO *append);
    if (BIO_push_PTR == nullptr)
    {
        load_symbol("BIO_push", BIO_push_PTR);
    }
    return BIO_push_PTR(b, append);
}

int BIO_printf(BIO *bio, const char *format, ...)
{
    int printed;
    va_list ap;
    va_start(ap, format);
    printed = BIO_vprintf(bio, format, ap);
    va_end(ap);
    return printed;
}

int BIO_puts(BIO *bp, const char *buf)
{
    static int (*BIO_puts_PTR)(BIO *bp, const char *buf);
    if (BIO_puts_PTR == nullptr)
    {
        load_symbol("BIO_puts", BIO_puts_PTR);
    }
    return BIO_puts_PTR(bp, buf);
}

int BIO_read(BIO *b, void *data, int dlen)
{
    static int (*BIO_read_PTR)(BIO *b, void *data, int dlen);
    if (BIO_read_PTR == nullptr)
    {
        load_symbol("BIO_read", BIO_read_PTR);
    }
    return BIO_read_PTR(b, data, dlen);
}

const BIO_METHOD *BIO_s_file()
{
    static const BIO_METHOD *(*BIO_s_file_PTR)();
    if (BIO_s_file_PTR == nullptr)
    {
        load_symbol("BIO_s_file", BIO_s_file_PTR);
    }
    return BIO_s_file_PTR();
}

const BIO_METHOD *BIO_s_mem()
{
    static const BIO_METHOD *(*BIO_s_mem_PTR)();
    if (BIO_s_mem_PTR == nullptr)
    {
        load_symbol("BIO_s_mem", BIO_s_mem_PTR);
    }
    return BIO_s_mem_PTR();
}

int BIO_snprintf(char *buf, size_t n, const char *format, ...)
{
    int printed;
    va_list ap;
    va_start(ap, format);
    printed = BIO_vsnprintf(buf, n, format, ap);
    va_end(ap);
    return printed;
}

const BIO_METHOD *BIO_s_socket()
{
    static const BIO_METHOD *(*BIO_s_socket_PTR)();
    if (BIO_s_socket_PTR == nullptr)
    {
        load_symbol("BIO_s_socket", BIO_s_socket_PTR);
    }
    return BIO_s_socket_PTR();
}

int BIO_vprintf(BIO *bio, const char *format, va_list args)
{
    static int (*BIO_vprintf_PTR)(BIO *bio, const char *format, va_list args);
    if (BIO_vprintf_PTR == nullptr)
    {
        load_symbol("BIO_vprintf", BIO_vprintf_PTR);
    }
    return BIO_vprintf_PTR(bio, format, args);
}

int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
{
    static int (*BIO_vsnprintf_PTR)(char *buf, size_t n, const char *format, va_list args);
    if (BIO_vsnprintf_PTR == nullptr)
    {
        load_symbol("BIO_vsnprintf", BIO_vsnprintf_PTR);
    }
    return BIO_vsnprintf_PTR(buf, n, format, args);
}

BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    static BIGNUM *(*BN_bin2bn_PTR)(const unsigned char *s, int len, BIGNUM *ret);
    if (BN_bin2bn_PTR == nullptr)
    {
        load_symbol("BN_bin2bn", BN_bin2bn_PTR);
    }
    return BN_bin2bn_PTR(s, len, ret);
}

char *BN_bn2hex(const BIGNUM *a)
{
    static char *(*BN_bn2hex_PTR)(const BIGNUM *a);
    if (BN_bn2hex_PTR == nullptr)
    {
        load_symbol("BN_bn2hex", BN_bn2hex_PTR);
    }
    return BN_bn2hex_PTR(a);
}

void BN_free(BIGNUM *a)
{
    static void (*BN_free_PTR)(BIGNUM *a);
    if (BN_free_PTR == nullptr)
    {
        load_symbol("BN_free", BN_free_PTR);
    }
    return BN_free_PTR(a);
}

BIGNUM *BN_new()
{
    static BIGNUM *(*BN_new_PTR)();
    if (BN_new_PTR == nullptr)
    {
        load_symbol("BN_new", BN_new_PTR);
    }
    return BN_new_PTR();
}

int BN_print(BIO *bio, const BIGNUM *a)
{
    static int (*BN_print_PTR)(BIO *bio, const BIGNUM *a);
    if (BN_print_PTR == nullptr)
    {
        load_symbol("BN_print", BN_print_PTR);
    }
    return BN_print_PTR(bio, a);
}

int BN_set_word(BIGNUM *a, BN_ULONG w)
{
    static int (*BN_set_word_PTR)(BIGNUM *a, BN_ULONG w);
    if (BN_set_word_PTR == nullptr)
    {
        load_symbol("BN_set_word", BN_set_word_PTR);
    }
    return BN_set_word_PTR(a, w);
}

int CONF_modules_load_file(const char *filename, const char *appname, unsigned long flags)
{
    static int (*CONF_modules_load_file_PTR)(const char *filename, const char *appname, unsigned long flags);
    if (CONF_modules_load_file_PTR == nullptr)
    {
        load_symbol("CONF_modules_load_file", CONF_modules_load_file_PTR);
    }
    return CONF_modules_load_file_PTR(filename, appname, flags);
}

void CRYPTO_free(void *ptr, const char *file, int line)
{
    static void (*CRYPTO_free_PTR)(void *ptr, const char *file, int line);
    if (CRYPTO_free_PTR == nullptr)
    {
        load_symbol("CRYPTO_free", CRYPTO_free_PTR);
    }
    return CRYPTO_free_PTR(ptr, file, line);
}

void *CRYPTO_malloc(size_t num, const char *file, int line)
{
    static void *(*CRYPTO_malloc_PTR)(size_t num, const char *file, int line);
    if (CRYPTO_malloc_PTR == nullptr)
    {
        load_symbol("CRYPTO_malloc", CRYPTO_malloc_PTR);
    }
    return CRYPTO_malloc_PTR(num, file, line);
}

OCSP_RESPONSE *d2i_OCSP_RESPONSE(OCSP_RESPONSE **val_out, const unsigned char **der_in, long length)
{
    static OCSP_RESPONSE *(*d2i_OCSP_RESPONSE_PTR)(OCSP_RESPONSE **val_out, const unsigned char **der_in, long length);
    if (d2i_OCSP_RESPONSE_PTR == nullptr)
    {
        load_symbol("d2i_OCSP_RESPONSE", d2i_OCSP_RESPONSE_PTR);
    }
    return d2i_OCSP_RESPONSE_PTR(val_out, der_in, length);
}

PKCS12 *d2i_PKCS12_bio(BIO *bp, PKCS12 **p12)
{
    static PKCS12 *(*d2i_PKCS12_bio_PTR)(BIO *bp, PKCS12 **p12);
    if (d2i_PKCS12_bio_PTR == nullptr)
    {
        load_symbol("d2i_PKCS12_bio", d2i_PKCS12_bio_PTR);
    }
    return d2i_PKCS12_bio_PTR(bp, p12);
}

void DES_ecb_encrypt(const_DES_cblock *input, DES_cblock *output, DES_key_schedule *ks, int enc)
{
    static void (*DES_ecb_encrypt_PTR)(const_DES_cblock *input, DES_cblock *output, DES_key_schedule *ks, int enc);
    if (DES_ecb_encrypt_PTR == nullptr)
    {
        load_symbol("DES_ecb_encrypt", DES_ecb_encrypt_PTR);
    }
    return DES_ecb_encrypt_PTR(input, output, ks, enc);
}

int DES_set_key(const_DES_cblock *key, DES_key_schedule *schedule)
{
    static int (*DES_set_key_PTR)(const_DES_cblock *key, DES_key_schedule *schedule);
    if (DES_set_key_PTR == nullptr)
    {
        load_symbol("DES_set_key", DES_set_key_PTR);
    }
    return DES_set_key_PTR(key, schedule);
}

void DES_set_odd_parity(DES_cblock *key)
{
    static void (*DES_set_odd_parity_PTR)(DES_cblock *key);
    if (DES_set_odd_parity_PTR == nullptr)
    {
        load_symbol("DES_set_odd_parity", DES_set_odd_parity_PTR);
    }
    return DES_set_odd_parity_PTR(key);
}

void DH_free(DH *dh)
{
    static void (*DH_free_PTR)(DH *dh);
    if (DH_free_PTR == nullptr)
    {
        load_symbol("DH_free", DH_free_PTR);
    }
    return DH_free_PTR(dh);
}

void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    static void (*DH_get0_key_PTR)(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key);
    if (DH_get0_key_PTR == nullptr)
    {
        load_symbol("DH_get0_key", DH_get0_key_PTR);
    }
    return DH_get0_key_PTR(dh, pub_key, priv_key);
}

void DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    static void (*DH_get0_pqg_PTR)(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g);
    if (DH_get0_pqg_PTR == nullptr)
    {
        load_symbol("DH_get0_pqg", DH_get0_pqg_PTR);
    }
    return DH_get0_pqg_PTR(dh, p, q, g);
}

DH *DH_new()
{
    static DH *(*DH_new_PTR)();
    if (DH_new_PTR == nullptr)
    {
        load_symbol("DH_new", DH_new_PTR);
    }
    return DH_new_PTR();
}

int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    static int (*DH_set0_pqg_PTR)(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
    if (DH_set0_pqg_PTR == nullptr)
    {
        load_symbol("DH_set0_pqg", DH_set0_pqg_PTR);
    }
    return DH_set0_pqg_PTR(dh, p, q, g);
}

int DH_set_length(DH *dh, long length)
{
    static int (*DH_set_length_PTR)(DH *dh, long length);
    if (DH_set_length_PTR == nullptr)
    {
        load_symbol("DH_set_length", DH_set_length_PTR);
    }
    return DH_set_length_PTR(dh, length);
}

void DSA_get0_key(const DSA *d, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    static void (*DSA_get0_key_PTR)(const DSA *d, const BIGNUM **pub_key, const BIGNUM **priv_key);
    if (DSA_get0_key_PTR == nullptr)
    {
        load_symbol("DSA_get0_key", DSA_get0_key_PTR);
    }
    return DSA_get0_key_PTR(d, pub_key, priv_key);
}

void DSA_get0_pqg(const DSA *d, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    static void (*DSA_get0_pqg_PTR)(const DSA *d, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g);
    if (DSA_get0_pqg_PTR == nullptr)
    {
        load_symbol("DSA_get0_pqg", DSA_get0_pqg_PTR);
    }
    return DSA_get0_pqg_PTR(d, p, q, g);
}

const SSL_METHOD *DTLSv1_2_client_method()
{
    static const SSL_METHOD *(*DTLSv1_2_client_method_PTR)();
    if (DTLSv1_2_client_method_PTR == nullptr)
    {
        load_symbol("DTLSv1_2_client_method", DTLSv1_2_client_method_PTR);
    }
    return DTLSv1_2_client_method_PTR();
}

void EC_KEY_free(EC_KEY *key)
{
    static void (*EC_KEY_free_PTR)(EC_KEY *key);
    if (EC_KEY_free_PTR == nullptr)
    {
        load_symbol("EC_KEY_free", EC_KEY_free_PTR);
    }
    return EC_KEY_free_PTR(key);
}

EC_KEY *EC_KEY_new_by_curve_name(int nid)
{
    static EC_KEY *(*EC_KEY_new_by_curve_name_PTR)(int nid);
    if (EC_KEY_new_by_curve_name_PTR == nullptr)
    {
        load_symbol("EC_KEY_new_by_curve_name", EC_KEY_new_by_curve_name_PTR);
    }
    return EC_KEY_new_by_curve_name_PTR(nid);
}

ENGINE *ENGINE_by_id(const char *id)
{
    static ENGINE *(*ENGINE_by_id_PTR)(const char *id);
    if (ENGINE_by_id_PTR == nullptr)
    {
        load_symbol("ENGINE_by_id", ENGINE_by_id_PTR);
    }
    return ENGINE_by_id_PTR(id);
}

int ENGINE_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)())
{
    static int (*ENGINE_ctrl_PTR)(ENGINE *e, int cmd, long i, void *p, void (*f)());
    if (ENGINE_ctrl_PTR == nullptr)
    {
        load_symbol("ENGINE_ctrl", ENGINE_ctrl_PTR);
    }
    return ENGINE_ctrl_PTR(e, cmd, i, p, f);
}

int ENGINE_ctrl_cmd(ENGINE *e, const char *cmd_name, long i, void *p, void (*f) (), int cmd_optional)
{
    static int (*ENGINE_ctrl_cmd_PTR)(ENGINE *e, const char *cmd_name, long i, void *p, void (*f) (), int cmd_optional);
    if (ENGINE_ctrl_cmd_PTR == nullptr)
    {
        load_symbol("ENGINE_ctrl_cmd", ENGINE_ctrl_cmd_PTR);
    }
    return ENGINE_ctrl_cmd_PTR(e, cmd_name, i, p, f, cmd_optional);
}

int ENGINE_finish(ENGINE *e)
{
    static int (*ENGINE_finish_PTR)(ENGINE *e);
    if (ENGINE_finish_PTR == nullptr)
    {
        load_symbol("ENGINE_finish", ENGINE_finish_PTR);
    }
    return ENGINE_finish_PTR(e);
}

int ENGINE_free(ENGINE *e)
{
    static int (*ENGINE_free_PTR)(ENGINE *e);
    if (ENGINE_free_PTR == nullptr)
    {
        load_symbol("ENGINE_free", ENGINE_free_PTR);
    }
    return ENGINE_free_PTR(e);
}

ENGINE *ENGINE_get_first()
{
    static ENGINE *(*ENGINE_get_first_PTR)();
    if (ENGINE_get_first_PTR == nullptr)
    {
        load_symbol("ENGINE_get_first", ENGINE_get_first_PTR);
    }
    return ENGINE_get_first_PTR();
}

const char *ENGINE_get_id(const ENGINE *e)
{
    static const char *(*ENGINE_get_id_PTR)(const ENGINE *e);
    if (ENGINE_get_id_PTR == nullptr)
    {
        load_symbol("ENGINE_get_id", ENGINE_get_id_PTR);
    }
    return ENGINE_get_id_PTR(e);
}

ENGINE *ENGINE_get_next(ENGINE *e)
{
    static ENGINE *(*ENGINE_get_next_PTR)(ENGINE *e);
    if (ENGINE_get_next_PTR == nullptr)
    {
        load_symbol("ENGINE_get_next", ENGINE_get_next_PTR);
    }
    return ENGINE_get_next_PTR(e);
}

int ENGINE_init(ENGINE *e)
{
    static int (*ENGINE_init_PTR)(ENGINE *e);
    if (ENGINE_init_PTR == nullptr)
    {
        load_symbol("ENGINE_init", ENGINE_init_PTR);
    }
    return ENGINE_init_PTR(e);
}

EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data)
{
    static EVP_PKEY *(*ENGINE_load_private_key_PTR)(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data);
    if (ENGINE_load_private_key_PTR == nullptr)
    {
        load_symbol("ENGINE_load_private_key", ENGINE_load_private_key_PTR);
    }
    return ENGINE_load_private_key_PTR(e, key_id, ui_method, callback_data);
}

int ENGINE_set_default(ENGINE *e, unsigned int flags)
{
    static int (*ENGINE_set_default_PTR)(ENGINE *e, unsigned int flags);
    if (ENGINE_set_default_PTR == nullptr)
    {
        load_symbol("ENGINE_set_default", ENGINE_set_default_PTR);
    }
    return ENGINE_set_default_PTR(e, flags);
}

void ERR_clear_error()
{
    static void (*ERR_clear_error_PTR)();
    if (ERR_clear_error_PTR == nullptr)
    {
        load_symbol("ERR_clear_error", ERR_clear_error_PTR);
    }
    return ERR_clear_error_PTR();
}

char *ERR_error_string(unsigned long e, char *buf)
{
    static char *(*ERR_error_string_PTR)(unsigned long e, char *buf);
    if (ERR_error_string_PTR == nullptr)
    {
        load_symbol("ERR_error_string", ERR_error_string_PTR);
    }
    return ERR_error_string_PTR(e, buf);
}

void ERR_error_string_n(unsigned long e, char *buf, size_t len)
{
    static void (*ERR_error_string_n_PTR)(unsigned long e, char *buf, size_t len);
    if (ERR_error_string_n_PTR == nullptr)
    {
        load_symbol("ERR_error_string_n", ERR_error_string_n_PTR);
    }
    return ERR_error_string_n_PTR(e, buf, len);
}

unsigned long ERR_get_error()
{
    static unsigned long (*ERR_get_error_PTR)();
    if (ERR_get_error_PTR == nullptr)
    {
        load_symbol("ERR_get_error", ERR_get_error_PTR);
    }
    return ERR_get_error_PTR();
}

unsigned long ERR_peek_error()
{
    static unsigned long (*ERR_peek_error_PTR)();
    if (ERR_peek_error_PTR == nullptr)
    {
        load_symbol("ERR_peek_error", ERR_peek_error_PTR);
    }
    return ERR_peek_error_PTR();
}

void ERR_print_errors_cb(int (*cb) (const char *str, size_t len, void *u), void *u)
{
    static void (*ERR_print_errors_cb_PTR)(int (*cb) (const char *str, size_t len, void *u), void *u);
    if (ERR_print_errors_cb_PTR == nullptr)
    {
        load_symbol("ERR_print_errors_cb", ERR_print_errors_cb_PTR);
    }
    return ERR_print_errors_cb_PTR(cb, u);
}

void ERR_print_errors_fp(FILE *fp)
{
    static void (*ERR_print_errors_fp_PTR)(FILE *fp);
    if (ERR_print_errors_fp_PTR == nullptr)
    {
        load_symbol("ERR_print_errors_fp", ERR_print_errors_fp_PTR);
    }
    return ERR_print_errors_fp_PTR(fp);
}

int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)
{
    static int (*EVP_DigestFinal_ex_PTR)(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
    if (EVP_DigestFinal_ex_PTR == nullptr)
    {
        load_symbol("EVP_DigestFinal_ex", EVP_DigestFinal_ex_PTR);
    }
    return EVP_DigestFinal_ex_PTR(ctx, md, s);
}

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
    static int (*EVP_DigestInit_ex_PTR)(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
    if (EVP_DigestInit_ex_PTR == nullptr)
    {
        load_symbol("EVP_DigestInit_ex", EVP_DigestInit_ex_PTR);
    }
    return EVP_DigestInit_ex_PTR(ctx, type, impl);
}

int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
    static int (*EVP_DigestUpdate_PTR)(EVP_MD_CTX *ctx, const void *d, size_t cnt);
    if (EVP_DigestUpdate_PTR == nullptr)
    {
        load_symbol("EVP_DigestUpdate", EVP_DigestUpdate_PTR);
    }
    return EVP_DigestUpdate_PTR(ctx, d, cnt);
}

const EVP_CIPHER *EVP_idea_cbc()
{
    static const EVP_CIPHER *(*EVP_idea_cbc_PTR)();
    if (EVP_idea_cbc_PTR == nullptr)
    {
        load_symbol("EVP_idea_cbc", EVP_idea_cbc_PTR);
    }
    return EVP_idea_cbc_PTR();
}

const EVP_MD *EVP_md5()
{
    static const EVP_MD *(*EVP_md5_PTR)();
    if (EVP_md5_PTR == nullptr)
    {
        load_symbol("EVP_md5", EVP_md5_PTR);
    }
    return EVP_md5_PTR();
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    static void (*EVP_MD_CTX_free_PTR)(EVP_MD_CTX *ctx);
    if (EVP_MD_CTX_free_PTR == nullptr)
    {
        load_symbol("EVP_MD_CTX_free", EVP_MD_CTX_free_PTR);
    }
    return EVP_MD_CTX_free_PTR(ctx);
}

EVP_MD_CTX *EVP_MD_CTX_new()
{
    static EVP_MD_CTX *(*EVP_MD_CTX_new_PTR)();
    if (EVP_MD_CTX_new_PTR == nullptr)
    {
        load_symbol("EVP_MD_CTX_new", EVP_MD_CTX_new_PTR);
    }
    return EVP_MD_CTX_new_PTR();
}

int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key)
{
    static int (*EVP_PKEY_assign_PTR)(EVP_PKEY *pkey, int type, void *key);
    if (EVP_PKEY_assign_PTR == nullptr)
    {
        load_symbol("EVP_PKEY_assign", EVP_PKEY_assign_PTR);
    }
    return EVP_PKEY_assign_PTR(pkey, type, key);
}

int EVP_PKEY_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from)
{
    static int (*EVP_PKEY_copy_parameters_PTR)(EVP_PKEY *to, const EVP_PKEY *from);
    if (EVP_PKEY_copy_parameters_PTR == nullptr)
    {
        load_symbol("EVP_PKEY_copy_parameters", EVP_PKEY_copy_parameters_PTR);
    }
    return EVP_PKEY_copy_parameters_PTR(to, from);
}

void EVP_PKEY_free(EVP_PKEY *pkey)
{
    static void (*EVP_PKEY_free_PTR)(EVP_PKEY *pkey);
    if (EVP_PKEY_free_PTR == nullptr)
    {
        load_symbol("EVP_PKEY_free", EVP_PKEY_free_PTR);
    }
    return EVP_PKEY_free_PTR(pkey);
}

struct dh_st *EVP_PKEY_get0_DH(EVP_PKEY *pkey)
{
    static struct dh_st *(*EVP_PKEY_get0_DH_PTR)(EVP_PKEY *pkey);
    if (EVP_PKEY_get0_DH_PTR == nullptr)
    {
        load_symbol("EVP_PKEY_get0_DH", EVP_PKEY_get0_DH_PTR);
    }
    return EVP_PKEY_get0_DH_PTR(pkey);
}

struct dsa_st *EVP_PKEY_get0_DSA(EVP_PKEY *pkey)
{
    static struct dsa_st *(*EVP_PKEY_get0_DSA_PTR)(EVP_PKEY *pkey);
    if (EVP_PKEY_get0_DSA_PTR == nullptr)
    {
        load_symbol("EVP_PKEY_get0_DSA", EVP_PKEY_get0_DSA_PTR);
    }
    return EVP_PKEY_get0_DSA_PTR(pkey);
}

struct rsa_st *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{
    static struct rsa_st *(*EVP_PKEY_get0_RSA_PTR)(EVP_PKEY *pkey);
    if (EVP_PKEY_get0_RSA_PTR == nullptr)
    {
        load_symbol("EVP_PKEY_get0_RSA", EVP_PKEY_get0_RSA_PTR);
    }
    return EVP_PKEY_get0_RSA_PTR(pkey);
}

struct rsa_st *EVP_PKEY_get1_RSA(EVP_PKEY *pkey)
{
    static struct rsa_st *(*EVP_PKEY_get1_RSA_PTR)(EVP_PKEY *pkey);
    if (EVP_PKEY_get1_RSA_PTR == nullptr)
    {
        load_symbol("EVP_PKEY_get1_RSA", EVP_PKEY_get1_RSA_PTR);
    }
    return EVP_PKEY_get1_RSA_PTR(pkey);
}

int EVP_PKEY_id(const EVP_PKEY *pkey)
{
    static int (*EVP_PKEY_id_PTR)(const EVP_PKEY *pkey);
    if (EVP_PKEY_id_PTR == nullptr)
    {
        load_symbol("EVP_PKEY_id", EVP_PKEY_id_PTR);
    }
    return EVP_PKEY_id_PTR(pkey);
}

EVP_PKEY *EVP_PKEY_new()
{
    static EVP_PKEY *(*EVP_PKEY_new_PTR)();
    if (EVP_PKEY_new_PTR == nullptr)
    {
        load_symbol("EVP_PKEY_new", EVP_PKEY_new_PTR);
    }
    return EVP_PKEY_new_PTR();
}

const EVP_MD *EVP_sha1()
{
    static const EVP_MD *(*EVP_sha1_PTR)();
    if (EVP_sha1_PTR == nullptr)
    {
        load_symbol("EVP_sha1", EVP_sha1_PTR);
    }
    return EVP_sha1_PTR();
}

const EVP_MD *EVP_sha256()
{
    static const EVP_MD *(*EVP_sha256_PTR)();
    if (EVP_sha256_PTR == nullptr)
    {
        load_symbol("EVP_sha256", EVP_sha256_PTR);
    }
    return EVP_sha256_PTR();
}

void GENERAL_NAMES_free(GENERAL_NAMES *a)
{
    static void (*GENERAL_NAMES_free_PTR)(GENERAL_NAMES *a);
    if (GENERAL_NAMES_free_PTR == nullptr)
    {
        load_symbol("GENERAL_NAMES_free", GENERAL_NAMES_free_PTR);
    }
    return GENERAL_NAMES_free_PTR(a);
}

int i2a_ASN1_OBJECT(BIO *bp, const ASN1_OBJECT *a)
{
    static int (*i2a_ASN1_OBJECT_PTR)(BIO *bp, const ASN1_OBJECT *a);
    if (i2a_ASN1_OBJECT_PTR == nullptr)
    {
        load_symbol("i2a_ASN1_OBJECT", i2a_ASN1_OBJECT_PTR);
    }
    return i2a_ASN1_OBJECT_PTR(bp, a);
}

int i2d_X509_PUBKEY(X509_PUBKEY *pkey, unsigned char **der)
{
    static int (*i2d_X509_PUBKEY_PTR)(X509_PUBKEY *pkey, unsigned char **der);
    if (i2d_X509_PUBKEY_PTR == nullptr)
    {
        load_symbol("i2d_X509_PUBKEY", i2d_X509_PUBKEY_PTR);
    }
    return i2d_X509_PUBKEY_PTR(pkey, der);
}

int i2t_ASN1_OBJECT(char *buf, int buf_len, const ASN1_OBJECT *a)
{
    static int (*i2t_ASN1_OBJECT_PTR)(char *buf, int buf_len, const ASN1_OBJECT *a);
    if (i2t_ASN1_OBJECT_PTR == nullptr)
    {
        load_symbol("i2t_ASN1_OBJECT", i2t_ASN1_OBJECT_PTR);
    }
    return i2t_ASN1_OBJECT_PTR(buf, buf_len, a);
}

int MD4_Final(unsigned char *md, MD4_CTX *c)
{
    static int (*MD4_Final_PTR)(unsigned char *md, MD4_CTX *c);
    if (MD4_Final_PTR == nullptr)
    {
        load_symbol("MD4_Final", MD4_Final_PTR);
    }
    return MD4_Final_PTR(md, c);
}

int MD4_Init(MD4_CTX *c)
{
    static int (*MD4_Init_PTR)(MD4_CTX *c);
    if (MD4_Init_PTR == nullptr)
    {
        load_symbol("MD4_Init", MD4_Init_PTR);
    }
    return MD4_Init_PTR(c);
}

int MD4_Update(MD4_CTX *c, const void *data, size_t len)
{
    static int (*MD4_Update_PTR)(MD4_CTX *c, const void *data, size_t len);
    if (MD4_Update_PTR == nullptr)
    {
        load_symbol("MD4_Update", MD4_Update_PTR);
    }
    return MD4_Update_PTR(c, data, len);
}

int MD5_Final(unsigned char *md, MD5_CTX *c)
{
    static int (*MD5_Final_PTR)(unsigned char *md, MD5_CTX *c);
    if (MD5_Final_PTR == nullptr)
    {
        load_symbol("MD5_Final", MD5_Final_PTR);
    }
    return MD5_Final_PTR(md, c);
}

int MD5_Init(MD5_CTX *c)
{
    static int (*MD5_Init_PTR)(MD5_CTX *c);
    if (MD5_Init_PTR == nullptr)
    {
        load_symbol("MD5_Init", MD5_Init_PTR);
    }
    return MD5_Init_PTR(c);
}

int MD5_Update(MD5_CTX *c, const void *data, size_t len)
{
    static int (*MD5_Update_PTR)(MD5_CTX *c, const void *data, size_t len);
    if (MD5_Update_PTR == nullptr)
    {
        load_symbol("MD5_Update", MD5_Update_PTR);
    }
    return MD5_Update_PTR(c, data, len);
}

const char *OBJ_nid2ln(int n)
{
    static const char *(*OBJ_nid2ln_PTR)(int n);
    if (OBJ_nid2ln_PTR == nullptr)
    {
        load_symbol("OBJ_nid2ln", OBJ_nid2ln_PTR);
    }
    return OBJ_nid2ln_PTR(n);
}

int OBJ_sn2nid(const char *s)
{
    static int (*OBJ_sn2nid_PTR)(const char *s);
    if (OBJ_sn2nid_PTR == nullptr)
    {
        load_symbol("OBJ_sn2nid", OBJ_sn2nid_PTR);
    }
    return OBJ_sn2nid_PTR(s);
}

void OCSP_BASICRESP_free(OCSP_BASICRESP *a)
{
    static void (*OCSP_BASICRESP_free_PTR)(OCSP_BASICRESP *a);
    if (OCSP_BASICRESP_free_PTR == nullptr)
    {
        load_symbol("OCSP_BASICRESP_free", OCSP_BASICRESP_free_PTR);
    }
    return OCSP_BASICRESP_free_PTR(a);
}

int OCSP_basic_verify(OCSP_BASICRESP *bs, STACK_OF(X509) *certs, X509_STORE *st, unsigned long flags)
{
    static int (*OCSP_basic_verify_PTR)(OCSP_BASICRESP *bs, STACK_OF(X509) *certs, X509_STORE *st, unsigned long flags);
    if (OCSP_basic_verify_PTR == nullptr)
    {
        load_symbol("OCSP_basic_verify", OCSP_basic_verify_PTR);
    }
    return OCSP_basic_verify_PTR(bs, certs, st, flags);
}

const char *OCSP_cert_status_str(long s)
{
    static const char *(*OCSP_cert_status_str_PTR)(long s);
    if (OCSP_cert_status_str_PTR == nullptr)
    {
        load_symbol("OCSP_cert_status_str", OCSP_cert_status_str_PTR);
    }
    return OCSP_cert_status_str_PTR(s);
}

int OCSP_check_validity(ASN1_GENERALIZEDTIME *thisupd, ASN1_GENERALIZEDTIME *nextupd, long sec, long maxsec)
{
    static int (*OCSP_check_validity_PTR)(ASN1_GENERALIZEDTIME *thisupd, ASN1_GENERALIZEDTIME *nextupd, long sec, long maxsec);
    if (OCSP_check_validity_PTR == nullptr)
    {
        load_symbol("OCSP_check_validity", OCSP_check_validity_PTR);
    }
    return OCSP_check_validity_PTR(thisupd, nextupd, sec, maxsec);
}

const char *OCSP_crl_reason_str(long s)
{
    static const char *(*OCSP_crl_reason_str_PTR)(long s);
    if (OCSP_crl_reason_str_PTR == nullptr)
    {
        load_symbol("OCSP_crl_reason_str", OCSP_crl_reason_str_PTR);
    }
    return OCSP_crl_reason_str_PTR(s);
}

int OCSP_resp_count(OCSP_BASICRESP *bs)
{
    static int (*OCSP_resp_count_PTR)(OCSP_BASICRESP *bs);
    if (OCSP_resp_count_PTR == nullptr)
    {
        load_symbol("OCSP_resp_count", OCSP_resp_count_PTR);
    }
    return OCSP_resp_count_PTR(bs);
}

OCSP_SINGLERESP *OCSP_resp_get0(OCSP_BASICRESP *bs, int idx)
{
    static OCSP_SINGLERESP *(*OCSP_resp_get0_PTR)(OCSP_BASICRESP *bs, int idx);
    if (OCSP_resp_get0_PTR == nullptr)
    {
        load_symbol("OCSP_resp_get0", OCSP_resp_get0_PTR);
    }
    return OCSP_resp_get0_PTR(bs, idx);
}

void OCSP_RESPONSE_free(OCSP_RESPONSE *a)
{
    static void (*OCSP_RESPONSE_free_PTR)(OCSP_RESPONSE *a);
    if (OCSP_RESPONSE_free_PTR == nullptr)
    {
        load_symbol("OCSP_RESPONSE_free", OCSP_RESPONSE_free_PTR);
    }
    return OCSP_RESPONSE_free_PTR(a);
}

OCSP_BASICRESP *OCSP_response_get1_basic(OCSP_RESPONSE *resp)
{
    static OCSP_BASICRESP *(*OCSP_response_get1_basic_PTR)(OCSP_RESPONSE *resp);
    if (OCSP_response_get1_basic_PTR == nullptr)
    {
        load_symbol("OCSP_response_get1_basic", OCSP_response_get1_basic_PTR);
    }
    return OCSP_response_get1_basic_PTR(resp);
}

int OCSP_response_status(OCSP_RESPONSE *resp)
{
    static int (*OCSP_response_status_PTR)(OCSP_RESPONSE *resp);
    if (OCSP_response_status_PTR == nullptr)
    {
        load_symbol("OCSP_response_status", OCSP_response_status_PTR);
    }
    return OCSP_response_status_PTR(resp);
}

const char *OCSP_response_status_str(long s)
{
    static const char *(*OCSP_response_status_str_PTR)(long s);
    if (OCSP_response_status_str_PTR == nullptr)
    {
        load_symbol("OCSP_response_status_str", OCSP_response_status_str_PTR);
    }
    return OCSP_response_status_str_PTR(s);
}

int OCSP_single_get0_status(OCSP_SINGLERESP *single, int *reason, ASN1_GENERALIZEDTIME **revtime, ASN1_GENERALIZEDTIME **thisupd, ASN1_GENERALIZEDTIME **nextupd)
{
    static int (*OCSP_single_get0_status_PTR)(OCSP_SINGLERESP *single, int *reason, ASN1_GENERALIZEDTIME **revtime, ASN1_GENERALIZEDTIME **thisupd, ASN1_GENERALIZEDTIME **nextupd);
    if (OCSP_single_get0_status_PTR == nullptr)
    {
        load_symbol("OCSP_single_get0_status", OCSP_single_get0_status_PTR);
    }
    return OCSP_single_get0_status_PTR(single, reason, revtime, thisupd, nextupd);
}

void OPENSSL_config(const char *config_name)
{
    static void (*OPENSSL_config_PTR)(const char *config_name);
    if (OPENSSL_config_PTR == nullptr)
    {
        load_symbol("OPENSSL_config", OPENSSL_config_PTR);
    }
    return OPENSSL_config_PTR(config_name);
}

int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
{
    static int (*OPENSSL_init_crypto_PTR)(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);
    if (OPENSSL_init_crypto_PTR == nullptr)
    {
        load_symbol("OPENSSL_init_crypto", OPENSSL_init_crypto_PTR);
    }
    return OPENSSL_init_crypto_PTR(opts, settings);
}

int OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
{
    static int (*OPENSSL_init_ssl_PTR)(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);
    if (OPENSSL_init_ssl_PTR == nullptr)
    {
        load_symbol("OPENSSL_init_ssl", OPENSSL_init_ssl_PTR);
    }
    return OPENSSL_init_ssl_PTR(opts, settings);
}

void OPENSSL_load_builtin_modules()
{
    static void (*OPENSSL_load_builtin_modules_PTR)();
    if (OPENSSL_load_builtin_modules_PTR == nullptr)
    {
        load_symbol("OPENSSL_load_builtin_modules", OPENSSL_load_builtin_modules_PTR);
    }
    return OPENSSL_load_builtin_modules_PTR();
}

int OPENSSL_sk_num(const OPENSSL_STACK *st)
{
    static int (*OPENSSL_sk_num_PTR)(const OPENSSL_STACK *st);
    if (OPENSSL_sk_num_PTR == nullptr)
    {
        load_symbol("OPENSSL_sk_num", OPENSSL_sk_num_PTR);
    }
    return OPENSSL_sk_num_PTR(st);
}

void *OPENSSL_sk_pop(OPENSSL_STACK *st)
{
    static void *(*OPENSSL_sk_pop_PTR)(OPENSSL_STACK *st);
    if (OPENSSL_sk_pop_PTR == nullptr)
    {
        load_symbol("OPENSSL_sk_pop", OPENSSL_sk_pop_PTR);
    }
    return OPENSSL_sk_pop_PTR(st);
}

void OPENSSL_sk_pop_free(OPENSSL_STACK *st, void (*func)(void *))
{
    static void (*OPENSSL_sk_pop_free_PTR)(OPENSSL_STACK *st, void (*func)(void *));
    if (OPENSSL_sk_pop_free_PTR == nullptr)
    {
        load_symbol("OPENSSL_sk_pop_free", OPENSSL_sk_pop_free_PTR);
    }
    return OPENSSL_sk_pop_free_PTR(st, func);
}

void *OPENSSL_sk_value(const OPENSSL_STACK *st, int v)
{
    static void *(*OPENSSL_sk_value_PTR)(const OPENSSL_STACK *st, int v);
    if (OPENSSL_sk_value_PTR == nullptr)
    {
        load_symbol("OPENSSL_sk_value", OPENSSL_sk_value_PTR);
    }
    return OPENSSL_sk_value_PTR(st, v);
}

unsigned long OpenSSL_version_num()
{
    static unsigned long (*OpenSSL_version_num_PTR)();
    if (OpenSSL_version_num_PTR == nullptr)
    {
        load_symbol("OpenSSL_version_num", OpenSSL_version_num_PTR);
    }
    return OpenSSL_version_num_PTR();
}

DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u)
{
    static DH *(*PEM_read_bio_DHparams_PTR)(BIO *bp, DH **x, pem_password_cb *cb, void *u);
    if (PEM_read_bio_DHparams_PTR == nullptr)
    {
        load_symbol("PEM_read_bio_DHparams", PEM_read_bio_DHparams_PTR);
    }
    return PEM_read_bio_DHparams_PTR(bp, x, cb, u);
}

X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u)
{
    static X509 *(*PEM_read_bio_X509_PTR)(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
    if (PEM_read_bio_X509_PTR == nullptr)
    {
        load_symbol("PEM_read_bio_X509", PEM_read_bio_X509_PTR);
    }
    return PEM_read_bio_X509_PTR(bp, x, cb, u);
}

EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u)
{
    static EVP_PKEY *(*PEM_read_PrivateKey_PTR)(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u);
    if (PEM_read_PrivateKey_PTR == nullptr)
    {
        load_symbol("PEM_read_PrivateKey", PEM_read_PrivateKey_PTR);
    }
    return PEM_read_PrivateKey_PTR(fp, x, cb, u);
}

X509 *PEM_read_X509(FILE *fp, X509 **x, pem_password_cb *cb, void *u)
{
    static X509 *(*PEM_read_X509_PTR)(FILE *fp, X509 **x, pem_password_cb *cb, void *u);
    if (PEM_read_X509_PTR == nullptr)
    {
        load_symbol("PEM_read_X509", PEM_read_X509_PTR);
    }
    return PEM_read_X509_PTR(fp, x, cb, u);
}

int PEM_write_bio_X509(BIO *bp, X509 *x)
{
    static int (*PEM_write_bio_X509_PTR)(BIO *bp, X509 *x);
    if (PEM_write_bio_X509_PTR == nullptr)
    {
        load_symbol("PEM_write_bio_X509", PEM_write_bio_X509_PTR);
    }
    return PEM_write_bio_X509_PTR(bp, x);
}

void PKCS12_free(PKCS12 *a)
{
    static void (*PKCS12_free_PTR)(PKCS12 *a);
    if (PKCS12_free_PTR == nullptr)
    {
        load_symbol("PKCS12_free", PKCS12_free_PTR);
    }
    return PKCS12_free_PTR(a);
}

int PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
    static int (*PKCS12_parse_PTR)(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca);
    if (PKCS12_parse_PTR == nullptr)
    {
        load_symbol("PKCS12_parse", PKCS12_parse_PTR);
    }
    return PKCS12_parse_PTR(p12, pass, pkey, cert, ca);
}

void PKCS12_PBE_add()
{
    static void (*PKCS12_PBE_add_PTR)();
    if (PKCS12_PBE_add_PTR == nullptr)
    {
        load_symbol("PKCS12_PBE_add", PKCS12_PBE_add_PTR);
    }
    return PKCS12_PBE_add_PTR();
}

void RAND_add(const void *buf, int num, double randomness)
{
    static void (*RAND_add_PTR)(const void *buf, int num, double randomness);
    if (RAND_add_PTR == nullptr)
    {
        load_symbol("RAND_add", RAND_add_PTR);
    }
    return RAND_add_PTR(buf, num, randomness);
}

int RAND_bytes(unsigned char *buf, int num)
{
    static int (*RAND_bytes_PTR)(unsigned char *buf, int num);
    if (RAND_bytes_PTR == nullptr)
    {
        load_symbol("RAND_bytes", RAND_bytes_PTR);
    }
    return RAND_bytes_PTR(buf, num);
}

const char *RAND_file_name(char *file, size_t num)
{
    static const char *(*RAND_file_name_PTR)(char *file, size_t num);
    if (RAND_file_name_PTR == nullptr)
    {
        load_symbol("RAND_file_name", RAND_file_name_PTR);
    }
    return RAND_file_name_PTR(file, num);
}

int RAND_load_file(const char *file, long max_bytes)
{
    static int (*RAND_load_file_PTR)(const char *file, long max_bytes);
    if (RAND_load_file_PTR == nullptr)
    {
        load_symbol("RAND_load_file", RAND_load_file_PTR);
    }
    return RAND_load_file_PTR(file, max_bytes);
}

void RAND_seed(const void *buf, int num)
{
    static void (*RAND_seed_PTR)(const void *buf, int num);
    if (RAND_seed_PTR == nullptr)
    {
        load_symbol("RAND_seed", RAND_seed_PTR);
    }
    return RAND_seed_PTR(buf, num);
}

int RAND_status()
{
    static int (*RAND_status_PTR)();
    if (RAND_status_PTR == nullptr)
    {
        load_symbol("RAND_status", RAND_status_PTR);
    }
    return RAND_status_PTR();
}

int RSA_flags(const RSA *r)
{
    static int (*RSA_flags_PTR)(const RSA *r);
    if (RSA_flags_PTR == nullptr)
    {
        load_symbol("RSA_flags", RSA_flags_PTR);
    }
    return RSA_flags_PTR(r);
}

void RSA_free(RSA *r)
{
    static void (*RSA_free_PTR)(RSA *r);
    if (RSA_free_PTR == nullptr)
    {
        load_symbol("RSA_free", RSA_free_PTR);
    }
    return RSA_free_PTR(r);
}

int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    static int (*RSA_generate_key_ex_PTR)(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
    if (RSA_generate_key_ex_PTR == nullptr)
    {
        load_symbol("RSA_generate_key_ex", RSA_generate_key_ex_PTR);
    }
    return RSA_generate_key_ex_PTR(rsa, bits, e, cb);
}

void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    static void (*RSA_get0_key_PTR)(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
    if (RSA_get0_key_PTR == nullptr)
    {
        load_symbol("RSA_get0_key", RSA_get0_key_PTR);
    }
    return RSA_get0_key_PTR(r, n, e, d);
}

RSA *RSA_new()
{
    static RSA *(*RSA_new_PTR)();
    if (RSA_new_PTR == nullptr)
    {
        load_symbol("RSA_new", RSA_new_PTR);
    }
    return RSA_new_PTR();
}

int SHA256_Final(unsigned char *md, SHA256_CTX *c)
{
    static int (*SHA256_Final_PTR)(unsigned char *md, SHA256_CTX *c);
    if (SHA256_Final_PTR == nullptr)
    {
        load_symbol("SHA256_Final", SHA256_Final_PTR);
    }
    return SHA256_Final_PTR(md, c);
}

int SHA256_Init(SHA256_CTX *c)
{
    static int (*SHA256_Init_PTR)(SHA256_CTX *c);
    if (SHA256_Init_PTR == nullptr)
    {
        load_symbol("SHA256_Init", SHA256_Init_PTR);
    }
    return SHA256_Init_PTR(c);
}

int SHA256_Update(SHA256_CTX *c, const void *data, size_t len)
{
    static int (*SHA256_Update_PTR)(SHA256_CTX *c, const void *data, size_t len);
    if (SHA256_Update_PTR == nullptr)
    {
        load_symbol("SHA256_Update", SHA256_Update_PTR);
    }
    return SHA256_Update_PTR(c, data, len);
}

int SSL_accept(SSL *ssl)
{
    static int (*SSL_accept_PTR)(SSL *ssl);
    if (SSL_accept_PTR == nullptr)
    {
        load_symbol("SSL_accept", SSL_accept_PTR);
    }
    return SSL_accept_PTR(ssl);
}

const char *SSL_CIPHER_get_name(const SSL_CIPHER *c)
{
    static const char *(*SSL_CIPHER_get_name_PTR)(const SSL_CIPHER *c);
    if (SSL_CIPHER_get_name_PTR == nullptr)
    {
        load_symbol("SSL_CIPHER_get_name", SSL_CIPHER_get_name_PTR);
    }
    return SSL_CIPHER_get_name_PTR(c);
}

int SSL_connect(SSL *ssl)
{
    static int (*SSL_connect_PTR)(SSL *ssl);
    if (SSL_connect_PTR == nullptr)
    {
        load_symbol("SSL_connect", SSL_connect_PTR);
    }
    return SSL_connect_PTR(ssl);
}

long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg)
{
    static long (*SSL_ctrl_PTR)(SSL *ssl, int cmd, long larg, void *parg);
    if (SSL_ctrl_PTR == nullptr)
    {
        load_symbol("SSL_ctrl", SSL_ctrl_PTR);
    }
    return SSL_ctrl_PTR(ssl, cmd, larg, parg);
}

int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *x)
{
    static int (*SSL_CTX_add_client_CA_PTR)(SSL_CTX *ctx, X509 *x);
    if (SSL_CTX_add_client_CA_PTR == nullptr)
    {
        load_symbol("SSL_CTX_add_client_CA", SSL_CTX_add_client_CA_PTR);
    }
    return SSL_CTX_add_client_CA_PTR(ctx, x);
}

int SSL_CTX_check_private_key(const SSL_CTX *ctx)
{
    static int (*SSL_CTX_check_private_key_PTR)(const SSL_CTX *ctx);
    if (SSL_CTX_check_private_key_PTR == nullptr)
    {
        load_symbol("SSL_CTX_check_private_key", SSL_CTX_check_private_key_PTR);
    }
    return SSL_CTX_check_private_key_PTR(ctx);
}

long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
{
    static long (*SSL_CTX_ctrl_PTR)(SSL_CTX *ctx, int cmd, long larg, void *parg);
    if (SSL_CTX_ctrl_PTR == nullptr)
    {
        load_symbol("SSL_CTX_ctrl", SSL_CTX_ctrl_PTR);
    }
    return SSL_CTX_ctrl_PTR(ctx, cmd, larg, parg);
}

void SSL_CTX_flush_sessions(SSL_CTX *ctx, long tm)
{
    static void (*SSL_CTX_flush_sessions_PTR)(SSL_CTX *ctx, long tm);
    if (SSL_CTX_flush_sessions_PTR == nullptr)
    {
        load_symbol("SSL_CTX_flush_sessions", SSL_CTX_flush_sessions_PTR);
    }
    return SSL_CTX_flush_sessions_PTR(ctx, tm);
}

void SSL_CTX_free(SSL_CTX *ctx)
{
    static void (*SSL_CTX_free_PTR)(SSL_CTX *);
    if (SSL_CTX_free_PTR == nullptr)
    {
        load_symbol("SSL_CTX_free", SSL_CTX_free_PTR);
    }
    return SSL_CTX_free_PTR(ctx);
}

X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx)
{
    static X509_STORE *(*SSL_CTX_get_cert_store_PTR)(const SSL_CTX *);
    if (SSL_CTX_get_cert_store_PTR == nullptr)
    {
        load_symbol("SSL_CTX_get_cert_store", SSL_CTX_get_cert_store_PTR);
    }
    return SSL_CTX_get_cert_store_PTR(ctx);
}

long SSL_CTX_get_timeout(const SSL_CTX *ctx)
{
    static long (*SSL_CTX_get_timeout_PTR)(const SSL_CTX *ctx);
    if (SSL_CTX_get_timeout_PTR == nullptr)
    {
        load_symbol("SSL_CTX_get_timeout", SSL_CTX_get_timeout_PTR);
    }
    return SSL_CTX_get_timeout_PTR(ctx);
}

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath)
{
    static int (*SSL_CTX_load_verify_locations_PTR)(SSL_CTX *ctx, const char *CAfile, const char *CApath);
    if (SSL_CTX_load_verify_locations_PTR == nullptr)
    {
        load_symbol("SSL_CTX_load_verify_locations", SSL_CTX_load_verify_locations_PTR);
    }
    return SSL_CTX_load_verify_locations_PTR(ctx, CAfile, CApath);
}

SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth)
{
    static SSL_CTX *(*SSL_CTX_new_PTR)(const SSL_METHOD *meth);
    if (SSL_CTX_new_PTR == nullptr)
    {
        load_symbol("SSL_CTX_new", SSL_CTX_new_PTR);
    }
    return SSL_CTX_new_PTR(meth);
}

int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const unsigned char *protos, unsigned int protos_len)
{
    static int (*SSL_CTX_set_alpn_protos_PTR)(SSL_CTX *ctx, const unsigned char *protos, unsigned int protos_len);
    if (SSL_CTX_set_alpn_protos_PTR == nullptr)
    {
        load_symbol("SSL_CTX_set_alpn_protos", SSL_CTX_set_alpn_protos_PTR);
    }
    return SSL_CTX_set_alpn_protos_PTR(ctx, protos, protos_len);
}

int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str)
{
    static int (*SSL_CTX_set_cipher_list_PTR)(SSL_CTX *ctx, const char *str);
    if (SSL_CTX_set_cipher_list_PTR == nullptr)
    {
        load_symbol("SSL_CTX_set_cipher_list", SSL_CTX_set_cipher_list_PTR);
    }
    return SSL_CTX_set_cipher_list_PTR(ctx, str);
}

int SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str)
{
    static int (*SSL_CTX_set_ciphersuites_PTR)(SSL_CTX *ctx, const char *str);
    if (SSL_CTX_set_ciphersuites_PTR == nullptr)
    {
        load_symbol("SSL_CTX_set_ciphersuites", SSL_CTX_set_ciphersuites_PTR);
    }
    return SSL_CTX_set_ciphersuites_PTR(ctx, str);
}

void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb)
{
    static void (*SSL_CTX_set_default_passwd_cb_PTR)(SSL_CTX *ctx, pem_password_cb *cb);
    if (SSL_CTX_set_default_passwd_cb_PTR == nullptr)
    {
        load_symbol("SSL_CTX_set_default_passwd_cb", SSL_CTX_set_default_passwd_cb_PTR);
    }
    return SSL_CTX_set_default_passwd_cb_PTR(ctx, cb);
}

void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u)
{
    static void (*SSL_CTX_set_default_passwd_cb_userdata_PTR)(SSL_CTX *ctx, void *u);
    if (SSL_CTX_set_default_passwd_cb_userdata_PTR == nullptr)
    {
        load_symbol("SSL_CTX_set_default_passwd_cb_userdata", SSL_CTX_set_default_passwd_cb_userdata_PTR);
    }
    return SSL_CTX_set_default_passwd_cb_userdata_PTR(ctx, u);
}

int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx)
{
    static int (*SSL_CTX_set_default_verify_paths_PTR)(SSL_CTX *ctx);
    if (SSL_CTX_set_default_verify_paths_PTR == nullptr)
    {
        load_symbol("SSL_CTX_set_default_verify_paths", SSL_CTX_set_default_verify_paths_PTR);
    }
    return SSL_CTX_set_default_verify_paths_PTR(ctx);
}

void SSL_CTX_set_keylog_callback(SSL_CTX *ctx, SSL_CTX_keylog_cb_func cb)
{
    static void (*SSL_CTX_set_keylog_callback_PTR)(SSL_CTX *ctx, SSL_CTX_keylog_cb_func cb);
    if (SSL_CTX_set_keylog_callback_PTR == nullptr)
    {
        load_symbol("SSL_CTX_set_keylog_callback", SSL_CTX_set_keylog_callback_PTR);
    }
    return SSL_CTX_set_keylog_callback_PTR(ctx, cb);
}

void SSL_CTX_set_msg_callback(SSL_CTX *ctx, void (*cb)(int, int, int, const void *, size_t, SSL *, void *))
{
    static void (*SSL_CTX_set_msg_callback_PTR)(SSL_CTX *ctx, void (*cb)(int, int, int, const void *, size_t, SSL *, void *));
    if (SSL_CTX_set_msg_callback_PTR == nullptr)
    {
        load_symbol("SSL_CTX_set_msg_callback", SSL_CTX_set_msg_callback_PTR);
    }
    return SSL_CTX_set_msg_callback_PTR(ctx, cb);
}

void SSL_CTX_set_next_proto_select_cb(SSL_CTX *s, SSL_CTX_npn_select_cb_func cb, void *arg)
{
    static void (*SSL_CTX_set_next_proto_select_cb_PTR)(SSL_CTX *s, SSL_CTX_npn_select_cb_func cb, void *arg);
    if (SSL_CTX_set_next_proto_select_cb_PTR == nullptr)
    {
        load_symbol("SSL_CTX_set_next_proto_select_cb", SSL_CTX_set_next_proto_select_cb_PTR);
    }
    return SSL_CTX_set_next_proto_select_cb_PTR(s, cb, arg);
}

unsigned long SSL_CTX_set_options(SSL_CTX *ctx, unsigned long op)
{
    static unsigned long (*SSL_CTX_set_options_PTR)(SSL_CTX *ctx, unsigned long op);
    if (SSL_CTX_set_options_PTR == nullptr)
    {
        load_symbol("SSL_CTX_set_options", SSL_CTX_set_options_PTR);
    }
    return SSL_CTX_set_options_PTR(ctx, op);
}

int SSL_CTX_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid_ctx, unsigned int sid_ctx_len)
{
    static int (*SSL_CTX_set_session_id_context_PTR)(SSL_CTX *ctx, const unsigned char *sid_ctx, unsigned int sid_ctx_len);
    if (SSL_CTX_set_session_id_context_PTR == nullptr)
    {
        load_symbol("SSL_CTX_set_session_id_context", SSL_CTX_set_session_id_context_PTR);
    }
    return SSL_CTX_set_session_id_context_PTR(ctx, sid_ctx, sid_ctx_len);
}

long SSL_CTX_set_timeout(SSL_CTX *ctx, long t)
{
    static long (*SSL_CTX_set_timeout_PTR)(SSL_CTX *ctx, long t);
    if (SSL_CTX_set_timeout_PTR == nullptr)
    {
        load_symbol("SSL_CTX_set_timeout", SSL_CTX_set_timeout_PTR);
    }
    return SSL_CTX_set_timeout_PTR(ctx, t);
}

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb callback)
{
    static void (*SSL_CTX_set_verify_PTR)(SSL_CTX *ctx, int mode, SSL_verify_cb callback);
    if (SSL_CTX_set_verify_PTR == nullptr)
    {
        load_symbol("SSL_CTX_set_verify", SSL_CTX_set_verify_PTR);
    }
    return SSL_CTX_set_verify_PTR(ctx, mode, callback);
}

void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth)
{
    static void (*SSL_CTX_set_verify_depth_PTR)(SSL_CTX *ctx, int depth);
    if (SSL_CTX_set_verify_depth_PTR == nullptr)
    {
        load_symbol("SSL_CTX_set_verify_depth", SSL_CTX_set_verify_depth_PTR);
    }
    return SSL_CTX_set_verify_depth_PTR(ctx, depth);
}

int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x)
{
    static int (*SSL_CTX_use_certificate_PTR)(SSL_CTX *ctx, X509 *x);
    if (SSL_CTX_use_certificate_PTR == nullptr)
    {
        load_symbol("SSL_CTX_use_certificate", SSL_CTX_use_certificate_PTR);
    }
    return SSL_CTX_use_certificate_PTR(ctx, x);
}

int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file)
{
    static int (*SSL_CTX_use_certificate_chain_file_PTR)(SSL_CTX *ctx, const char *file);
    if (SSL_CTX_use_certificate_chain_file_PTR == nullptr)
    {
        load_symbol("SSL_CTX_use_certificate_chain_file", SSL_CTX_use_certificate_chain_file_PTR);
    }
    return SSL_CTX_use_certificate_chain_file_PTR(ctx, file);
}

int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type)
{
    static int (*SSL_CTX_use_certificate_file_PTR)(SSL_CTX *ctx, const char *file, int type);
    if (SSL_CTX_use_certificate_file_PTR == nullptr)
    {
        load_symbol("SSL_CTX_use_certificate_file", SSL_CTX_use_certificate_file_PTR);
    }
    return SSL_CTX_use_certificate_file_PTR(ctx, file, type);
}

int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
{
    static int (*SSL_CTX_use_PrivateKey_PTR)(SSL_CTX *ctx, EVP_PKEY *pkey);
    if (SSL_CTX_use_PrivateKey_PTR == nullptr)
    {
        load_symbol("SSL_CTX_use_PrivateKey", SSL_CTX_use_PrivateKey_PTR);
    }
    return SSL_CTX_use_PrivateKey_PTR(ctx, pkey);
}

int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
    static int (*SSL_CTX_use_PrivateKey_file_PTR)(SSL_CTX *ctx, const char *file, int type);
    if (SSL_CTX_use_PrivateKey_file_PTR == nullptr)
    {
        load_symbol("SSL_CTX_use_PrivateKey_file", SSL_CTX_use_PrivateKey_file_PTR);
    }
    return SSL_CTX_use_PrivateKey_file_PTR(ctx, file, type);
}

int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa)
{
    static int (*SSL_CTX_use_RSAPrivateKey_PTR)(SSL_CTX *ctx, RSA *rsa);
    if (SSL_CTX_use_RSAPrivateKey_PTR == nullptr)
    {
        load_symbol("SSL_CTX_use_RSAPrivateKey", SSL_CTX_use_RSAPrivateKey_PTR);
    }
    return SSL_CTX_use_RSAPrivateKey_PTR(ctx, rsa);
}

int SSL_do_handshake(SSL *s)
{
    static int (*SSL_do_handshake_PTR)(SSL *s);
    if (SSL_do_handshake_PTR == nullptr)
    {
        load_symbol("SSL_do_handshake", SSL_do_handshake_PTR);
    }
    return SSL_do_handshake_PTR(s);
}

void SSL_free(SSL *ssl)
{
    static void (*SSL_free_PTR)(SSL *ssl);
    if (SSL_free_PTR == nullptr)
    {
        load_symbol("SSL_free", SSL_free_PTR);
    }
    return SSL_free_PTR(ssl);
}

void SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data, unsigned int *len)
{
    static void (*SSL_get0_alpn_selected_PTR)(const SSL *ssl, const unsigned char **data, unsigned int *len);
    if (SSL_get0_alpn_selected_PTR == nullptr)
    {
        load_symbol("SSL_get0_alpn_selected", SSL_get0_alpn_selected_PTR);
    }
    return SSL_get0_alpn_selected_PTR(ssl, data, len);
}

SSL_SESSION *SSL_get1_session(SSL *ssl)
{
    static SSL_SESSION *(*SSL_get1_session_PTR)(SSL *ssl);
    if (SSL_get1_session_PTR == nullptr)
    {
        load_symbol("SSL_get1_session", SSL_get1_session_PTR);
    }
    return SSL_get1_session_PTR(ssl);
}

X509 *SSL_get_certificate(const SSL *ssl)
{
    static X509 *(*SSL_get_certificate_PTR)(const SSL *ssl);
    if (SSL_get_certificate_PTR == nullptr)
    {
        load_symbol("SSL_get_certificate", SSL_get_certificate_PTR);
    }
    return SSL_get_certificate_PTR(ssl);
}

const SSL_CIPHER *SSL_get_current_cipher(const SSL *s)
{
    static const SSL_CIPHER *(*SSL_get_current_cipher_PTR)(const SSL *s);
    if (SSL_get_current_cipher_PTR == nullptr)
    {
        load_symbol("SSL_get_current_cipher", SSL_get_current_cipher_PTR);
    }
    return SSL_get_current_cipher_PTR(s);
}

int SSL_get_error(const SSL *s, int ret_code)
{
    static int (*SSL_get_error_PTR)(const SSL *s, int ret_code);
    if (SSL_get_error_PTR == nullptr)
    {
        load_symbol("SSL_get_error", SSL_get_error_PTR);
    }
    return SSL_get_error_PTR(s, ret_code);
}

int SSL_get_ex_data_X509_STORE_CTX_idx()
{
    static int (*SSL_get_ex_data_X509_STORE_CTX_idx_PTR)();
    if (SSL_get_ex_data_X509_STORE_CTX_idx_PTR == nullptr)
    {
        load_symbol("SSL_get_ex_data_X509_STORE_CTX_idx", SSL_get_ex_data_X509_STORE_CTX_idx_PTR);
    }
    return SSL_get_ex_data_X509_STORE_CTX_idx_PTR();
}

int SSL_get_fd(const SSL *s)
{
    static int (*SSL_get_fd_PTR)(const SSL *s);
    if (SSL_get_fd_PTR == nullptr)
    {
        load_symbol("SSL_get_fd", SSL_get_fd_PTR);
    }
    return SSL_get_fd_PTR(s);
}

STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *s)
{
    static STACK_OF(X509) *(*SSL_get_peer_cert_chain_PTR)(const SSL *s);
    if (SSL_get_peer_cert_chain_PTR == nullptr)
    {
        load_symbol("SSL_get_peer_cert_chain", SSL_get_peer_cert_chain_PTR);
    }
    return SSL_get_peer_cert_chain_PTR(s);
}

X509 *SSL_get_peer_certificate(const SSL *s)
{
    static X509 *(*SSL_get_peer_certificate_PTR)(const SSL *s);
    if (SSL_get_peer_certificate_PTR == nullptr)
    {
        load_symbol("SSL_get_peer_certificate", SSL_get_peer_certificate_PTR);
    }
    return SSL_get_peer_certificate_PTR(s);
}

struct evp_pkey_st *SSL_get_privatekey(const SSL *ssl)
{
    static struct evp_pkey_st *(*SSL_get_privatekey_PTR)(const SSL *ssl);
    if (SSL_get_privatekey_PTR == nullptr)
    {
        load_symbol("SSL_get_privatekey", SSL_get_privatekey_PTR);
    }
    return SSL_get_privatekey_PTR(ssl);
}

int SSL_get_shutdown(const SSL *ssl)
{
    static int (*SSL_get_shutdown_PTR)(const SSL *ssl);
    if (SSL_get_shutdown_PTR == nullptr)
    {
        load_symbol("SSL_get_shutdown", SSL_get_shutdown_PTR);
    }
    return SSL_get_shutdown_PTR(ssl);
}

long SSL_get_verify_result(const SSL *ssl)
{
    static long (*SSL_get_verify_result_PTR)(const SSL *ssl);
    if (SSL_get_verify_result_PTR == nullptr)
    {
        load_symbol("SSL_get_verify_result", SSL_get_verify_result_PTR);
    }
    return SSL_get_verify_result_PTR(ssl);
}

SSL *SSL_new(SSL_CTX *ctx)
{
    static SSL *(*SSL_new_PTR)(SSL_CTX *ctx);
    if (SSL_new_PTR == nullptr)
    {
        load_symbol("SSL_new", SSL_new_PTR);
    }
    return SSL_new_PTR(ctx);
}

int SSL_pending(const SSL *s)
{
    static int (*SSL_pending_PTR)(const SSL *s);
    if (SSL_pending_PTR == nullptr)
    {
        load_symbol("SSL_pending", SSL_pending_PTR);
    }
    return SSL_pending_PTR(s);
}

int SSL_read(SSL *ssl, void *buf, int num)
{
    static int (*SSL_read_PTR)(SSL *ssl, void *buf, int num);
    if (SSL_read_PTR == nullptr)
    {
        load_symbol("SSL_read", SSL_read_PTR);
    }
    return SSL_read_PTR(ssl, buf, num);
}

void SSL_SESSION_free(SSL_SESSION *ses)
{
    static void (*SSL_SESSION_free_PTR)(SSL_SESSION *ses);
    if (SSL_SESSION_free_PTR == nullptr)
    {
        load_symbol("SSL_SESSION_free", SSL_SESSION_free_PTR);
    }
    return SSL_SESSION_free_PTR(ses);
}

int SSL_session_reused(const SSL *s)
{
    static int (*SSL_session_reused_PTR)(const SSL *s);
    if (SSL_session_reused_PTR == nullptr)
    {
        load_symbol("SSL_session_reused", SSL_session_reused_PTR);
    }
    return SSL_session_reused_PTR(s);
}

int SSL_set1_host(SSL *s, const char *hostname)
{
    static int (*SSL_set1_host_PTR)(SSL *s, const char *hostname);
    if (SSL_set1_host_PTR == nullptr)
    {
        load_symbol("SSL_set1_host", SSL_set1_host_PTR);
    }
    return SSL_set1_host_PTR(s, hostname);
}

void SSL_set_accept_state(SSL *s)
{
    static void (*SSL_set_accept_state_PTR)(SSL *s);
    if (SSL_set_accept_state_PTR == nullptr)
    {
        load_symbol("SSL_set_accept_state", SSL_set_accept_state_PTR);
    }
    return SSL_set_accept_state_PTR(s);
}

void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio)
{
    static void (*SSL_set_bio_PTR)(SSL *s, BIO *rbio, BIO *wbio);
    if (SSL_set_bio_PTR == nullptr)
    {
        load_symbol("SSL_set_bio", SSL_set_bio_PTR);
    }
    return SSL_set_bio_PTR(s, rbio, wbio);
}

void SSL_set_connect_state(SSL *s)
{
    static void (*SSL_set_connect_state_PTR)(SSL *s);
    if (SSL_set_connect_state_PTR == nullptr)
    {
        load_symbol("SSL_set_connect_state", SSL_set_connect_state_PTR);
    }
    return SSL_set_connect_state_PTR(s);
}

int SSL_set_fd(SSL *s, int fd)
{
    static int (*SSL_set_fd_PTR)(SSL *s, int fd);
    if (SSL_set_fd_PTR == nullptr)
    {
        load_symbol("SSL_set_fd", SSL_set_fd_PTR);
    }
    return SSL_set_fd_PTR(s, fd);
}

int SSL_set_session(SSL *to, SSL_SESSION *session)
{
    static int (*SSL_set_session_PTR)(SSL *to, SSL_SESSION *session);
    if (SSL_set_session_PTR == nullptr)
    {
        load_symbol("SSL_set_session", SSL_set_session_PTR);
    }
    return SSL_set_session_PTR(to, session);
}

int SSL_shutdown(SSL *s)
{
    static int (*SSL_shutdown_PTR)(SSL *s);
    if (SSL_shutdown_PTR == nullptr)
    {
        load_symbol("SSL_shutdown", SSL_shutdown_PTR);
    }
    return SSL_shutdown_PTR(s);
}

int SSL_version(const SSL *ssl)
{
    static int (*SSL_version_PTR)(const SSL *ssl);
    if (SSL_version_PTR == nullptr)
    {
        load_symbol("SSL_version", SSL_version_PTR);
    }
    return SSL_version_PTR(ssl);
}

int SSL_write(SSL *ssl, const void *buf, int num)
{
    static int (*SSL_write_PTR)(SSL *ssl, const void *buf, int num);
    if (SSL_write_PTR == nullptr)
    {
        load_symbol("SSL_write", SSL_write_PTR);
    }
    return SSL_write_PTR(ssl, buf, num);
}

const SSL_METHOD *TLS_client_method()
{
    static const SSL_METHOD *(*TLS_client_method_PTR)();
    if (TLS_client_method_PTR == nullptr)
    {
        load_symbol("TLS_client_method", TLS_client_method_PTR);
    }
    return TLS_client_method_PTR();
}

const SSL_METHOD *TLS_method()
{
    static const SSL_METHOD *(*TLS_method_PTR)();
    if (TLS_method_PTR == nullptr)
    {
        load_symbol("TLS_method", TLS_method_PTR);
    }
    return TLS_method_PTR();
}

const SSL_METHOD *TLS_server_method()
{
    static const SSL_METHOD *(*TLS_server_method_PTR)();
    if (TLS_server_method_PTR == nullptr)
    {
        load_symbol("TLS_server_method", TLS_server_method_PTR);
    }
    return TLS_server_method_PTR();
}

const SSL_METHOD *TLSv1_1_client_method()
{
    static const SSL_METHOD *(*TLSv1_1_client_method_PTR)();
    if (TLSv1_1_client_method_PTR == nullptr)
    {
        load_symbol("TLSv1_1_client_method", TLSv1_1_client_method_PTR);
    }
    return TLSv1_1_client_method_PTR();
}

const SSL_METHOD *TLSv1_1_server_method()
{
    static const SSL_METHOD *(*TLSv1_1_server_method_PTR)();
    if (TLSv1_1_server_method_PTR == nullptr)
    {
        load_symbol("TLSv1_1_server_method", TLSv1_1_server_method_PTR);
    }
    return TLSv1_1_server_method_PTR();
}

const SSL_METHOD *TLSv1_2_client_method()
{
    static const SSL_METHOD *(*TLSv1_2_client_method_PTR)();
    if (TLSv1_2_client_method_PTR == nullptr)
    {
        load_symbol("TLSv1_2_client_method", TLSv1_2_client_method_PTR);
    }
    return TLSv1_2_client_method_PTR();
}

const SSL_METHOD *TLSv1_2_server_method()
{
    static const SSL_METHOD *(*TLSv1_2_server_method_PTR)();
    if (TLSv1_2_server_method_PTR == nullptr)
    {
        load_symbol("TLSv1_2_server_method", TLSv1_2_server_method_PTR);
    }
    return TLSv1_2_server_method_PTR();
}

const SSL_METHOD *TLSv1_client_method()
{
    static const SSL_METHOD *(*TLSv1_client_method_PTR)();
    if (TLSv1_client_method_PTR == nullptr)
    {
        load_symbol("TLSv1_client_method", TLSv1_client_method_PTR);
    }
    return TLSv1_client_method_PTR();
}

const SSL_METHOD *TLSv1_server_method()
{
    static const SSL_METHOD *(*TLSv1_server_method_PTR)();
    if (TLSv1_server_method_PTR == nullptr)
    {
        load_symbol("TLSv1_server_method", TLSv1_server_method_PTR);
    }
    return TLSv1_server_method_PTR();
}

UI_METHOD *UI_create_method(const char *name)
{
    static UI_METHOD *(*UI_create_method_PTR)(const char *name);
    if (UI_create_method_PTR == nullptr)
    {
        load_symbol("UI_create_method", UI_create_method_PTR);
    }
    return UI_create_method_PTR(name);
}

void UI_destroy_method(UI_METHOD *ui_method)
{
    static void (*UI_destroy_method_PTR)(UI_METHOD *ui_method);
    if (UI_destroy_method_PTR == nullptr)
    {
        load_symbol("UI_destroy_method", UI_destroy_method_PTR);
    }
    return UI_destroy_method_PTR(ui_method);
}

void *UI_get0_user_data(UI *ui)
{
    static void *(*UI_get0_user_data_PTR)(UI *ui);
    if (UI_get0_user_data_PTR == nullptr)
    {
        load_symbol("UI_get0_user_data", UI_get0_user_data_PTR);
    }
    return UI_get0_user_data_PTR(ui);
}

int UI_get_input_flags(UI_STRING *uis)
{
    static int (*UI_get_input_flags_PTR)(UI_STRING *uis);
    if (UI_get_input_flags_PTR == nullptr)
    {
        load_symbol("UI_get_input_flags", UI_get_input_flags_PTR);
    }
    return UI_get_input_flags_PTR(uis);
}

enum UI_string_types UI_get_string_type(UI_STRING *uis)
{
    static enum UI_string_types (*UI_get_string_type_PTR)(UI_STRING *uis);
    if (UI_get_string_type_PTR == nullptr)
    {
        load_symbol("UI_get_string_type", UI_get_string_type_PTR);
    }
    return UI_get_string_type_PTR(uis);
}

int (*UI_method_get_closer(const UI_METHOD *method))(UI *)
{
    static int (*(*UI_method_get_closer_PTR)(const UI_METHOD *method))(UI *);
    if (UI_method_get_closer_PTR == nullptr)
    {
        load_symbol("UI_method_get_closer", UI_method_get_closer_PTR);
    }
    return UI_method_get_closer_PTR(method);
}

int (*UI_method_get_opener(const UI_METHOD *method))(UI *)
{
    static int (*(*UI_method_get_opener_PTR)(const UI_METHOD *method))(UI *);
    if (UI_method_get_opener_PTR == nullptr)
    {
        load_symbol("UI_method_get_opener", UI_method_get_opener_PTR);
    }
    return UI_method_get_opener_PTR(method);
}

int (*UI_method_get_reader(const UI_METHOD *method))(UI *, UI_STRING *)
{
    static int (*(*UI_method_get_reader_PTR)(const UI_METHOD *method))(UI *, UI_STRING *);
    if (UI_method_get_reader_PTR == nullptr)
    {
        load_symbol("UI_method_get_reader", UI_method_get_reader_PTR);
    }
    return UI_method_get_reader_PTR(method);
}

int (*UI_method_get_writer(const UI_METHOD *method))(UI *, UI_STRING *)
{
    static int (*(*UI_method_get_writer_PTR)(const UI_METHOD *method))(UI *, UI_STRING *);
    if (UI_method_get_writer_PTR == nullptr)
    {
        load_symbol("UI_method_get_writer", UI_method_get_writer_PTR);
    }
    return UI_method_get_writer_PTR(method);
}

int UI_method_set_closer(UI_METHOD *method, int (*closer)(UI *))
{
    static int (*UI_method_set_closer_PTR)(UI_METHOD *method, int (*closer)(UI *));
    if (UI_method_set_closer_PTR == nullptr)
    {
        load_symbol("UI_method_set_closer", UI_method_set_closer_PTR);
    }
    return UI_method_set_closer_PTR(method, closer);
}

int UI_method_set_opener(UI_METHOD *method, int (*opener)(UI *))
{
    static int (*UI_method_set_opener_PTR)(UI_METHOD *method, int (*opener)(UI *));
    if (UI_method_set_opener_PTR == nullptr)
    {
        load_symbol("UI_method_set_opener", UI_method_set_opener_PTR);
    }
    return UI_method_set_opener_PTR(method, opener);
}

int UI_method_set_reader(UI_METHOD *method, int (*reader)(UI *, UI_STRING *))
{
    static int (*UI_method_set_reader_PTR)(UI_METHOD *method, int (*reader)(UI *, UI_STRING *));
    if (UI_method_set_reader_PTR == nullptr)
    {
        load_symbol("UI_method_set_reader", UI_method_set_reader_PTR);
    }
    return UI_method_set_reader_PTR(method, reader);
}

int UI_method_set_writer(UI_METHOD *method, int (*writer)(UI *, UI_STRING *))
{
    static int (*UI_method_set_writer_PTR)(UI_METHOD *method, int (*writer)(UI *, UI_STRING *));
    if (UI_method_set_writer_PTR == nullptr)
    {
        load_symbol("UI_method_set_writer", UI_method_set_writer_PTR);
    }
    return UI_method_set_writer_PTR(method, writer);
}

UI_METHOD *UI_OpenSSL()
{
    static UI_METHOD *(*UI_OpenSSL_PTR)();
    if (UI_OpenSSL_PTR == nullptr)
    {
        load_symbol("UI_OpenSSL", UI_OpenSSL_PTR);
    }
    return UI_OpenSSL_PTR();
}

int UI_set_result(UI *ui, UI_STRING *uis, const char *result)
{
    static int (*UI_set_result_PTR)(UI *ui, UI_STRING *uis, const char *result);
    if (UI_set_result_PTR == nullptr)
    {
        load_symbol("UI_set_result", UI_set_result_PTR);
    }
    return UI_set_result_PTR(ui, uis, result);
}

int X509_check_host(X509 *x, const char *chk, size_t chklen, unsigned int flags, char **peername)
{
    static int (*X509_check_host_PTR)(X509 *x, const char *chk, size_t chklen, unsigned int flags, char **peername);
    if (X509_check_host_PTR == nullptr)
    {
        load_symbol("X509_check_host", X509_check_host_PTR);
    }
    return X509_check_host_PTR(x, chk, chklen, flags, peername);
}

int X509_check_ip_asc(X509 *x, const char *ipasc, unsigned int flags)
{
    static int (*X509_check_ip_asc_PTR)(X509 *x, const char *ipasc, unsigned int flags);
    if (X509_check_ip_asc_PTR == nullptr)
    {
        load_symbol("X509_check_ip_asc", X509_check_ip_asc_PTR);
    }
    return X509_check_ip_asc_PTR(x, ipasc, flags);
}

int X509_check_issued(X509 *issuer, X509 *subject)
{
    static int (*X509_check_issued_PTR)(X509 *issuer, X509 *subject);
    if (X509_check_issued_PTR == nullptr)
    {
        load_symbol("X509_check_issued", X509_check_issued_PTR);
    }
    return X509_check_issued_PTR(issuer, subject);
}

int X509_cmp(const X509 *a, const X509 *b)
{
    static int (*X509_cmp_PTR)(const X509 *a, const X509 *b);
    if (X509_cmp_PTR == nullptr)
    {
        load_symbol("X509_cmp", X509_cmp_PTR);
    }
    return X509_cmp_PTR(a, b);
}

X509 *X509_dup(X509 *x509)
{
    static X509 *(*X509_dup_PTR)(X509 *x509);
    if (X509_dup_PTR == nullptr)
    {
        load_symbol("X509_dup", X509_dup_PTR);
    }
    return X509_dup_PTR(x509);
}

ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ne)
{
    static ASN1_OCTET_STRING *(*X509_EXTENSION_get_data_PTR)(X509_EXTENSION *ne);
    if (X509_EXTENSION_get_data_PTR == nullptr)
    {
        load_symbol("X509_EXTENSION_get_data", X509_EXTENSION_get_data_PTR);
    }
    return X509_EXTENSION_get_data_PTR(ne);
}

ASN1_OBJECT *X509_EXTENSION_get_object(X509_EXTENSION *ex)
{
    static ASN1_OBJECT *(*X509_EXTENSION_get_object_PTR)(X509_EXTENSION *ex);
    if (X509_EXTENSION_get_object_PTR == nullptr)
    {
        load_symbol("X509_EXTENSION_get_object", X509_EXTENSION_get_object_PTR);
    }
    return X509_EXTENSION_get_object_PTR(ex);
}

void X509_free(X509 *a)
{
    static void (*X509_free_PTR)(X509 *a);
    if (X509_free_PTR == nullptr)
    {
        load_symbol("X509_free", X509_free_PTR);
    }
    return X509_free_PTR(a);
}

const STACK_OF(X509_EXTENSION) *X509_get0_extensions(const X509 *x)
{
    static const STACK_OF(X509_EXTENSION) *(*X509_get0_extensions_PTR)(const X509 *x);
    if (X509_get0_extensions_PTR == nullptr)
    {
        load_symbol("X509_get0_extensions", X509_get0_extensions_PTR);
    }
    return X509_get0_extensions_PTR(x);
}

const ASN1_TIME *X509_get0_notAfter(const X509 *x)
{
    static const ASN1_TIME *(*X509_get0_notAfter_PTR)(const X509 *x);
    if (X509_get0_notAfter_PTR == nullptr)
    {
        load_symbol("X509_get0_notAfter", X509_get0_notAfter_PTR);
    }
    return X509_get0_notAfter_PTR(x);
}

const ASN1_TIME * X509_get0_notBefore(const X509 *x)
{
    static const ASN1_TIME * (*X509_get0_notBefore_PTR)(const X509 *x);
    if (X509_get0_notBefore_PTR == nullptr)
    {
        load_symbol("X509_get0_notBefore", X509_get0_notBefore_PTR);
    }
    return X509_get0_notBefore_PTR(x);
}

void X509_get0_signature(const ASN1_BIT_STRING **psig, const X509_ALGOR **palg, const X509 *x)
{
    static void (*X509_get0_signature_PTR)(const ASN1_BIT_STRING **psig, const X509_ALGOR **palg, const X509 *x);
    if (X509_get0_signature_PTR == nullptr)
    {
        load_symbol("X509_get0_signature", X509_get0_signature_PTR);
    }
    return X509_get0_signature_PTR(psig, palg, x);
}

void *X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx)
{
    static void *(*X509_get_ext_d2i_PTR)(const X509 *x, int nid, int *crit, int *idx);
    if (X509_get_ext_d2i_PTR == nullptr)
    {
        load_symbol("X509_get_ext_d2i", X509_get_ext_d2i_PTR);
    }
    return X509_get_ext_d2i_PTR(x, nid, crit, idx);
}

X509_NAME *X509_get_issuer_name(const X509 *a)
{
    static X509_NAME *(*X509_get_issuer_name_PTR)(const X509 *a);
    if (X509_get_issuer_name_PTR == nullptr)
    {
        load_symbol("X509_get_issuer_name", X509_get_issuer_name_PTR);
    }
    return X509_get_issuer_name_PTR(a);
}

ASN1_TIME *X509_getm_notAfter(const X509 *x)
{
    static ASN1_TIME *(*X509_getm_notAfter_PTR)(const X509 *x);
    if (X509_getm_notAfter_PTR == nullptr)
    {
        load_symbol("X509_getm_notAfter", X509_getm_notAfter_PTR);
    }
    return X509_getm_notAfter_PTR(x);
}

ASN1_TIME *X509_getm_notBefore(const X509 *x)
{
    static ASN1_TIME *(*X509_getm_notBefore_PTR)(const X509 *x);
    if (X509_getm_notBefore_PTR == nullptr)
    {
        load_symbol("X509_getm_notBefore", X509_getm_notBefore_PTR);
    }
    return X509_getm_notBefore_PTR(x);
}

EVP_PKEY *X509_get_pubkey(X509 *x)
{
    static EVP_PKEY *(*X509_get_pubkey_PTR)(X509 *x);
    if (X509_get_pubkey_PTR == nullptr)
    {
        load_symbol("X509_get_pubkey", X509_get_pubkey_PTR);
    }
    return X509_get_pubkey_PTR(x);
}

ASN1_INTEGER *X509_get_serialNumber(X509 *x)
{
    static ASN1_INTEGER *(*X509_get_serialNumber_PTR)(X509 *x);
    if (X509_get_serialNumber_PTR == nullptr)
    {
        load_symbol("X509_get_serialNumber", X509_get_serialNumber_PTR);
    }
    return X509_get_serialNumber_PTR(x);
}

int X509_get_signature_nid(const X509 *x)
{
    static int (*X509_get_signature_nid_PTR)(const X509 *x);
    if (X509_get_signature_nid_PTR == nullptr)
    {
        load_symbol("X509_get_signature_nid", X509_get_signature_nid_PTR);
    }
    return X509_get_signature_nid_PTR(x);
}

X509_NAME *X509_get_subject_name(const X509 *a)
{
    static X509_NAME *(*X509_get_subject_name_PTR)(const X509 *a);
    if (X509_get_subject_name_PTR == nullptr)
    {
        load_symbol("X509_get_subject_name", X509_get_subject_name_PTR);
    }
    return X509_get_subject_name_PTR(a);
}

long X509_get_version(const X509 *x)
{
    static long (*X509_get_version_PTR)(const X509 *x);
    if (X509_get_version_PTR == nullptr)
    {
        load_symbol("X509_get_version", X509_get_version_PTR);
    }
    return X509_get_version_PTR(x);
}

X509_PUBKEY *X509_get_X509_PUBKEY(const X509 *x)
{
    static X509_PUBKEY *(*X509_get_X509_PUBKEY_PTR)(const X509 *x);
    if (X509_get_X509_PUBKEY_PTR == nullptr)
    {
        load_symbol("X509_get_X509_PUBKEY", X509_get_X509_PUBKEY_PTR);
    }
    return X509_get_X509_PUBKEY_PTR(x);
}

ASN1_TIME *X509_gmtime_adj(ASN1_TIME *s, long adj)
{
    static ASN1_TIME *(*X509_gmtime_adj_PTR)(ASN1_TIME *s, long adj);
    if (X509_gmtime_adj_PTR == nullptr)
    {
        load_symbol("X509_gmtime_adj", X509_gmtime_adj_PTR);
    }
    return X509_gmtime_adj_PTR(s, adj);
}

int X509_load_crl_file(X509_LOOKUP *ctx, const char *file, int type)
{
    static int (*X509_load_crl_file_PTR)(X509_LOOKUP *ctx, const char *file, int type);
    if (X509_load_crl_file_PTR == nullptr)
    {
        load_symbol("X509_load_crl_file", X509_load_crl_file_PTR);
    }
    return X509_load_crl_file_PTR(ctx, file, type);
}

X509_LOOKUP_METHOD *X509_LOOKUP_file()
{
    static X509_LOOKUP_METHOD *(*X509_LOOKUP_file_PTR)();
    if (X509_LOOKUP_file_PTR == nullptr)
    {
        load_symbol("X509_LOOKUP_file", X509_LOOKUP_file_PTR);
    }
    return X509_LOOKUP_file_PTR();
}

int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type, const unsigned char *bytes, int len, int loc, int set)
{
    static int (*X509_NAME_add_entry_by_txt_PTR)(X509_NAME *name, const char *field, int type, const unsigned char *bytes, int len, int loc, int set);
    if (X509_NAME_add_entry_by_txt_PTR == nullptr)
    {
        load_symbol("X509_NAME_add_entry_by_txt", X509_NAME_add_entry_by_txt_PTR);
    }
    return X509_NAME_add_entry_by_txt_PTR(name, field, type, bytes, len, loc, set);
}

ASN1_STRING * X509_NAME_ENTRY_get_data(const X509_NAME_ENTRY *ne)
{
    static ASN1_STRING * (*X509_NAME_ENTRY_get_data_PTR)(const X509_NAME_ENTRY *ne);
    if (X509_NAME_ENTRY_get_data_PTR == nullptr)
    {
        load_symbol("X509_NAME_ENTRY_get_data", X509_NAME_ENTRY_get_data_PTR);
    }
    return X509_NAME_ENTRY_get_data_PTR(ne);
}

X509_NAME_ENTRY *X509_NAME_get_entry(const X509_NAME *name, int loc)
{
    static X509_NAME_ENTRY *(*X509_NAME_get_entry_PTR)(const X509_NAME *name, int loc);
    if (X509_NAME_get_entry_PTR == nullptr)
    {
        load_symbol("X509_NAME_get_entry", X509_NAME_get_entry_PTR);
    }
    return X509_NAME_get_entry_PTR(name, loc);
}

int X509_NAME_get_index_by_NID(X509_NAME *name, int nid, int lastpos)
{
    static int (*X509_NAME_get_index_by_NID_PTR)(X509_NAME *name, int nid, int lastpos);
    if (X509_NAME_get_index_by_NID_PTR == nullptr)
    {
        load_symbol("X509_NAME_get_index_by_NID", X509_NAME_get_index_by_NID_PTR);
    }
    return X509_NAME_get_index_by_NID_PTR(name, nid, lastpos);
}

int X509_NAME_get_text_by_NID(X509_NAME *name, int nid, char *buf, int len)
{
    static int (*X509_NAME_get_text_by_NID_PTR)(X509_NAME *name, int nid, char *buf, int len);
    if (X509_NAME_get_text_by_NID_PTR == nullptr)
    {
        load_symbol("X509_NAME_get_text_by_NID", X509_NAME_get_text_by_NID_PTR);
    }
    return X509_NAME_get_text_by_NID_PTR(name, nid, buf, len);
}

char *X509_NAME_oneline(const X509_NAME *a, char *buf, int size)
{
    static char *(*X509_NAME_oneline_PTR)(const X509_NAME *a, char *buf, int size);
    if (X509_NAME_oneline_PTR == nullptr)
    {
        load_symbol("X509_NAME_oneline", X509_NAME_oneline_PTR);
    }
    return X509_NAME_oneline_PTR(a, buf, size);
}

int X509_NAME_print_ex(BIO *out, const X509_NAME *nm, int indent, unsigned long flags)
{
    static int (*X509_NAME_print_ex_PTR)(BIO *out, const X509_NAME *nm, int indent, unsigned long flags);
    if (X509_NAME_print_ex_PTR == nullptr)
    {
        load_symbol("X509_NAME_print_ex", X509_NAME_print_ex_PTR);
    }
    return X509_NAME_print_ex_PTR(out, nm, indent, flags);
}

X509 *X509_new()
{
    static X509 *(*X509_new_PTR)();
    if (X509_new_PTR == nullptr)
    {
        load_symbol("X509_new", X509_new_PTR);
    }
    return X509_new_PTR();
}

int X509_set_issuer_name(X509 *x, X509_NAME *name)
{
    static int (*X509_set_issuer_name_PTR)(X509 *x, X509_NAME *name);
    if (X509_set_issuer_name_PTR == nullptr)
    {
        load_symbol("X509_set_issuer_name", X509_set_issuer_name_PTR);
    }
    return X509_set_issuer_name_PTR(x, name);
}

int X509_set_pubkey(X509 *x, EVP_PKEY *pkey)
{
    static int (*X509_set_pubkey_PTR)(X509 *x, EVP_PKEY *pkey);
    if (X509_set_pubkey_PTR == nullptr)
    {
        load_symbol("X509_set_pubkey", X509_set_pubkey_PTR);
    }
    return X509_set_pubkey_PTR(x, pkey);
}

int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md)
{
    static int (*X509_sign_PTR)(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);
    if (X509_sign_PTR == nullptr)
    {
        load_symbol("X509_sign", X509_sign_PTR);
    }
    return X509_sign_PTR(x, pkey, md);
}

int X509_signature_print(BIO *bp, const X509_ALGOR *alg, const ASN1_STRING *sig)
{
    static int (*X509_signature_print_PTR)(BIO *bp, const X509_ALGOR *alg, const ASN1_STRING *sig);
    if (X509_signature_print_PTR == nullptr)
    {
        load_symbol("X509_signature_print", X509_signature_print_PTR);
    }
    return X509_signature_print_PTR(bp, alg, sig);
}

int X509_STORE_add_cert(X509_STORE *ctx, X509 *x)
{
    static int (*X509_STORE_add_cert_PTR)(X509_STORE *ctx, X509 *x);
    if (X509_STORE_add_cert_PTR == nullptr)
    {
        load_symbol("X509_STORE_add_cert", X509_STORE_add_cert_PTR);
    }
    return X509_STORE_add_cert_PTR(ctx, x);
}

X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *v, X509_LOOKUP_METHOD *m)
{
    static X509_LOOKUP *(*X509_STORE_add_lookup_PTR)(X509_STORE *v, X509_LOOKUP_METHOD *m);
    if (X509_STORE_add_lookup_PTR == nullptr)
    {
        load_symbol("X509_STORE_add_lookup", X509_STORE_add_lookup_PTR);
    }
    return X509_STORE_add_lookup_PTR(v, m);
}

X509 *X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx)
{
    static X509 *(*X509_STORE_CTX_get_current_cert_PTR)(X509_STORE_CTX *ctx);
    if (X509_STORE_CTX_get_current_cert_PTR == nullptr)
    {
        load_symbol("X509_STORE_CTX_get_current_cert", X509_STORE_CTX_get_current_cert_PTR);
    }
    return X509_STORE_CTX_get_current_cert_PTR(ctx);
}

int X509_STORE_CTX_get_error(X509_STORE_CTX *ctx)
{
    static int (*X509_STORE_CTX_get_error_PTR)(X509_STORE_CTX *ctx);
    if (X509_STORE_CTX_get_error_PTR == nullptr)
    {
        load_symbol("X509_STORE_CTX_get_error", X509_STORE_CTX_get_error_PTR);
    }
    return X509_STORE_CTX_get_error_PTR(ctx);
}

int X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx)
{
    static int (*X509_STORE_CTX_get_error_depth_PTR)(X509_STORE_CTX *ctx);
    if (X509_STORE_CTX_get_error_depth_PTR == nullptr)
    {
        load_symbol("X509_STORE_CTX_get_error_depth", X509_STORE_CTX_get_error_depth_PTR);
    }
    return X509_STORE_CTX_get_error_depth_PTR(ctx);
}

void *X509_STORE_CTX_get_ex_data(X509_STORE_CTX *ctx, int idx)
{
    static void *(*X509_STORE_CTX_get_ex_data_PTR)(X509_STORE_CTX *ctx, int idx);
    if (X509_STORE_CTX_get_ex_data_PTR == nullptr)
    {
        load_symbol("X509_STORE_CTX_get_ex_data", X509_STORE_CTX_get_ex_data_PTR);
    }
    return X509_STORE_CTX_get_ex_data_PTR(ctx, idx);
}

int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags)
{
    static int (*X509_STORE_set_flags_PTR)(X509_STORE *ctx, unsigned long flags);
    if (X509_STORE_set_flags_PTR == nullptr)
    {
        load_symbol("X509_STORE_set_flags", X509_STORE_set_flags_PTR);
    }
    return X509_STORE_set_flags_PTR(ctx, flags);
}

int X509_up_ref(X509 *x)
{
    static int (*X509_up_ref_PTR)(X509 *x);
    if (X509_up_ref_PTR == nullptr)
    {
        load_symbol("X509_up_ref", X509_up_ref_PTR);
    }
    return X509_up_ref_PTR(x);
}

int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, unsigned long flag, int indent)
{
    static int (*X509V3_EXT_print_PTR)(BIO *out, X509_EXTENSION *ext, unsigned long flag, int indent);
    if (X509V3_EXT_print_PTR == nullptr)
    {
        load_symbol("X509V3_EXT_print", X509V3_EXT_print_PTR);
    }
    return X509V3_EXT_print_PTR(out, ext, flag, indent);
}

int X509_verify(X509 *a, EVP_PKEY *r)
{
    static int (*X509_verify_PTR)(X509 *a, EVP_PKEY *r);
    if (X509_verify_PTR == nullptr)
    {
        load_symbol("X509_verify", X509_verify_PTR);
    }
    return X509_verify_PTR(a, r);
}

const char *X509_verify_cert_error_string(long n)
{
    static const char *(*X509_verify_cert_error_string_PTR)(long n);
    if (X509_verify_cert_error_string_PTR == nullptr)
    {
        load_symbol("X509_verify_cert_error_string", X509_verify_cert_error_string_PTR);
    }
    return X509_verify_cert_error_string_PTR(n);
}
