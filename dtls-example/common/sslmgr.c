#import "sslmgr.h"

//static void sigpipe_handler (int);

BIO *dtls_bio_err = 0;
char *pass;
int verify_depth = 0;
int verify_error = X509_V_OK;

int dtls_exit_err (char *string)
{
	fprintf (stderr, "%s: %s(): %s\n", __FILE__, __func__, string);
	exit (0);
}

void dtls_report_berr (char *fmt, ...)
{
	va_list args;

	va_start (args, fmt);
	
	vfprintf (stderr, fmt, args);
	ERR_print_errors (dtls_bio_err);
	va_end(args);
	exit (0);
}

int dtls_generate_rsa_key (SSL_CTX *ctx)
{
	RSA *rsa = NULL;
	
	rsa = RSA_generate_key (1024, RSA_F4, NULL, NULL);

	if (!SSL_CTX_set_tmp_rsa (ctx, rsa))
	{
		dtls_report_err ("%s: %s(): Failed to set RSA Key\n", __FILE__, __func__);
		return 1;
	}

	RSA_free (rsa);
	return 0;
}

void dtls_report_err (char *fmt, ...)
{
	va_list args;

	va_start (args, fmt);
	
	vfprintf (stderr, fmt, args);
	ERR_print_errors (dtls_bio_err);
	va_end(args);
}

void dtls_load_dh_params (SSL_CTX *ctx, char *dh_file)
{
	DH *ret = 0;
	BIO *bio = NULL;
	
	if (NULL == (bio = BIO_new_file (dh_file, "r")))
	{
		dtls_destroy_ctx (ctx);
		dtls_report_berr ("%s: %s(): Unable to load DH parameters - %s\n", __FILE__, __func__, strerror (errno));
	}

	ret = PEM_read_bio_DHparams (bio, NULL, NULL, NULL);
	BIO_free (bio);

	if (SSL_CTX_set_tmp_dh (ctx, ret) < 0)
	{
		dtls_destroy_ctx (ctx);
		dtls_report_berr ("%s: %s(): Unable to set DH Parameters - %s\n", __FILE__, __func__, strerror (errno));
	}

	DH_free (ret);
	return;
}

int dtls_password_cb (char *buf, int num, int rwflag, void *userdata)
{
	if ((NULL == pass) || (NULL == buf))
		return 0;

	if (num < (strlen (pass) + 1))
		return 0;

	strcpy (buf, pass);

	return strlen (buf);
}

void dtls_info_callback (const SSL *ssl, int where, int ret)
{
	const char *str = NULL;
	int w;

	w = where & ~SSL_ST_MASK;

	str = where & SSL_ST_CONNECT ? "connect" : where & SSL_ST_ACCEPT ? "accept" : "undefined";
	if (where & SSL_CB_LOOP)
	{
		dtls_report_err ("SSL state [\"%s\"]: %s\n", str, SSL_state_string_long (ssl));
	}
	else if (where & SSL_CB_ALERT)
	{
		dtls_report_err ("SSL: alert [\"%s\"]: %s : %s\n", where & SSL_CB_READ ? "read" : "write", \
			SSL_alert_type_string_long (ret), SSL_alert_desc_string_long (ret));
	}
}

#if 0
static void sigpipe_handler (int x)
{
	/* Do something here */
}
#endif

void dtls_destroy_ctx (SSL_CTX *ctx)
{
	SSL_CTX_free (ctx);
	return;
}

int dtls_verify_callback (int ok, X509_STORE_CTX *ctx)
{
	char buf[256] = {0};
	X509 *err_cert = NULL;
	int err = 0, depth = 0;

	err_cert = X509_STORE_CTX_get_current_cert (ctx);
	err = X509_STORE_CTX_get_error (ctx);
	depth = X509_STORE_CTX_get_error_depth (ctx);

	X509_NAME_oneline (X509_get_subject_name (err_cert), buf, sizeof buf);
	dtls_report_err ("depth=%d %s\n", depth, buf);
	if (!ok)
	{
		dtls_report_err ("verify error:num = %d:%s\n", err, X509_verify_cert_error_string(err));
		if (verify_depth >= depth)
		{
			ok = 1;
			verify_error = X509_V_OK;
		}
		else
		{
			ok = 0;
			verify_error = X509_V_ERR_CERT_CHAIN_TOO_LONG;
		}
	}
	switch (ctx->error)
	{
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			X509_NAME_oneline (X509_get_issuer_name (ctx->current_cert), buf, sizeof buf);
			dtls_report_err ("issuer= %s\n",buf);
			break;
		case X509_V_ERR_CERT_NOT_YET_VALID:
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			dtls_report_err ("notBefore=");
			ASN1_TIME_print (dtls_bio_err, X509_get_notBefore (ctx->current_cert));
			dtls_report_err ("\n");
			break;
		case X509_V_ERR_CERT_HAS_EXPIRED:
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			dtls_report_err ("notAfter=");
			ASN1_TIME_print (dtls_bio_err, X509_get_notAfter(ctx->current_cert));
			BIO_printf(dtls_bio_err,"\n");
			break;
	}
	dtls_report_err ("verify return:%d\n", ok);

	return (ok);
}
