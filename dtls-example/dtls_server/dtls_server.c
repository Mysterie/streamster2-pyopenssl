/* File : dtls_server.c */
/*
*/
/******************************** dtls_server.c********************************/
/*                                                                            */
/* Abstract:                                                                  */
/* This file contains APIs for setting up DTLSv1 server                       */
/*                                                                            */
/******************************************************************************/
/* Other copyright info							      */
/* Most parts of the DTLSv1 server implementation are taken from OpenSSLv0.9.8*/
/* source file apps/s_server.c - DTLS implementation written by Nagendra      */
/* Modadugu (nagendra@cs.stanford.edu) for the OpenSSL project 2005.          */
/******************************************************************************/
/*                                                                            */
/* Initial File Information:                                                  */
/*                                                                            */
/* Initial Filename: dtls_server.c                                            */
/* Filetype: C/Source                                                         */
/* Author: Arun S.                                                            */
/* e-mail: hi2arun [at] gmail [dot] com                                       */
/******************************************************************************/
/******************************************************************************/
 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <assert.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#include <dirent.h>

#import "sslmgr.h"

#define INVALID_KEY_ARRAY_SIZE	100
#define DTLS_CERT "dtls.pem"
#define DTLS_CA_KEY "dtlsCA.key"
#define DTLS_KEY_CERT "dtls.key"
#define DTLS_CSR "dtls.csr"
#define DTLS_CA_CERT "dtlsCA.pem"
#define DTLS_DH_FILE "dtlsDH.pem"

#define DTLSC_CERT "client/dtlsc.pem"
#define DTLSC_KEY_CERT "client/dtlsc.key"
#define DTLSC_CSR "client/dtls.csr"

SSL_CTX *dtls_setup_ssl_server (void);
static int setup_udpserver(int);
static int init_ssl_connection(SSL *con);

extern int verify_list;
int accept_socket;
FILE *log_fp;
BIO *bio_err = NULL;
BIO *bio_s_out = NULL;

#ifdef DEBUG
static void print_stats(BIO *bio, SSL_CTX *ssl_ctx)
{
	BIO_printf(bio,"%4ld items in the session cache\n",
		SSL_CTX_sess_number(ssl_ctx));
	BIO_printf(bio,"%4ld client connects (SSL_connect())\n",
		SSL_CTX_sess_connect(ssl_ctx));
	BIO_printf(bio,"%4ld client renegotiates (SSL_connect())\n",
		SSL_CTX_sess_connect_renegotiate(ssl_ctx));
	BIO_printf(bio,"%4ld client connects that finished\n",
		SSL_CTX_sess_connect_good(ssl_ctx));
	BIO_printf(bio,"%4ld server accepts (SSL_accept())\n",
		SSL_CTX_sess_accept(ssl_ctx));
	BIO_printf(bio,"%4ld server renegotiates (SSL_accept())\n",
		SSL_CTX_sess_accept_renegotiate(ssl_ctx));
	BIO_printf(bio,"%4ld server accepts that finished\n",
		SSL_CTX_sess_accept_good(ssl_ctx));
	BIO_printf(bio,"%4ld session cache hits\n",SSL_CTX_sess_hits(ssl_ctx));
	BIO_printf(bio,"%4ld session cache misses\n",SSL_CTX_sess_misses(ssl_ctx));
	BIO_printf(bio,"%4ld session cache timeouts\n",SSL_CTX_sess_timeouts(ssl_ctx));
	BIO_printf(bio,"%4ld callback cache hits\n",SSL_CTX_sess_cb_hits(ssl_ctx));
	BIO_printf(bio,"%4ld cache full overflows (%ld allowed)\n",
		SSL_CTX_sess_cache_full(ssl_ctx),
		SSL_CTX_sess_get_cache_size(ssl_ctx));
}
#endif

int dtls_get_data (int s, SSL_CTX *ctx)
{
	char *buf = NULL;
	fd_set readfds;
	int ret = 1, width = 0;
	int i = 0;
	SSL *con = NULL;
	BIO *sbio = NULL;
	int bufsize = BUFSIZ;
	bio_err = BIO_new_fp (stderr, BIO_NOCLOSE);
	bio_s_out = BIO_new_fp (stderr, BIO_NOCLOSE);

	
	if ((buf = OPENSSL_malloc (bufsize)) == NULL)
	{
		BIO_printf (bio_err, "out of memory\n");
		goto ERR;
	}

	if (con == NULL) 
	{
		con = SSL_new(ctx);
	}
	SSL_clear (con);

	if (SSL_version (con) == DTLS1_VERSION)
	{
		struct timeval timeout;

		sbio = BIO_new_dgram (s, BIO_NOCLOSE);

		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		BIO_ctrl (sbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
			
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		BIO_ctrl (sbio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);

		
			/* want to do MTU discovery */
		BIO_ctrl (sbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);

	        /* turn on cookie exchange */
        	SSL_set_options (con, SSL_OP_COOKIE_EXCHANGE);
//		fprintf (stderr, "%s: %s(): DTLSv1 Initialization done\n", __FILE__, __func__);
	}

	SSL_set_bio (con, sbio, sbio);
	SSL_set_accept_state (con);
	/* SSL_set_fd(con,s); */

	width = s + 1;
	for (;;)
	{
		int read_from_terminal;
		int read_from_sslcon;

		read_from_terminal = 0;
		read_from_sslcon = SSL_pending (con);

		if (!read_from_sslcon)
		{
			struct timeval tv;
			FD_ZERO(&readfds);
			FD_SET(s, &readfds);
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			i = select(width, (void *)&readfds, NULL, NULL, &tv);
			if (i < 0)
			{
				continue;
			}
			if (FD_ISSET (s, &readfds))
			{
				read_from_sslcon = 1;
			}
			else
			{
				ret = 2;
				goto shut;
			}
		}
		if (read_from_sslcon)
		{
			if (!SSL_is_init_finished(con))
			{
				i = init_ssl_connection(con);
			
				if (i < 0)
				{
					ret = 0;
					goto ERR;
				}
				else if (i == 0)
				{
					ret = 1;
					goto ERR;
				}
			}
			else
			{
AGAIN:	
				i = SSL_read (con, (char *) buf, bufsize);
				switch (SSL_get_error (con, i))
				{
					case SSL_ERROR_NONE:
						write (fileno (stdout), buf, (unsigned int) i);
						if (SSL_pending(con)) 
						{
							fprintf (stderr, "%s: %s(): Some more seems to be coming... "\
								"letz wait for that\n", __FILE__, __func__);
							goto AGAIN;
						}
						else
							fprintf (stderr, "%s(): Hey, itz all over boss... do finishing "\
								"ceremony\n", __func__);
						ret = 0;
						goto ERR;
					case SSL_ERROR_WANT_WRITE:
					case SSL_ERROR_WANT_READ:
					case SSL_ERROR_WANT_X509_LOOKUP:
						BIO_printf(bio_s_out,"Read BLOCK\n");
						break;
					case SSL_ERROR_SYSCALL:
					case SSL_ERROR_SSL:
						BIO_printf(bio_s_out,"ERROR\n");
						ERR_print_errors(bio_err);
						ret = 1;
						goto ERR;
					case SSL_ERROR_ZERO_RETURN:
						BIO_printf(bio_s_out,"\nDONE\n");
						ret = 0;
						goto ERR;
				}
			}
		}
	}
ERR:
	if (0 == ret)
	{
		char temp [] = "ACK from SERVER: READ SUCCESSFULLY DONE\n";
		for (;;)
		{
			i = SSL_write (con, temp, strlen (temp));

			switch (SSL_get_error (con, i))
			{
				case SSL_ERROR_NONE:
					if (SSL_pending (con))
						break;
					else
						goto WRITEDONE;
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_X509_LOOKUP:
					BIO_printf (bio_s_out, "Write BLOCK\n");
					break;
				case SSL_ERROR_SYSCALL:
				case SSL_ERROR_SSL:
					BIO_printf (bio_s_out, "ERROR\n");
					ERR_print_errors (bio_err);
					ret = 1;
					goto WRITEDONE;
				case SSL_ERROR_ZERO_RETURN:
					BIO_printf (bio_s_out, "\nDONE\n");
					ret = 1;
					goto WRITEDONE;
			}
		}
	}
WRITEDONE:
#ifdef DEBUG
	BIO_printf (bio_s_out, "shutting down SSL\n");
	print_stats (bio_s_out, ctx);
#endif
#if 1
	SSL_set_shutdown (con, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
#else
	SSL_shutdown(con);
#endif
shut:
	if (con != NULL) SSL_free (con);
	if (2 != ret)
		BIO_printf(bio_s_out,"CONNECTION CLOSED\n");

	if (buf != NULL)
	{
		OPENSSL_cleanse (buf, bufsize);
		OPENSSL_free (buf);
	}

	if ((ret >= 0) && (2 != ret))
		BIO_printf (bio_s_out, "ACCEPT\n");
	return(ret);
}

static int init_ssl_connection(SSL *con)
{
	int i;
#ifdef DEBUG
	const char *str;
	X509 *peer;
	static char buf[BUFSIZ];
#endif
	long verify_error;
	int err = 0;

	if ((i = SSL_accept(con)) <= 0)
	{
		err = SSL_get_error (con, i);
		if ((SSL_ERROR_WANT_READ == err) || (SSL_ERROR_WANT_WRITE == err))
			fprintf (stderr, "%s: %s(): Error [SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE]\n", \
				__FILE__, __func__);

		if (BIO_sock_should_retry (i))
		{
			BIO_printf(bio_s_out, "DELAY\n");
			return 1;
		}

		
		BIO_printf(bio_err, "ERROR\n");
		verify_error = SSL_get_verify_result (con);
		if (verify_error != X509_V_OK)
		{
			BIO_printf(bio_err,"verify error:%s\n",
				X509_verify_cert_error_string(verify_error));
		}
		else
		{
			fprintf (stderr, "%s: %s(): X509_V_OK but error\n", __FILE__, __func__);
			ERR_print_errors (bio_err);
		}
		return 0;
	}

#ifdef DEBUG
	PEM_write_bio_SSL_SESSION (bio_s_out, SSL_get_session (con));

	peer = SSL_get_peer_certificate (con);
	if (NULL != peer)
	{
		BIO_printf (bio_s_out, "Client certificate\n");
		PEM_write_bio_X509 (bio_s_out, peer);
		X509_NAME_oneline (X509_get_subject_name (peer), buf, sizeof buf);
		BIO_printf (bio_s_out, "subject = %s\n", buf);
		X509_NAME_oneline (X509_get_issuer_name (peer), buf, sizeof buf);
		BIO_printf (bio_s_out, "issuer = %s\n", buf);
		X509_free(peer);
	}

	if (SSL_get_shared_ciphers (con, buf, sizeof buf) != NULL)
		BIO_printf (bio_s_out, "Shared ciphers: %s\n", buf);
	str = SSL_CIPHER_get_name (SSL_get_current_cipher (con));
	BIO_printf (bio_s_out, "CIPHER is %s\n", (str != NULL) ? str : "(NONE)");
#endif
	if (con->hit) BIO_printf (bio_s_out, "Reused session-id\n");
	if (SSL_ctrl (con, SSL_CTRL_GET_FLAGS, 0, NULL) & TLS1_FLAGS_TLS_PADDING_BUG)
		BIO_printf (bio_s_out, "Peer has incorrect TLSv1 block padding\n");

	return 1;
}

SSL_CTX *dtls_setup_ssl_server (void)
{
	SSL_METHOD *meth = NULL;
	SSL_CTX *ctx = NULL;
	int s_server_verify = SSL_VERIFY_CLIENT_ONCE; //SSL_VERIFY_NONE;

	if (!dtls_bio_err)
	{
		SSL_library_init ();
		ERR_clear_error ();
		SSL_load_error_strings ();
		OpenSSL_add_all_algorithms ();

		dtls_bio_err = BIO_new_fp (stderr, BIO_NOCLOSE);
	}

	meth = DTLSv1_server_method ();	// Support DTLS v1 server - Datagram TLS - requires openSSL > v0.9.8
	ctx = SSL_CTX_new (meth);	// New SSL CTX object as Framework to establish new SSL connections
	
	if (NULL == ctx)
	{
		dtls_report_berr ("%s: %s(): ERROR: SSL_ctx_new - DTLSv1_server_method\n", __FILE__, __func__);
	}
	
	SSL_CTX_set_quiet_shutdown (ctx, 1);
	if (!SSL_CTX_use_certificate_chain_file (ctx, DTLS_CERT))
	{
		dtls_destroy_ctx (ctx);
		dtls_report_berr ("Error loading the file \"%s\" - %s\n", DTLS_CERT, strerror (errno));
	}

//	SSL_CTX_set_default_passwd_cb (ctx, dtls_password_cb);

	if (!SSL_CTX_use_PrivateKey_file (ctx, DTLS_KEY_CERT, SSL_FILETYPE_PEM))
	{
		dtls_destroy_ctx (ctx);
		dtls_report_berr ("Error loading the private key from the file \"%s\" - %s\n", DTLS_KEY_CERT, strerror (errno));
	}

	if (!SSL_CTX_check_private_key (ctx))
	{
		dtls_destroy_ctx (ctx);
		dtls_report_berr ("%s: %s(): Private key does not match the certificate\n", __FILE__, __func__);
	}

	if (!SSL_CTX_load_verify_locations (ctx, DTLS_CA_CERT, 0))
	{
		dtls_destroy_ctx (ctx);
		dtls_report_berr ("Error loading the CA file - %s\n", strerror (errno));
	}

	dtls_generate_rsa_key (ctx);
	
//	SSL_CTX_set_verify_depth (ctx, 2);
	SSL_CTX_set_verify(ctx, s_server_verify, dtls_verify_callback);
	SSL_CTX_set_options (ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
	SSL_CTX_set_session_id_context (ctx, "dtls-example", strlen ("dtls-example"));
#ifdef DEBUG	
	SSL_CTX_set_info_callback (ctx, dtls_info_callback);
#endif
	SSL_CTX_set_read_ahead (ctx, 1);	// Specific for DTLS
	
	return ctx;
}

static int dtls_print_usage (char *prgname)
{
	fprintf (stderr, "%s()\n", __func__);
	fprintf (stderr, "Usage: %s -p <port_to_bind> <options>\n", prgname);
	fprintf (stderr, "\n \t -p <port no> - Without any options to run the server. But it requires server "
		"certificates. Generate server certificates first using -s option and then run the server\n");
	fprintf (stderr, "Options:\n \t -s - To generate server certificates\n");
	fprintf (stderr, "Options:\n \t -c <client_name> - To generate client certificates\n");
	return 0;
}

static int dtls_build_server_cert (void)
{
	char GEN[BUFSIZ + 1] = {0};
	char cwd [256] = {0};
	FILE *FP = NULL;
	struct stat sbuf;
	fprintf (stderr, "%s(): Call received \n\n", __func__);
	fprintf (stderr, "%s(): Cleaning up old server certs...\n", __func__);
	/* No issues in unlinking files, though not present */ 
	unlink (DTLS_CA_CERT);
	unlink (DTLS_CA_KEY);
	unlink (DTLS_CSR);
	unlink (DTLS_KEY_CERT);
	unlink (DTLS_CERT);
	unlink (DTLS_DH_FILE);
	unlink ("serial");
	unlink ("index.txt");
	snprintf (GEN, BUFSIZ, "openssl req -nodes -x509 -days 365 -newkey rsa:512 -keyout %s -out %s -config "
		"openssl.cnf", DTLS_CA_KEY, DTLS_CA_CERT);
	system (GEN);
	if ((0 != stat (DTLS_CA_KEY, &sbuf)) || (0 != stat (DTLS_CA_CERT, &sbuf)))
	{
		fprintf (stderr, "%s(): Oops! Failed to build CA cert successfully...\n", __func__);
		return 1;
	}
	
	memset (GEN, 0, sizeof (GEN));
	snprintf (GEN, BUFSIZ, "openssl req -nodes -new -newkey rsa:512 -config tempsrv.cnf -keyout %s -out %s", \
		DTLS_KEY_CERT, DTLS_CSR);
	system (GEN);
	
	if ((0 != stat (DTLS_KEY_CERT, &sbuf)) || (0 != stat (DTLS_CSR, &sbuf)))
	{
		fprintf (stderr, "%s(): Oops! Failed to build server key...\n", __func__);
		return 1;
	}
	
	if (0 != stat ("index.txt", &sbuf))
	{
		FP = fopen ("index.txt", "w");
		fclose (FP);
	}

	if (0 != stat ("serial", &sbuf))
	{
		FP = fopen ("serial", "w");
		fprintf (FP, "01\n");
		fclose (FP);
	}
	memset (GEN, 0, sizeof (GEN));
	snprintf (GEN, BUFSIZ, "openssl ca -batch -config openssl.cnf -days 365 -in %s -out %s", DTLS_CSR, DTLS_CERT);
	system (GEN);
	
	if (0 != stat (DTLS_CERT, &sbuf))
	{
		fprintf (stderr, "%s(): Oops! Failed to build server cert...\n", __func__);
		return 1;
	}

	snprintf (GEN, BUFSIZ, "openssl dhparam -out %s 512", DTLS_DH_FILE);
	system (GEN);
	if (0 != stat (DTLS_DH_FILE, &sbuf))
	{
		fprintf (stderr, "%s(): Oops! Failed to generate DH key...\n", __func__);
		return 1;
	}
	getcwd (cwd, 256);
	fprintf (stderr, "\n*******************************************************************************************\n");
	fprintf (stderr, "\n\n%s(): Server certs, keys, and dh are successfully generated and "
		"are at: %s\n\n", __func__, cwd);
	fprintf (stderr, "\n*******************************************************************************************\n");
	fprintf (stderr, "Your server CA cert\t: %s\n", DTLS_CA_CERT);
	fprintf (stderr, "Your server KEY\t\t: %s\n",DTLS_KEY_CERT);
	fprintf (stderr, "Your server CERT\t: %s\n", DTLS_CERT);
	fprintf (stderr, "Your server DH file\t: %s\n", DTLS_DH_FILE);
	fprintf (stderr, "\n*******************************************************************************************\n");
	
	
	return 0;
}

static int dtls_build_client_cert (void)
{
	struct stat sbuf;
	char GEN [BUFSIZ + 1];
	char cwd [256] = {0};
	DIR *FD = NULL;

	unlink (DTLSC_CERT);
	unlink (DTLSC_KEY_CERT);
	unlink (DTLSC_CSR);

	if (NULL == (FD = opendir ("client")))
	{
		if (0 != mkdir ("client", S_IRWXU))
                {
			fprintf (stderr, "%s(): Unable to create/open client directory: client", __func__);
			return 1;           
		}
	}
	else
		closedir (FD);	

	if (0 != stat (DTLS_CERT, &sbuf))
	{
		if (dtls_build_server_cert ())
			return 1;
	}

	memset (GEN,0, sizeof (GEN));
	snprintf (GEN, BUFSIZ, "openssl req -nodes -new -newkey rsa:512 -config tempcli.cnf -keyout %s -out %s", \
		DTLSC_KEY_CERT, DTLSC_CSR);
	system (GEN);

	if ((0 != stat (DTLSC_KEY_CERT, &sbuf)) || (0 != stat (DTLSC_CSR, &sbuf)))
	{
		fprintf (stderr, "%s(): Oops! Failed to generate client key...\n", __func__);
		return 1;
	}

	memset (GEN, 0, sizeof (GEN));
	snprintf (GEN, BUFSIZ, "openssl ca -batch -config openssl.cnf -days 365 -in %s -out %s", DTLSC_CSR, DTLSC_CERT);
	system (GEN);

	if (0 != stat (DTLSC_CERT, &sbuf))
	{	
		fprintf (stderr, "%s(): Oops! Failed to generate client cert...\n", __func__);
		return 1;
	}

	unlink (DTLSC_CSR);
	system ("cp -f dtlsCA.pem client/");

	getcwd (cwd, 256);
	fprintf (stderr, "\n*******************************************************************************************\n");
	fprintf (stderr, "\n\n%s(): Client certs, keys are successfully generated and "
		"are at: %s/client/\n\n", __func__, cwd);
	fprintf (stderr, "\n*******************************************************************************************\n");
	fprintf (stderr, "Your client KEY\t\t: %s\n",DTLSC_KEY_CERT);
	fprintf (stderr, "Your client CERT\t: %s\n", DTLSC_CERT);
	fprintf (stderr, "Your CA cert\t\t: client/dtlsCA.pem\n");
	fprintf (stderr, "Copy all the all files from the client directory to the dtls_client location\n");
	fprintf (stderr, "\n*******************************************************************************************\n");
	
	
	return 0;
}

int 
main(int argc, char **argv)
{
	SSL_CTX *ctx = NULL;
	int ret = 0;
	int c = 0;
	int server_port = 0;
	extern char *optarg;
	
	int serversock = 0, flags = 0, addr_len;


	while ((c = getopt (argc, argv, "p:sch")) != -1)
	{
		switch (c)
		{
			case 'p':
				if (optarg)
					server_port = atoi (optarg);
				break;
			case 's':
				if (dtls_build_server_cert ())
					return 0;
				break;
			case 'c':
				if (dtls_build_client_cert ())
					return 0;
				break;
			case 'h':
				return dtls_print_usage (argv[0]);
			default:
				return dtls_print_usage (argv[0]);
		}
	}

	if (!server_port)
		return 0;

	log_fp = (FILE *) stderr;
	
	accept_socket = serversock = setup_udpserver(server_port);
	if (serversock <= -1 )
	{
		fprintf(log_fp, "%s: ERR: %s: The server could not be initalised\n", __FILE__, __func__);
		exit (EXIT_FAILURE);
	}
	ctx = dtls_setup_ssl_server ();
	dtls_load_dh_params (ctx, DTLS_DH_FILE);	// DH shud of max size 512 (dnt use 1024)
	/* Setting O_NODELAY option for socket */
	if ((flags = fcntl(serversock, F_GETFL, 0)) != -1)
	{
	   	flags |= O_NDELAY;
		fcntl (serversock, F_SETFL, flags);
	}
	else
	{
		fprintf(log_fp, "%s: ERR: %s: fcntl failed: %s\n", __FILE__, __func__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	addr_len = sizeof (struct sockaddr_in);
	for (;;)
	{
//		printf ("loop\n");
		if ((ret = dtls_get_data (serversock, ctx)) < 0)
		{
			close (serversock);
			return ret;
		}
	}
	
}

static int 
setup_udpserver(int server_port)
{
	int udpsock;
	struct sockaddr_in server_addr;    

	fprintf (stderr, "%s: Got a call....\n", __func__);
	if ((udpsock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) 
	{
		fprintf(log_fp, "%s: ERR: %s: socket creation failed: %s\n", __FILE__, __func__, strerror(errno));
		return -1;
	}

	memset(&(server_addr), 0, sizeof (struct sockaddr_in)); 
	server_addr.sin_family = AF_INET;         
	server_addr.sin_port = htons(server_port);     
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	
	if (bind(udpsock, (struct sockaddr *)&server_addr, sizeof (struct sockaddr)) == -1)
	{
		fprintf(log_fp, "%s: ERR: %s: bind failed: %s\n", __FILE__, __func__, strerror(errno));
		return -1;
	}	
	
	fprintf(log_fp,"%s: INFO: Starting Server On %s:%d\n",__FILE__ ,inet_ntoa(server_addr.sin_addr), server_port);
	
	return udpsock;
}
