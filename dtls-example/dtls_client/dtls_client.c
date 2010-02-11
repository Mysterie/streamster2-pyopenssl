/* File : dtls_client.c */
/*
*/
/******************************** dtls_client.c********************************/
/*                                                                            */
/* Abstract:                                                                  */
/* This file contains APIs for setting up DTLSv1 client                       */
/*                                                                            */
/******************************************************************************/
/* Other copyright info                                                       */
/* Most parts of the DTLSv1 client implementation are taken from OpenSSLv0.9.8*/
/* source file apps/s_client.c - DTLS implementation written by Nagendra      */
/* Modadugu (nagendra@cs.stanford.edu) for the OpenSSL project 2005.          */
/******************************************************************************/
/*                                                                            */
/* Initial File Information:                                                  */
/*                                                                            */
/* Initial Filename: dtls_client.c                                            */
/* Filetype: C/Source                                                         */
/* Author: Arun S.                                                            */
/* e-mail: hi2arun [at] gmail [dot] com                                       */
/******************************************************************************/
/******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <assert.h>

#import "sslmgr.h"

#define SIZ_SERIAL_NO   10
#define PIDFILE "dtls_client.pid"
#define PASSWORD "dtls-example"
#define DTLSC_CERT "dtlsc.pem"
#define DTLSC_KEY_CERT "dtlsc.key"
#define DTLSC_ROOT_CACERT "dtlsCA.pem"

/* global variables */
int  udpsock;
SSL_CTX *ctx;
SSL *ssl;
BIO *sbio;
extern int errno;
static SSL_CTX *dtls_setup_sslclient (void);
static int dtls_connect (void);
extern void dtls_info_callback (const SSL *ssl, int where, int ret);
static int handle_data(SSL *ssl);
static int creat_pidfile(void);

/* Do exit */
void doexit(int error)
{
	closelog();
	/* No harm calling unlink, if pid file is
	   already unlinked or not created */
	unlink(PIDFILE);
	if (ssl)
		SSL_shutdown (ssl);
	if (ctx)
		dtls_destroy_ctx (ctx);
	if (udpsock > 0)
		close (udpsock);
	exit(error);
}


/* Signal Handling fucntions */
void sig_child(int signo)
{
 	int status;

  	while (waitpid(-1 , &status, WNOHANG ) > 0);

	return;
}


void exit_halt(int signo)
{
	doexit (signo); // Or do something here like sending BYE to server or other clean ups!!!
}

static void setup_sig_handler(int sig, void (*handler)(int))
{
	struct sigaction sa;

	sa.sa_handler = handler;
	sigemptyset(&(sa.sa_mask));
	sigaddset(&(sa.sa_mask), sig);
	sa.sa_flags = 0;
	sigaction(sig, &sa, 0);
	return;
}


int sig_setup()
{
	setup_sig_handler(SIGINT, SIG_IGN);
	setup_sig_handler(SIGHUP, exit_halt );
	setup_sig_handler(SIGTERM, exit_halt);
	return 1;
}


/* Some Socket helper functions */
in_addr_t pgethostbyname(char *server)
{
	struct hostent *he;
  	in_addr_t ip;

  	ip = 0;
  	he = gethostbyname(server);
  	if (he == NULL)
		return -1;
  	ip = *(in_addr_t *)he->h_addr;
  	return ip;
}
static SSL_CTX *dtls_setup_sslclient (void)
{
	SSL_METHOD *meth = NULL;
	SSL_CTX *ctx = NULL;
	extern char *pass;

	if (!dtls_bio_err)
	{
		SSL_library_init ();
		ERR_clear_error ();
		SSL_load_error_strings ();
		OpenSSL_add_all_algorithms ();

		dtls_bio_err = BIO_new_fp (stderr, BIO_NOCLOSE);
	}

	meth = DTLSv1_client_method (); // Datagam TLS v1 client - requires openSSL > v0.9.8
	ctx = SSL_CTX_new (meth);	// New SSL CTX object as Framework to establish new SSL connections

	if (!SSL_CTX_use_certificate_chain_file (ctx, DTLSC_CERT))
	{
		dtls_destroy_ctx (ctx);
		dtls_report_berr ("Error loading the file \"%s\" - %s\n", DTLSC_CERT, strerror (errno));
	}

	pass = PASSWORD;

	/* Enable this if u hve generated your certificates with password. If certs are generated with '-nodes' option, this 			is not required */

//	SSL_CTX_set_default_passwd_cb (ctx, dtls_password_cb);

//	fprintf (stderr, "%s: %s(): Am now here @ %d\n", __FILE__, __func__, __LINE__);
	if (!SSL_CTX_use_PrivateKey_file (ctx, DTLSC_KEY_CERT, SSL_FILETYPE_PEM))
	{
		dtls_destroy_ctx (ctx);
		dtls_report_berr ("Error loading the private key from the file \"%s\" - %s\n", DTLSC_KEY_CERT, \
			strerror (errno));
	}
	
	if (!SSL_CTX_load_verify_locations (ctx, DTLSC_ROOT_CACERT, 0))
	{
		dtls_destroy_ctx (ctx);
		dtls_report_berr ("Error loading the CA file - %s\n", strerror (errno));
	}

	SSL_CTX_set_verify_depth (ctx, 2);
	SSL_CTX_set_options (ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);

#ifdef DEBUG
	SSL_CTX_set_info_callback (ctx, &dtls_info_callback);
#endif
	SSL_CTX_set_read_ahead (ctx, 1); // Required for DTLS - please refer apps/s_client.c source file
	
	return ctx;
}

void
init_daemon()
{
	int status;

	status = fork();
	switch (status)
	{
		case -1:
			syslog(LOG_ERR, "Fork failed exiting...");
			doexit(errno);
		case 0:
			/* Child */
			break;
		default:
			/* Parent */
			exit(EXIT_SUCCESS);
	}

	close(0);
	close(1);
	close(2);
	status = setsid();
	if (status == -1)
	{
		syslog(LOG_ERR, "setsid failed. Client exiting...");
		doexit(errno);
	}
	return;
}

static int dtls_connect (void)
{
	struct timeval timeout;
	fd_set wfd;
	int width = 0;
	struct sockaddr peer;
	int peerlen = sizeof (struct sockaddr);

	ssl = SSL_new (ctx);
//	if (DTLS1_VERSION == SSL_version (ssl))
//		fprintf (stderr, "%s: %s(): Yes: DTLS1_VERSION CLIENT\n", __FILE__, __func__);
	sbio = BIO_new_dgram (udpsock, BIO_NOCLOSE);
	if (getsockname (udpsock, &peer, (socklen_t *)&peerlen) < 0)
	{
		dtls_report_err ("%s: %s(): getsockname FAILED: %s\n", __FILE__, __func__, strerror (errno));
		shutdown (udpsock, SHUT_RDWR);
		return -1;
	}
	BIO_ctrl_set_connected (sbio, 1, &peer);
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;
	BIO_ctrl (sbio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);
	BIO_ctrl(sbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);
	SSL_set_bio (ssl, sbio, sbio);
	SSL_set_connect_state (ssl);
//	fprintf (stderr, "%s: %s(): Am now here @ %d\n", __FILE__, __func__, __LINE__);
	width = SSL_get_fd (ssl) + 1;
	FD_ZERO (&wfd);
	FD_SET (SSL_get_fd (ssl), &wfd);
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;
	if (select (width, NULL, &wfd, NULL, &timeout) < 0)
	{
		return 1;
	}
	return 0;
}	

int main(int argc, char **argv)
{
	int status = 0;
	struct sockaddr_in servaddr;
	int ret = 0;
	int server_port = 0;

	if (argc < 3)
	{
		fprintf (stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
		assert (argc == 3);
	}

//	init_daemon(); // Enable this, to Daemonize the client
	server_port = atoi (argv[2]);

	if((status = creat_pidfile()) != 1)
	{
		syslog(LOG_ERR, "PID file could not be created...exiting");
		doexit(EXIT_FAILURE);
	}

	sig_setup();

	udpsock = socket(PF_INET, SOCK_DGRAM, 0);
	if (udpsock == -1)
	{
		syslog(LOG_ERR, "%s(): %s @ %d", __func__, strerror (errno), __LINE__);
		doexit(EXIT_FAILURE);
	}
#if 1
	memset((void *)&servaddr,'\0',sizeof(struct sockaddr_in));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(server_port);
	if ((servaddr.sin_addr.s_addr = pgethostbyname(argv[1])) < 0)
	{
		close(udpsock);
		syslog(LOG_ERR, "%s(): %s @ %d", __func__, strerror (errno), __LINE__);
		doexit(EXIT_FAILURE);
	}

	status = connect(udpsock, (struct sockaddr *) &servaddr ,sizeof(struct sockaddr_in));
	if(status == -1)
	{
		syslog(LOG_ERR, "%s(): %s @ %d", __func__, strerror (errno), __LINE__);
		doexit(EXIT_FAILURE);
	}
	else
#endif
	{
		ctx = dtls_setup_sslclient();
REDO:
	//	fprintf (stderr, "%s: %s(): Am here @ %d\n", __FILE__, __func__, __LINE__);
		ret = dtls_connect ();
		if (-1 == ret)
			goto END;
		else if (1 == ret)
			goto REDO;
		status = handle_data(ssl);
		if (status == -1)
		{
			syslog(LOG_ERR, "Unable to send beat : send failed[%s]...exiting", strerror(errno));
			doexit(EXIT_FAILURE);
		}

		SSL_shutdown (ssl);
	}
END:
	if (NULL != ssl)
		SSL_free (ssl);
	
	if (udpsock > 0)
		close(udpsock);
	closelog();

	return 0;
}

static int handle_data(SSL *ssl)
{
	int retval;
	char sendbuf[1024] = {0};

//	fprintf (stderr, "%s(): received a call...\n", __func__);
	strncpy (sendbuf, "MSG from CLIENT: Hello Server!\n", sizeof (sendbuf));

	while (1)
	{
		retval = SSL_write (ssl, sendbuf, sizeof (sendbuf));
//		fprintf (stderr, "%s: %s(): count: %d\n", __FILE__, __func__, retval);
		switch (SSL_get_error (ssl, retval))
		{
			case SSL_ERROR_NONE:
				if (retval == sizeof (sendbuf))
				{
					fprintf (stderr, "%s(): Am done with my write\n", __func__);
					goto WRITEDONE;
				}
				break;
			case SSL_ERROR_WANT_READ:
				fprintf (stderr, "%s: %s(): Want read - am now @ %d\n", __FILE__, __func__, __LINE__);
				break;
			case SSL_ERROR_WANT_X509_LOOKUP:
			case SSL_ERROR_WANT_WRITE:
				fprintf (stderr, "%s: %s(): Want write - am now @ %d\n", __FILE__, __func__, __LINE__);
				break;
			case SSL_ERROR_ZERO_RETURN:
				goto WRITEDONE;
			case SSL_ERROR_SSL:
			case SSL_ERROR_SYSCALL:
				dtls_report_err ("%s: %s(): Data send failed.\n", __FILE__, __func__);
				return -1;
		}
	}

WRITEDONE:
	memset (sendbuf, 0, sizeof (sendbuf));
	for (;;)
	{
		retval = SSL_read (ssl, sendbuf, sizeof (sendbuf));
		switch (SSL_get_error (ssl, retval))
		{
			case SSL_ERROR_NONE:
				write (fileno (stderr), sendbuf, (unsigned int )retval);
				if (SSL_pending (ssl))
				{
					fprintf (stderr, "%s(): Some more stuff yet to come... letz wait for "\
						"that..\n", __func__);
					break;
				}
				else
				{
					fprintf (stderr, "%s(): mmm ... no more to come... letz finish it "\
						"off...\n", __func__);
					return 0;
				}
			case SSL_ERROR_WANT_WRITE:
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_X509_LOOKUP:
				fprintf (stderr, "%s: %s(): Read BLOCK - am now @ %d\n", __FILE__, __func__, __LINE__);
				break;
			case SSL_ERROR_SYSCALL:
			case SSL_ERROR_SSL:
				dtls_report_err ("%s: %s(): Data READ failed - am now @ %d\n", __FILE__, __func__, \
					__LINE__);
				return -1;
			case SSL_ERROR_ZERO_RETURN:
				fprintf (stderr, "%s: %s(): Am DONE\n", __FILE__, __func__);
				return 0;
		}
	}
       	 
	return 0;
}

static int creat_pidfile(void)
{
	FILE *pidfile = NULL;

	pidfile = fopen(PIDFILE, "w");
	if (! pidfile)
		return -1;
	
	fprintf(pidfile, "%d\n", getpid());
	fclose(pidfile);
	
	return 1;
}
