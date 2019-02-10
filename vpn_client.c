#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

#define BUFF_SIZE 2000
#define PORT_NUMBER 55555
#define STDIN 0

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client" 

struct sockaddr_in peerAddr;

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n",
                    X509_verify_cert_error_string(err));
    }
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization 
   // This step is no longer needed as of version 1.1.0.
   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   SSL_METHOD *meth;
   SSL_CTX* ctx;
   SSL* ssl;

   meth = (SSL_METHOD *)TLSv1_2_method();
   ctx = SSL_CTX_new(meth);

   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
   if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
  printf("Error setting the verify locations. \n");
  exit(0);
   }
   ssl = SSL_new (ctx);

   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   return ssl;
}


int setupTCPClient(const char* hostname, int port)
{
   struct sockaddr_in server_addr;

   // Get the IP address from hostname
   struct hostent* hp = gethostbyname(hostname);

   // Create a TCP socket
   int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

   // Fill in the destination information (IP, port #, and family)
   memset (&server_addr, '\0', sizeof(server_addr));
   memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
    // server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
   server_addr.sin_port   = htons (port);
   server_addr.sin_family = AF_INET;

   // Connect to the destination
   connect(sockfd, (struct sockaddr*) &server_addr,
           sizeof(server_addr));

   return sockfd;
}

int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);       

   return tunfd;
}


/**** read ---> raw data ---> encrypt data ---> ssl ****/
void tunSelected(int tunfd, SSL* ssl, int sockfd){
    int  len;
    char buff[BUFF_SIZE];

    printf(" >>> Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE - 1);

    // for demo
    printf("  >> Received length: %d\n", len);
    printf("  >> Received raw packet:\n");
    for (int i = 0; i < len;i++){
      printf("0x%x ",buff[i]);
    }
    printf("\n\n");
    // for demo

    for (int i = BUFF_SIZE - 1; i >= 0; i--){
    	if (i != 0){
    		buff[i] = buff[i-1];
    	}
    	else {
    		buff[i] = 1;
    	}
    }
    SSL_write(ssl, buff, len + 1);
}

/**** ssl ---> encrypt data ---> raw data ---> spoof****/
void socketSelected (int tunfd, SSL* ssl, int sockfd){
    int  len;
    char buff[BUFF_SIZE];

    printf(" >>> Got a packet from the socket\n");


    bzero(buff, BUFF_SIZE);
    len = SSL_read(ssl, buff, sizeof(buff) - 1);

    char * vpn_header = buff;
    char * vpn_data = buff + 1;

    // /*for demo
    printf("  >> Received length: %d\n", len);
    printf("  >> vpn_header: %x\n", vpn_header[0]);
    printf("  >> vpn_data:\n");
    for (int i = 0; i < len - 1;i++){
      printf("0x%x ",vpn_data[i]);
    }
    printf("\n");
    // */for demo


    if (vpn_header[0]==1){
    	write(tunfd, vpn_data, len - 1);
    }
    else if (vpn_header[0]==3){
    	printf("  >> Login success\n");
    	printf("  >> IP of tun0 assigned as: 192.168.53.%d\n", vpn_data[0]);
        char str[100];
        sprintf(str, "192.168.53.%d", vpn_data[0]);
        if(fork()==0){
            char * argv[] = {"sudo", "ifconfig", "tun0", str, "up", NULL};
            execvp(argv[0], argv);
            //exit(1);
        }
        sleep(1);
        printf("  >> Set up TUN0:\n  - \"sudo ifconfig tun0 %s/24 up\"\n", str);
        if(fork()==0){
            char * argv[] = {"sudo", "route", "add", "-net", "192.168.60.0/24", "tun0", NULL};
            execvp(argv[0], argv);
            //exit(1);
        }
        sleep(1);
        printf("  >> Routing table set:\n  - \"sudo route add -net 192.168.60.0/24 tun0\"\n");
        if(fork()==0){
            char * argv[] = {"sudo", "route", "add", "-net", "192.168.53.0/24", "tun0", NULL};
            execvp(argv[0], argv);
            //exit(1);
        }
        sleep(1);
        printf("  >> Routing table set:\n  - \"sudo route add -net 192.168.53.0/24 tun0\"\n");
    }
    else if (vpn_header[0]==4){
    	printf("  >> Login fail\n  >> VPN exited.\n");
    	SSL_shutdown(ssl);
    	SSL_free(ssl);
    	close(sockfd);
    	exit(0);
    }

    printf("\n");
}

void sendLoginInfo(char * un, char * pw, SSL* ssl){
	char buff[BUFF_SIZE];
	char * vpn_header = buff;
    char * vpn_un = buff + 1;
    char * vpn_pw = buff + 26;
    vpn_header[0] = 2;
    for (int i = 0; i < 25; i ++){
    	vpn_un[i] = un[i];
    }
    for (int i = 0; i < strlen(pw); i++){
    	vpn_pw[i] = pw[i];
    }
    SSL_write(ssl, buff, 26 + strlen(pw));
}

void STDINSelected(SSL* ssl, int sockfd){
	char buffer[40];
	fgets(buffer, 40, stdin);
	buffer[strlen(buffer)-1] = '\0';
	//printf("Hello and %s\n", buffer);
	if (!strcmp(buffer, "quit")){
		printf("\n  > Trying to %s...\n", buffer);
		char buff[BUFF_SIZE];
		char * vpn_header = buff;
    	char * vpn_data = buff + 1;
    	char foo[7] = "ababab\0";
    	for (int i = 0; i < 7; i++){
    		vpn_data[i] = foo[i];
    	}
    	vpn_header[0] = 5;
    	SSL_write(ssl, buff, 8);

    	sleep(1);
    	SSL_shutdown(ssl);
    	SSL_free(ssl);
    	close(sockfd);
    	exit(1);
	}
	else if (!strcmp(buffer, "teststdin")){
		printf("  > Trying to %s...\n", buffer);
	}
	else {
		printf("  > Undefined command: %s\n", buffer);
	}
}


int main (int argc, char * argv[]) {
    char *hostname = "qi.com";
    int port = 4433;

    //if (argc > 1) hostname = argv[1];
    //if (argc > 2) port = atoi(argv[2]);
    int tunfd, sockfd;
    tunfd  = createTunDevice();

    /*----------------TLS initialization ----------------*/
    SSL *ssl   = setupTLSClient(hostname);
    sockfd = setupTCPClient(hostname, port);
    /*----------------TLS handshake ---------------------*/
    SSL_set_fd(ssl, sockfd);
    int err = SSL_connect(ssl); 
    CHK_SSL(err);
    printf(" >>> SSL connection is successful\n");
    printf (" >>> SSL connection using %s\n", SSL_get_cipher(ssl));

    /*------------ user name and password ---------------*/
    printf(" >>> Enter your username: ");
    char username[25];
	fgets(username, 25, stdin);
	username[strlen(username)-1] = '\0';
	char * password;
	password = getpass(" >>> Enter your password: ");
	//printf("username: %s\npassword: %s\n", username, password);
	sendLoginInfo(username, password, ssl);



    // Enter the main loop
    while (1) {
        fd_set readFDSet;

        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
        FD_SET(tunfd, &readFDSet);
        FD_SET(STDIN, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, ssl, sockfd);
        if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, ssl, sockfd);
        if (FD_ISSET(STDIN, &readFDSet)) STDINSelected(ssl, sockfd);
    } 
}
 
