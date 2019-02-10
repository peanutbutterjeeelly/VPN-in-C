///////////////////////////////////////////////////////////////////////
// vpn_multiple_server_v2.c - server for final project task 6        //
// ver 2.0                                                           //
// Jing Qi CSE644 - Internet security, Spring 2018                   //
///////////////////////////////////////////////////////////////////////
/*
 * Compile:
 *  gcc -o vpn_server vpn_multiple_server_v2.c -lssl -lcrypto -lcrypt
 *
 */
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
#include <shadow.h> 
#include <crypt.h>

#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

struct IP2PipeMapping{
    unsigned int ip;
    unsigned int pipe;
};
struct IP2PipeMapping ipm[200];

int client_count = 0;
int client_num = 0;
int client_ip_suffix = 0;

struct sockaddr_in peerAddr;

int createTunDevice();      // create a Tun Device -> return the file descriptor
int setupTCPServer();       // set up a TCP server
void socketSelected (int tunfd, SSL* ssl, int sock); 
                            // do something when get message from child's SSL connection
int login(char *user, char *passwd);
                            // server child to login, return -1: fail; 1: success.

int main (int argc, char * argv[]){

    int tunfd = createTunDevice();
    
    SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL *ssl;
    int err;
    // Step 0: OpenSSL library initialization 
    // This step is no longer needed as of version 1.1.0.
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    // Step 1: SSL context initialization
    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    // Step 2: Set up the server certificate and private key
    SSL_CTX_use_certificate_file(ctx, "./cert_server/server_crt.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/server_key.pem", SSL_FILETYPE_PEM);
    // Step 3: Create a new SSL structure for a connection
    ssl = SSL_new (ctx);
    int sockfd = setupTCPServer();

    while(1){
        
        fd_set parentFD_set;
        FD_ZERO(&parentFD_set);
        FD_SET(sockfd, &parentFD_set);
        FD_SET(tunfd, &parentFD_set);
        select(FD_SETSIZE, &parentFD_set, NULL, NULL, NULL);

        if(FD_ISSET(tunfd, &parentFD_set)){                             // tun0 gets something, usually from host_v
                                                                        // then pipe to child
            printf(" >>> Parent process:\n");
            printf("  >> Got a package from tun0\n");
            int  len;
            char buff[BUFF_SIZE];
            bzero(buff, BUFF_SIZE);
            len = read(tunfd, buff, BUFF_SIZE - 1);
            printf("  >>   length: %d\n", len);
            printf("  >>   content:\n");
            for (int i = 0; i < len; i++){
                printf("0x%x ", buff[i]);
            }
            printf("\n");

            // pipe to child
            
        }
        if(FD_ISSET(sockfd, &parentFD_set)){                                // sockfd gets something, means a new connection
                                                                        // then create a child
            struct sockaddr_in sa_client;
            size_t client_len;
            int sock = accept(sockfd, (struct sockaddr*)&sa_client, &client_len);   
                                                                        // get connected
            client_count++;
            client_num = client_count - 1;
            client_ip_suffix = client_count % 200 + 5;
            int pipeBetweenChild[2];
            pipe(pipeBetweenChild);
            ipm[client_num].ip = client_ip_suffix;
            ipm[client_num].pipe = pipeBetweenChild[1];

            if(fork()==0){                                              // child process
                close(pipeBetweenChild[1]);

                SSL_set_fd (ssl, sock);
                err = SSL_accept (ssl);
                CHK_SSL(err);
                printf ("SSL connection established!\n");

                while(1){
                    fd_set childFDSet;
                    FD_ZERO(&childFDSet);
                    FD_SET(sock, &childFDSet);
                    FD_SET(pipeBetweenChild[0], &childFDSet);

                    if(FD_ISSET(sock,  &childFDSet)) {
                        socketSelected(tunfd, ssl, sock);
                    }
                    if(FD_ISSET(pipeBetweenChild[0],  &childFDSet)){
                        char readFromPipeBuffer[BUFF_SIZE];
                        bzero(readFromPipeBuffer, BUFF_SIZE);
                        int length = read(pipeBetweenChild[0], readFromPipeBuffer, sizeof(readFromPipeBuffer));
                        
                        // *********** Print out the buffer from pipe ***********
                        printf(" >>> Child Process:\n");
                        printf("  >> Got a package from pipe:\n");
                        printf("  >>   length: %d\n", length);
                        printf("  >>   content:\n");
                        for (int i = 0; i < length; i++){
                            printf("0x%x ", readFromPipeBuffer[i]);
                        }
                        printf("\n\n");
                        // *******************************************************/

                        for (int i = BUFF_SIZE - 1; i >= 0; i--){       // add a header
                            if (i != 0){
                                readFromPipeBuffer[i] = readFromPipeBuffer[i-1];
                            }
                            else {
                                readFromPipeBuffer[i] = 1;              // this is a normal data package
                            }
                        }
                        SSL_write(ssl, readFromPipeBuffer, length + 1);
                    }
                }
            }
            // child process end

            else {                                                      // parent process
                close(pipeBetweenChild[0]);
                //SSL_shutdown(ssl);  
                //SSL_free(ssl);
                //close(sockfd);
                //close(sock);
            }
            // parent process end

        }
    }
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

int setupTCPServer(){
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (4433);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

void socketSelected (int tunfd, SSL* ssl, int sock){
    int len;
    char buff[BUFF_SIZE];
    bzero(buff, BUFF_SIZE);
    len = SSL_read(ssl, buff, sizeof(buff) - 1);
    char * vpn_header = buff;
    char * vpn_data = buff + 1;

    printf(" >>> Child process:\n");
    printf("  >> Got a packet from SSL\n");
    printf("  >>   length: %d\n", len);
    printf("  >>   vpn_header: %x\n", vpn_header[0]);
    printf("  >>   content:\n");
    for (int i = 0; i < len - 1; i++){
        printf("0x%x ", vpn_data[i]);
    }
    printf("\n");
    if (vpn_header[0] ==0){                                             // NULL package, usually error
        printf(" >>> Error.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        printf(" >>> This child process's connection is terminated.\n");
    }
    else if (vpn_header[0] ==1){                                            // normal data package
        printf(" >>> This package is normal data.\n");
        write(tunfd, vpn_data, len - 1);
        printf(" >>> Data send out.\n");
    }
    else if (vpn_header[0] ==2){                                            // login request
        printf(" >>> This package is login request.\n");
        char * vpn_un = buff + 1;
        char * vpn_pw = buff + 26;
        char login_resp_buff[BUFF_SIZE];
        char * login_resp_buff_header = login_resp_buff;
        char * login_resp_buff_data = login_resp_buff + 1;
        //printf("username: %s\npassword: %s\n", vpn_un, vpn_pw);
        int result = login(vpn_un, vpn_pw);
        printf("  >> username: %s\n  >> password: %s\n  >> result: %d\n", vpn_un, vpn_pw, result);
        if (result == 1){
            login_resp_buff_header[0] = 3;
            login_resp_buff_data[0] = (char) client_ip_suffix;
            SSL_write(ssl, login_resp_buff, 2);
            printf(" >>> Login-Success responding package is sent.\n");
        }
        else{
            login_resp_buff_header[0] = 4;
            SSL_write(ssl, login_resp_buff, 1 + strlen(login_resp_buff_data));
            SSL_shutdown(ssl);  
            SSL_free(ssl);
            close(sock);
            printf(" >>> Login-Fail responding package is sent.\n");
            printf(" >>> This child process's connection is terminated.\n");
        }
    }
    else if (vpn_header[0] == 5){
        printf(" >>> Client are closing...\n");
        SSL_shutdown(ssl);  
        SSL_free(ssl);
        close(sock);
        printf(" >>> This child process's connection is terminated.\n");
    }
}

int login(char *user, char *passwd) { 
    struct spwd *pw; 
    char *epasswd;
    pw = getspnam(user); 
    if (pw == NULL) { return -1; }
    epasswd = crypt(passwd, pw->sp_pwdp); 
    if (strcmp(epasswd, pw->sp_pwdp)) { return -1; }
    return 1;
}