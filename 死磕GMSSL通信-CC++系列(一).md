#### 死磕GMSSL通信-C/C++系列（一）

GMSSL系列：

[死磕GMSSL通信-C/C++系列（一）](./死磕GMSSL通信-CC++系列(一).md)

[死磕GMSSL通信-java/Netty系列（二）](./死磕GMSSL通信-javaNetty系列(二).md)

[死磕GMSSL通信-java/Netty系列（三）](./死磕GMSSL通信-javaNetty系列(三).md)

最近再做国密通信的项目开发，以为国密也就简单的集成一个库就可以完事了，没想到能有这么多坑。遂写下文章，避免重复踩坑。以下国密通信的坑有以下场景

1、使用GMSSL guanzhi/GmSSL进行通信

[https://github.com/guanzhi/GmSSL]: 最新版本，好像只有国密算法，没有openssl
[https://github.com/guanzhi/GmSSL/tree/GmSSL-v2]: v2版本，有openssl

2、使用加密套件SM2-WITH-SMS4-SM3

**使用心得**

​       GmSSL这个库的问题很多，发现许多库和它都不能正常通信，都需要修改代码，不是修改客户端就是修改服务端，而且这个开源项目基本处于不维护的状态，如果准备集成的GM通信的，优先选择**铜锁/Tongsuo** 这个项目，毕竟背后是商业公司在维护。

1、经过最近几天的测试，发现

window编译

网上有好多编译教程，我这里也不细说了，大概步骤如下

安装Perl软件：从Perl官网(https://www.activestate.com/products/perl/downloads/)下载安装包直接安装就行了。安装完好后命令行执行【perl -v】就可以查看版本信息

以64位为列，打开“ VS2015 x64 本机工具命令提示符”



![image-20240412170837915](https://s2.loli.net/2024/04/12/3Vf7CQMSxbegOHz.png)

执行：perl Configure VC-WIN64A no-asm no-shared

![image-20240412171021233](https://s2.loli.net/2024/04/12/79DEwikIBbWSaQV.png)

- VC-WIN32 表示编译选项生成32位的库
- VC-WIN64A 表示编译选项生成64位的库
- VC-WIN64I 表示编译选项生成IA64的库,使用安腾cpu的需要使用此选项，安腾x64架构是inter自家的，比较少见
- no-asm 表示不使用汇编,如果本地安装了nasm工具，可以不使用此选项
- --prefix=D:xxx\xx 表示输出目录

执行nmake

![image-20240412171044150](https://s2.loli.net/2024/04/12/4GhY76DPCNzKgVE.png)

最后程序根目录生成俩个静态库 libcrypto.lib、libssl.lib

###### 生成证书

这里就不提供证书生成的过程了，网上生成的教程很多，GMSSL需要五个证书

1. CA.cert.pem

2. SE.cert.pem

3. SE.key.pem

4. SS.cert.pem

5. SS.key.pem

   > [注意]
   >
   > 理论上客户端和服务端的证书应该是俩套，也可以直接客户端和服务器用一样的证书，我这里直接用了一套，大家可以自行测试俩套的

   #### 

GMSSL双向通信

**server端代码**

#### 

```c
/*
 * Copyright 1998-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

 /*-
  * A minimal program to serve an SSL connection.
  * It uses blocking.
  * saccept host:port
  * host is the interface IP to use.  If any interface, use *:port
  * The default it *:4433
  *
  * cc -I../../include saccept.c -L../.. -lssl -lcrypto -ldl
  */

#include <stdio.h>
#include <signal.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define CA_CERT_FILE            "CA.cert.pem"
#define SIGN_CERT_FILE          "SS.cert.pem"
#define SIGN_KEY_FILE           "SS.key.pem"
#define ENCODE_CERT_FILE        "SE.cert.pem"
#define ENCODE_KEY_FILE         "SE.key.pem"

static int done = 0;

void interrupt(int sig)
{
    done = 1;
}

int main(int argc, char* argv[])
{
    char* port = "0.0.0.0:9999";
    BIO* in = NULL;
    BIO* ssl_bio, * tmp;
    SSL_CTX* ctx;
    char buf[512];
    int ret = 1, i;

 
    ctx = SSL_CTX_new(GMTLS_server_method());
 
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
#if 1
    if (!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL))
    {
        goto err;
    }
 
    if (!SSL_CTX_use_certificate_file(ctx, SIGN_CERT_FILE, SSL_FILETYPE_PEM))
        goto err;
    if (!SSL_CTX_use_PrivateKey_file(ctx, SIGN_KEY_FILE, SSL_FILETYPE_PEM))
        goto err;
    if (!SSL_CTX_use_certificate_file(ctx, ENCODE_CERT_FILE, SSL_FILETYPE_PEM))
        goto err;
    if (!SSL_CTX_use_PrivateKey_file(ctx, ENCODE_KEY_FILE, SSL_FILETYPE_PEM))
        goto err;
    if (!SSL_CTX_check_private_key(ctx))
        goto err;
#endif//

    /* Setup server side SSL bio */
    ssl_bio = BIO_new_ssl(ctx, 0);

    if ((in = BIO_new_accept(port)) == NULL)
        goto err;

    /*
     * This means that when a new connection is accepted on 'in', The ssl_bio
     * will be 'duplicated' and have the new socket BIO push into it.
     * Basically it means the SSL BIO will be automatically setup
     */
    BIO_set_accept_bios(in, ssl_bio);

    /* Arrange to leave server loop on interrupt */
    //sigsetup();

again:
    /*
     * The first call will setup the accept socket, and the second will get a
     * socket.  In this loop, the first actual accept will occur in the
     * BIO_read() function.
     */

    if (BIO_do_accept(in) <= 0)
        goto err;

    while (!done) {
        i = BIO_read(in, buf, 512);
        if (i == 0) {
            /*
             * If we have finished, remove the underlying BIO stack so the
             * next time we call any function for this BIO, it will attempt
             * to do an accept
             */
            printf("Done\n");
            tmp = BIO_pop(in);
            BIO_free_all(tmp);
            goto again;
        }
        if (i < 0)
            goto err;
        fwrite(buf, 1, i, stdout);
        fflush(stdout);
    }

    ret = 0;
err:
    if (ret) {
        ERR_print_errors_fp(stderr);
    }
    BIO_free(in);
    exit(ret);
    return (!ret);
}
```



**client段代码**

```c
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#if  1
#pragma comment(lib,"ws2_32.lib")

#include <memory.h>
#include <errno.h>
#include <WS2tcpip.h> 
#include <winsock2.h>
#include <windows.h>

#else

#include <netdb.h>
#include <unistd.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#endif //  1


#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include "openssl/ssl.h"
#include "openssl/x509v3.h"

#define MAX_BUF_LEN 4096
//#define CLIENT_S_CERT   "./cert/CS.pem"
//#define CLIENT_E_CERT   "./cert/CE.pem"
//#define CLIENT_CA_CERT  "./cert/CA.pem"

//#define CLIENT_S_CERT   "SS.cert.pem"
//#define CLIENT_E_CERT   "SE.cert.pem"
//#define CLIENT_CA_CERT  "CA.cert.pem"

#define CA_CERT_FILE            "CA.cert.pem"
#define SIGN_CERT_FILE          "SS.cert.pem"
#define SIGN_KEY_FILE           "SS.key.pem"
#define ENCODE_CERT_FILE        "SE.cert.pem"
#define ENCODE_KEY_FILE         "SE.key.pem"

#define SSL_ERROR_WANT_HSM_RESULT 10


void Init_OpenSSL()
{
    if (!SSL_library_init())
        exit(0);
    SSL_load_error_strings();
}
 
int main(int argc, char** argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    BIO* conn = NULL;
    SSL* ssl = NULL;
    SSL_CTX* ctx = NULL;
    int usecert = 1;
    int retval;
    int aio_tag = 0;
    char sendbuf[MAX_BUF_LEN];
    int i = 0;
    const SSL_METHOD* meth;
 

    Init_OpenSSL();


    meth = GMTLS_client_method();
    ctx = SSL_CTX_new(meth);
    if (ctx == NULL)
    {
        printf("Error of Create SSL CTX!\n");
        goto err;
    }


#if 1
    if (!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL))
    {
        goto err;
    }
    //if (!SSL_CTX_use_certificate_chain_file(ctx, CERT_FILE))
    if (!SSL_CTX_use_certificate_file(ctx, SIGN_CERT_FILE, SSL_FILETYPE_PEM))
        goto err;
    if (!SSL_CTX_use_PrivateKey_file(ctx, SIGN_KEY_FILE, SSL_FILETYPE_PEM))
        goto err;
    if (!SSL_CTX_use_certificate_file(ctx, ENCODE_CERT_FILE, SSL_FILETYPE_PEM))
        goto err;
    if (!SSL_CTX_use_PrivateKey_file(ctx, ENCODE_KEY_FILE, SSL_FILETYPE_PEM))
        goto err;
    if (!SSL_CTX_check_private_key(ctx))
        goto err;
#endif//
    SSL_CTX_set_cipher_list(ctx, "SM2-WITH-SMS4-SM3");
    /*Now Connect host:port*/
    conn = BIO_new_connect("127.0.0.1:9999");
    if (!conn)
    {
        printf("Error Of Create Connection BIO\n");
        goto err;
    }

    if (BIO_do_connect(conn) <= 0)
    {
        printf("Error Of Connect to %s\n", "127.0.0.1:9999");
        goto err;
    }

    if (!SSL_CTX_set_cipher_list(ctx, "SM2-WITH-SMS4-SM3")) {
        printf("set cipher list fail!\n");
        exit(0);
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        printf("SSL New Error\n");
        goto err;
    }

    SSL_set_bio(ssl, conn, conn);

    /*if (SSL_connect(ssl) <= 0)
    {
        printf("Error Of SSL connect server\n");
        goto err;
    }*/

    SSL_set_connect_state(ssl);
    //SSL_set_sm2_group_id_custom(29);
    while (1)
    {
        retval = SSL_do_handshake(ssl);
        if (retval > 0)
            break;
        else
        {
            if (SSL_get_error(ssl, retval) == SSL_ERROR_WANT_HSM_RESULT)
                continue;
            else
            {
                printf("Error Of SSL do handshake\n");
                goto err;
            }
        }
    }

    for (i = 0; i < MAX_BUF_LEN; i++) {

        sprintf(sendbuf + i, "%d", i % 10);
    }

    while (1) {

        if (SSL_write(ssl, "hello i am from client ", strlen("hello i am from client ")) <= 0)
        {
            printf("ssl_write fail!\n");
            break;
        }
        break;
    }
    {
        char rbuf[2048];

        memset(rbuf, 0x0, sizeof(rbuf));
        if (SSL_read(ssl, rbuf, 2048) > 0)
            printf("SSL recv: %s.\n", rbuf);
        else
            printf("None recv buf.\n");

        SSL_shutdown(ssl);
    }

err:
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);

    return 0;
}
```



Wireshark 抓包，有如下消息交互，证明成功

![image-20240412174428294](https://s2.loli.net/2024/04/12/Gf6U2COb8DWapud.png)



###### 参考博客

[新手入坑GMSSL（一）Windows下编译GMSSL并生成CA证书_gmssl证书制作windows-CSDN博客](https://blog.csdn.net/qq_40153886/article/details/106933931)

[GmSSL编程实现gmtls协议C/S通信(BIO版本)_tassl_demo/mk_tls_cert 下的 sm2certgen.sh-CSDN博客](https://blog.csdn.net/xiejianjun417/article/details/99963297)

