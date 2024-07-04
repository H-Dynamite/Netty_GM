#### 死磕GMSSL通信-java/Netty系列（二）

GMSSL系列：

[死磕GMSSL通信-C/C++系列（一）](./死磕GMSSL通信-CC++系列(一).md)

[死磕GMSSL通信-java/Netty系列（二）](./死磕GMSSL通信-javaNetty系列(二).md)

[死磕GMSSL通信-java/Netty系列（三）](./死磕GMSSL通信-javaNetty系列(三).md)

在上一篇文章中，我们探讨了如何利用C/C++实现国密通信。而本文将聚焦于Java环境下，特别是基于Netty框架，如何实现与国密系统的安全通信。为了确保新项目遵循最新的国密标准，我们将优先推荐使用**GB/T 38636-2020（TLCP）协议。对于Java开发者而言，可以选用TencentKonaSMSuite**这一基于Java原生实现的库来支持TLCP/GMSSL、TLS 1.3（含RFC 8998扩展）及TLS 1.2等多种协议，以及SM2、SM3、SM4等国密算法。然而，若项目已依赖于**guanzhi/GmSSL**，因其基于OpenSSL实现，与TencentKona存在兼容性问题，特别是在SM2withSM3算法的验签环节。鉴于网上对此类问题反馈较多，且难以直接解决，若您的项目与此情况相符，以下将重点介绍如何对Netty进行针对性改造，以适应国密通信需求。如果您并非处于此类特定场景，本部分内容可能并不适用。

**一、GM/T与TLCP标准概览**

国密通信目前遵循两大标准：**GM/T 0024-2014（GMSSL）与GB/T 38636-2020（TLCP）**。其中，TLCP作为更新的标准，其规范更加完善，广泛支持SM系列密码算法和数字证书等技术，以保障传输层的机密性、完整性和身份认证。两者的详细差异可参阅[关于 TLCP | gotlcp (trisia.github.io)](https://trisia.github.io/gotlcp/doc/AboutTLCP.html)。对于新项目，建议优先采用TLCP协议以确保合规性和安全性。

**二、TencentKonaSMSuite与原生Java支持**

**TencentKonaSMSuite**是一组全面的Java安全提供商，不仅实现了SM2、SM3、SM4等国密算法，还支持TLCP、GMSSL、TLS 1.3（含RFC 8998扩展）及TLS 1.2等协议。其完全基于Java编写，具备良好的跨平台兼容性，适用于各种运行Java环境的操作系统，包括但不限于Linux、macOS、Windows，以及支持x86_64和aarch64架构的CPU。对于Android平台，由于不依赖任何内部JDK API，TencentKonaSMSuite同样能够顺利运行。

**三、与guanzhi/GmSSL兼容性问题及Netty改造方案**

尽管TencentKonaSMSuite提供了丰富的国密支持，但对于已使用**guanzhi/GmSSL**的项目，由于后者基于OpenSSL实现，两者之间可能存在兼容性问题。尤其是SM2withSM3算法的验签环节，许多用户报告遇到困难，且无有效解决方案。鉴于此，对于已深度依赖guanzhi/GmSSL的项目，选择继续沿用其国密功能并针对Netty进行相应改造，以满足现有系统的通信需求。

**Netty**本身支持原生OpenSSL访问，这为基于guanzhi/GmSSL的国密通信提供了便利。针对此类场景，改造Netty以实现国密通信的主要步骤如下：

1. **配置OpenSSL环境**： 确保项目环境中正确安装并配置了包含国密支持的OpenSSL库。guanzhi/GmSSL通常会提供对应的OpenSSL编译版本，需将其路径添加至系统环境变量或项目配置中，确保Netty能够找到并链接到正确的库文件。

2. **定制Netty SSL引擎**： 利用Netty提供的`SslContextBuilder`及其相关API，创建自定义的SSL上下文，指定使用GmSSL提供的OpenSSL引擎。这通常涉及到设置正确的协议版本、密码套件列表（如SM2-WITH-SMS4-SM3），以及指向GmSSL证书和私钥文件的路径。

3. **适配国密握手流程**： 根据GmSSL的国密握手协议特点，可能需要在Netty的SSL处理逻辑中进行特定调整。例如，处理特定的握手消息、调整密钥协商算法、验证国密证书等。这部分可能需要深入理解GmSSL的握手细节，并结合Netty的事件驱动模型进行代码编写。

4. **测试与调试**： 在完成上述改造后，进行全面的单元测试和集成测试，确保Netty在国密通信场景下的稳定性和安全性。对于可能出现的问题，如握手失败、加密解密异常等，应利用Netty提供的日志输出、调试工具等进行细致排查。

   

 **四、关于 SM2-WITH-SMS4-SM3加密套件** 

GMSSL guanzhi/GmSSL 加密套件SM2-WITH-SMS4-SM3其实属于GM/T SSL-VPN CipherSuites 套件，从源码就可以看到

![image-20240415193421784](https://s2.loli.net/2024/04/16/7aHBhJ3oGf1RcKg.png)

**五、编译**

参考连接[Netty集成国密开源基础密码库Tongsuo_netty 集成国密ssl-CSDN博客](https://blog.csdn.net/x1075339587/article/details/130513163)

其实这个博客写的已经把大概流程都写好了，但是是基于tongsuo的，我这边是基于guanzhi/GmSSL，


​    Netty调用Netty-tcnative组件，Netty-tcnative调用集成Openssl算法库的JNI动态库。集成思路：将Openssl替换为guanzhi/GmSSL。

​    Netty编译需要依赖Netty-tcnative组件。Netty-tcnative使用Maven编译时会去下载密码库代码，编译密码库组件，并将密码库的库文件静态依赖到JNI动态库中。由此完成Netty到密码库的通道加密的调用。 

Netty-tcnative再linux编译比较好编译，但是再window编译，我尝试了各种办法，总是编译失败，所以我采用半自动的方式进行编译，Netty-tcnative会生成临时文件，直接用vs打开，设置openssl的头文件和静态库路径，然后生成静态库，静态库改个名字放到jar包里边，其实自动编译也是这个原理哈哈O(∩_∩)O

![image-20240415195115476](https://s2.loli.net/2024/04/16/npO3PcQEHRxG9j2.png)

![image-20240415195253656](https://s2.loli.net/2024/04/16/bClYhf8oAsWxNce.png)

netty改造实现

c端代码 修改openssl-dynamic中sslcontent.c文件中的make方法中更换为NTLS的握手方式；扩展setCertificate方法 增加对国密双证的支持。直接传输五个证书的路径吗，之前有的是说要转成x509之类的，转来转去的有点麻烦，这个是直接传输证书路径，由底层gmssl去解析，格式必须是pem格式

```c
TCN_IMPLEMENT_CALL(jboolean, SSLContext, setCertificateExt)(TCN_STDARGS, jlong ctx,
                                                         jstring enccert, jstring enckey,
                                                         jstring signcert, jstring signkey,
                                                         jstring password)
{
#ifdef OPENSSL_IS_BORINGSSL
    tcn_Throw(e, "Not supported using BoringSSL");
    return JNI_FALSE;
#else
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    TCN_CHECK_NULL(c, ctx, JNI_FALSE);
    jboolean rv = JNI_TRUE;
    TCN_ALLOC_CSTRING(enccert);
    TCN_ALLOC_CSTRING(enckey);
    TCN_ALLOC_CSTRING(signcert);
    TCN_ALLOC_CSTRING(signkey);
    TCN_ALLOC_CSTRING(password);
    EVP_PKEY *encpkey = NULL;
    X509 *encxcert = NULL;
    EVP_PKEY *signpkey = NULL;
    X509 *signxcert = NULL;
    const char *enc_key_file = NULL;
    const char *enc_cert_file = NULL;
    const char *sign_key_file = NULL;
    const char *sign_cert_file = NULL;
    //const char *p = NULL;
    char *old_password = NULL;
    char err[ERR_LEN];
    if (J2S(password)) {
        old_password = c->password;
        c->password = strdup(cpassword);
        if (c->password == NULL) {
            rv = JNI_FALSE;
            goto cleanup;
        }
    }
    enc_key_file  = J2S(enckey);
    enc_cert_file = J2S(enccert);
    sign_key_file  = J2S(signkey);
    sign_cert_file = J2S(signcert);
    if (!enc_key_file) {
        enc_key_file = enc_cert_file;
    }
    if (!sign_key_file) {
        sign_key_file = sign_cert_file;
    }
    if (!enc_key_file || !enc_cert_file) {
        tcn_Throw(e, "No Enc Certificate file specified or invalid file format");
        rv = JNI_FALSE;
        goto cleanup;
    }
    if (!sign_key_file || !sign_cert_file) {
        tcn_Throw(e, "No Sign Certificate file specified or invalid file format");
        rv = JNI_FALSE;
        goto cleanup;
    }
 
    SSL_CTX_set_cipher_list(c->ctx, "SM2-WITH-SMS4-SM3");

    if (SSL_CTX_use_certificate_file(c->ctx, sign_cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_error_string_n(ERR_get_error(), err, ERR_LEN);
        tcn_Throw(e, "Error setting sign certificate (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }

    if (SSL_CTX_use_PrivateKey_file(c->ctx, sign_key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_error_string_n(ERR_get_error(), err, ERR_LEN);
        tcn_Throw(e, "Error setting sign private key (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }

    if (!SSL_CTX_check_private_key(c->ctx)) {
        ERR_error_string_n(ERR_get_error(), err, ERR_LEN);
        tcn_Throw(e, "Error :  private check failer (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }

    if (SSL_CTX_use_certificate_file(c->ctx, enc_cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_error_string_n(ERR_get_error(), err, ERR_LEN);
        tcn_Throw(e, "Error setting enc certificate (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }
 
    if (SSL_CTX_use_PrivateKey_file(c->ctx, enc_key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_error_string_n(ERR_get_error(), err, ERR_LEN);
        tcn_Throw(e, "Error setting enc private key (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }

    if (!SSL_CTX_check_private_key(c->ctx)) {
        ERR_error_string_n(ERR_get_error(), err, ERR_LEN);
        tcn_Throw(e, "Error :  private check failer", err);
        rv = JNI_FALSE;
        goto cleanup;
    }

    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
   
cleanup:
    TCN_FREE_CSTRING(enccert);
    TCN_FREE_CSTRING(enckey);
    TCN_FREE_CSTRING(signcert);
    TCN_FREE_CSTRING(signkey);
    TCN_FREE_CSTRING(password);
    EVP_PKEY_free(encpkey); // this function is safe to call with NULL
    X509_free(encxcert); // this function is safe to call with NULL
    EVP_PKEY_free(signpkey);
    X509_free(signxcert);
    free_and_reset_pass(c, old_password, rv);
    return rv;
#endif // OPENSSL_IS_BORINGSSL
}

```



java端调用逻辑，通过build函数调用上边的方法创建SslContext对象，其实腾讯以及第三方的实现基于netty集成都是创建SslContext对象。然后注入给netty

```
public static native boolean setCertificateExt(long var0, String var2, String var3, String var4, String var5, String var6) throws Exception;
```

![image-20240415202334248](https://s2.loli.net/2024/04/16/jDJlxrZqFW7SeiR.png)



java client用法

```java
      final SslContext sslCtx = SslContextGMBuilder.forClient().protocols()
                .keyManagerFile(null, signENCPath, signENCPrivateKeyPath,
                        signPrivatePath, signPrivateKeyPath,
                        null
                )
                .ciphers(Arrays.asList("SM2-WITH-SMS4-SM3"))
                .build();

    //示例用法
      Bootstrap b = new Bootstrap();
            b.group(group)
            .channel(NioSocketChannel.class)
            .option(ChannelOption.TCP_NODELAY, true)
            .handler(new ChannelInitializer<SocketChannel>() {
                @Override
                public void initChannel(SocketChannel ch) throws Exception {
                    ChannelPipeline p = ch.pipeline();
                    p.addLast(sslCtx.newHandler(ch.alloc()));//注意这里
                    p.addLast(new EchoClientHandler());
                }
            });


```





基本代码和流程已经介绍完了，稍后我会把源码上传的github上，方便大家编译和下载

后续工作：

继续改造server端

###### 参考博客

[新手入坑GMSSL（一）Windows下编译GMSSL并生成CA证书_gmssl证书制作windows-CSDN博客](https://blog.csdn.net/qq_40153886/article/details/106933931)

[GmSSL编程实现gmtls协议C/S通信(BIO版本)_tassl_demo/mk_tls_cert 下的 sm2certgen.sh-CSDN博客](https://blog.csdn.net/xiejianjun417/article/details/99963297)