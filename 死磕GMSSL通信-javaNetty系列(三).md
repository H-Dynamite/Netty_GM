#### 死磕GMSSL通信-java/Netty系列（三）

接着上次的博客继续完善，上次其实只是客户端的改造，这次把服务端的也补上，netty集成GMSSL实现GMServer

1、netty_tcnative c代码改造，这个是客户端和服务端都需要都该的地方

sslcontext.c文件

TCN_IMPLEMENT_CALL(jlong, SSLContext, make)(TCN_STDARGS, jint protocol, jint mode)方法

```c
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
    // TODO this is very hacky as io.netty.handler.ssl.OpenSsl#doesSupportProtocol also uses this method to test for supported protocols. Furthermore
    // in OpenSSL 1.1.0 the way protocols are enable/disabled changes
    // (SSL_OP_NO_SSLv3,... are deprecated and you should use: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_max_proto_version.html)
    if (mode == SSL_MODE_CLIENT) {
        ctx = SSL_CTX_new(GMTLS_client_method());//修改
    } else if (mode == SSL_MODE_SERVER) {
        ctx = SSL_CTX_new(GMTLS_server_method());//修改
    } else {
        ctx = SSL_CTX_new(TLS_method());
    }
```



客户端必须注释掉这行代码`SL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION` 和 `SSL_OP_LEGACY_SERVER_CONNECT` 这两个选项。这样做是为了增强 SSL/TLS 通信的安全性，避免因兼容性设置而引入潜在的安全风险。 **这个地方注意，必须要注释掉，不然会提示加密套件有漏洞之类的。**

```c
    //SSL_CTX_clear_options(c->ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | SSL_OP_LEGACY_SERVER_CONNECT);
```

 

GmSSL 中对应的国密算法 SM2 使用的是名为 **SM2 P-256V1** 的椭圆曲线，其参数与国际标准中的曲线不同，专门为国密算法设计，所以需要再netty里边把这个加上，否则会提示加密套件不支持之类的错误提示，再OpenSsl.java这个文件

```
private static final String[] DEFAULT_NAMED_GROUPS = { "x25519", "secp256r1", "secp384r1", "secp521r1","sm2p256v1" };
```

使用也很简单，其他就和netty的流程一样了

```
   final SslContext sslCtx  = SslContextGMBuilder.forServer(encCertPath, encKeyPath,
                signCertPath, signKeyPath,
                caCertPath).protocols()
        .ciphers(Arrays.asList(
                "TLCP_SM2-WITH-SMS4-SM3"
        ))
        .clientAuth(ClientAuth.NONE)
        .build();
        
        
        // Configure the server.
        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        try {
            ServerBootstrap b = new ServerBootstrap();
            final EchoServerHandler serverHandler = new EchoServerHandler();
            b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .option(ChannelOption.SO_BACKLOG, 100)
                    .handler(new LoggingHandler(LogLevel.INFO))
                    .childHandler(new ChannelInitializer<SocketChannel>() {

                        @Override
                        public void initChannel(SocketChannel ch) throws Exception {
                            ChannelPipeline p = ch.pipeline();
                            p.addLast(sslCtx.newHandler(ch.alloc()));
                            p.addLast(serverHandler);
                        }
                    });

            // Start the server.
            ChannelFuture f = b.bind(8999).sync();
```

基本代码和流程已经介绍完了，稍后我会把源码上传的github上，方便大家编译和下载

集成netty 打包注意事项，由于引入的三个jar包

netty-handler-4.1.91.Final.jar

netty-tcnative-classes-2.0.59.Final.jar

netty-tcnative-openssl-static-2.0.59.Final.jar

> [非常重要]
>
> **maven引入顺序** 千万要注意，否则遇大坑

> [!IMPORTANT]
>
> **maven引入顺序** 千万要注意，否则遇大坑



```
        <dependency>
            <groupId>io.netty</groupId>
            <artifactId>netty-tcnative-classes</artifactId>
            <version>2.0.59.Final</version>
            <scope>system</scope>
            <systemPath>${project.basedir}/libs/netty-tcnative-classes-2.0.59.Final.jar</systemPath>
        </dependency>

        <dependency>
            <groupId>io.netty</groupId>
            <artifactId>netty-tcnative-openssl-static</artifactId>
            <version>2.0.59.Final</version>
            <scope>system</scope>
            <systemPath>${project.basedir}/libs/netty-tcnative-openssl-static-2.0.59.Final.jar</systemPath>
        </dependency>

        <dependency>
            <groupId>local-sdk11</groupId>
            <artifactId>netty-handler</artifactId>
            <version>4.1.91.Final</version>
            <scope>system</scope>
            <systemPath>${project.basedir}/libs/netty-handler-4.1.91.Final.jar</systemPath>
        </dependency>

```

打包的时候也需要注意引用顺序，否则遇大坑

```xml
          <archive>
                        <manifest>
                            <addClasspath>true</addClasspath>
                            <!-- MANIFEST.MF 中 Class-Path 加入前缀 -->
                            <classpathPrefix>libs/</classpathPrefix>
                            <!-- jar包不包含唯一版本标识 -->
                            <useUniqueVersions>false</useUniqueVersions>
                            <!-- 指定启动类的包路径 -->
                            <mainClass>org.example.Main</mainClass>
                        </manifest>
                        <manifestEntries>
                            <!--MANIFEST.MF 中 Class-Path 加入资源文件目录 -->
                           <Class-Path>config/ libs/netty-tcnative-classes-2.0.59.Final.jar libs/netty-tcnative-openssl-static-2.0.59.Final.jar libs/netty-handler-4.1.91.Final.jar </Class-Path>
                        </manifestEntries>
                    </archive>
```



以下就可能是如上顺序引起的错误之一



```bash
  Suppressed: java.lang.LinkageError: Possible multiple incompatible native libraries on the classpath for 'C:\Users\dssr\AppData\Local\Temp\netty_tcnative_windows_x86_642142236245374873856.dll'?
                at io.netty.util.internal.NativeLibraryLoader.rethrowWithMoreDetailsIfPossible(NativeLibraryLoader.java:414)
                at io.netty.util.internal.NativeLibraryLoader.loadLibrary(NativeLibraryLoader.java:402)
                at io.netty.util.internal.NativeLibraryLoader.load(NativeLibraryLoader.java:218)
                at io.netty.util.internal.NativeLibraryLoader.loadFirstAvailable(NativeLibraryLoader.java:105)
                ... 8 more
        Caused by: java.lang.NoSuchMethodError: Method io.netty.internal.tcnative.NativeStaticallyReferencedJniMethods.sslOpAllowUnsafeLegacyRenegotiation()I not found
```







后续工作：

1、继续实现其他语言的GMSSL通信

2、代码上传到github

###### 参考博客

[新手入坑GMSSL（一）Windows下编译GMSSL并生成CA证书_gmssl证书制作windows-CSDN博客](https://blog.csdn.net/qq_40153886/article/details/106933931)

[GmSSL编程实现gmtls协议C/S通信(BIO版本)_tassl_demo/mk_tls_cert 下的 sm2certgen.sh-CSDN博客](https://blog.csdn.net/xiejianjun417/article/details/99963297)