/*
 * Copyright 2012 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.example.securechat;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.example.telnet.TelnetServer;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.*;
import io.netty.handler.ssl.util.SelfSignedCertificate;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Simple SSL chat server modified from {@link TelnetServer}.
 */
public final class GMServer {

    static final int PORT = Integer.parseInt(System.getProperty("port", "8999"));

    public static void main(String[] args) throws Exception {
        //SelfSignedCertificate ssc = new SelfSignedCertificate();
//        SslContext sslCtx = SslContextBuilder.forServer(ssc.certificate(), ssc.privateKey())
//            .build();
//        CA = D:\\Lizhenhai\\DrConfigTools\\pem\\CA.cert.pem
//                SE = D:\\Lizhenhai\\DrConfigTools\\pem\\SE.cert.pem
//                SE_K = D:\\Lizhenhai\\DrConfigTools\\pem\\SE.key.pem
//                SS = D:\\Lizhenhai\\DrConfigTools\\pem\\SS.cert.pem
//                SS_K = D:\\Lizhenhai\\DrConfigTools\\pem\\SS.key.pem
//                msgBin= C:\\Users\\dr\\Downloads\\output.bin
        String caFilepath = "D:\\Lizhenhai\\DrConfigTools\\pem\\CA.cert.pem";
        String signENCPath = "D:\\Lizhenhai\\DrConfigTools\\pem\\SE.cert.pem";
        String signENCPrivateKeyPath = "D:\\Lizhenhai\\DrConfigTools\\pem\\SE.key.pem";
        String signPrivatePath = "D:\\Lizhenhai\\DrConfigTools\\pem\\SS.cert.pem";
        String signPrivateKeyPath = "D:\\Lizhenhai\\DrConfigTools\\pem\\SS.key.pem";

        byte[] bytes = Files.readAllBytes(Paths.get(caFilepath));

        String content = new String(bytes, StandardCharsets.UTF_8);

//        String msgBinPath = "D:\\Lizhenhai\\DrConfigTools\\pem\\CA.cert.pem";
//        String clientConnIp = properties.getProperty("client_conn_ip");
//        int clientConnPort = Integer.parseInt(properties.getProperty("client_conn_port"));
        final SslContext sslCtx = SslContextGMBuilder.forServer(signENCPath, signENCPrivateKeyPath,
                        signPrivatePath, signPrivateKeyPath,
                        caFilepath).protocols()
                .protocols(SslProtocols.SSL_v2_HELLO,SslProtocols.SSL_v3,SslProtocols.TLS_v1)
                .ciphers(Arrays.asList(
                        "TLCP_SM2-WITH-SMS4-SM3",
                        "SM2-WITH-SMS4-SM3"
                )) // 允许的密码套件列表
                .clientAuth(    ClientAuth.NONE)
                .trustManager(content)
                .build();

        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        try {
            ServerBootstrap b = new ServerBootstrap();
            final EchoServerHandler serverHandler = new EchoServerHandler();

            b.group(bossGroup, workerGroup)
             .channel(NioServerSocketChannel.class)
             .handler(new LoggingHandler(LogLevel.INFO))
                    .childHandler(new ChannelInitializer<SocketChannel>() {

                        @Override
                        public void initChannel(SocketChannel ch) throws Exception {
                            ChannelPipeline p = ch.pipeline();
                            p.addLast(sslCtx.newHandler(ch.alloc()));
                            p.addLast(serverHandler);
                        }
                    });
//             .childHandler(new SecureChatServerInitializer(sslCtx));

            b.bind(PORT).sync().channel().closeFuture().sync();
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }

    @ChannelHandler.Sharable
    private static class EchoServerHandler extends ChannelInboundHandlerAdapter {

        public void channelRead(ChannelHandlerContext ctx, Object msg) throws UnsupportedEncodingException {

            ByteBuf byteBuf = (ByteBuf) msg;
            byte[] bytes = new byte[byteBuf.readableBytes()];
            byteBuf.readBytes(bytes);
            String msg_str = new String(bytes, "UTF-8");
            System.out.println("===========>接收客户端消息:" + msg_str);

            ctx.write(msg);
        }

        @Override
        public void channelReadComplete(ChannelHandlerContext ctx) {
            ctx.flush();
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            // Close the connection when an exception is raised.
            cause.printStackTrace();
            ctx.close();
        }
    }
}
