# 困扰我们几年的老 GmSSL 兼容问题，终于被我和 AI 一起解决了

## 一个看似普通、实际上几乎无从下手的问题

最近我想把项目里的一套 GmSSL 服务端改造成纯 Java 实现。

原来的服务端使用 Java 调用 C 语言编写的 GmSSL。它不仅部署麻烦，而且严重依赖操作系统和本地动态库。在 Windows 上勉强可以运行，换到 macOS 就会遇到各种问题。为了实现真正的跨平台，我希望用 Java、Netty 和腾讯 KonaSSL 重写 TLCP 服务端。

最开始，我觉得这件事的路线应该很清楚：

1. 用 Netty 创建 TCP 服务端；
2. 使用 KonaSSL 提供 TLCP 和国密算法支持；
3. 加载原有的签名证书、加密证书和私钥；
4. 配置 `TLCP_ECC_SM4_CBC_SM3` 密码套件；
5. 让原来的客户端连接新服务端。

然而真正开始之后才发现，这不是一次普通的技术迁移。

它更像是在没有地图、没有客户端源码、没有维护人员的情况下，考古一套多年前的私有协议实现。

## 客户端只剩下二进制，源码早已丢失

最麻烦的地方是，客户端源码已经找不到了。

我们手里只有编译好的客户端程序。它会每隔几秒自动连接服务端，但无法进入内部调试，也无法查看它究竟使用了什么签名数据、SM2 ID 或证书处理逻辑。

而原来的 GmSSL 也是一个很老的版本：

```text
GmSSL 2.5.4
OpenSSL 1.1.0d
```

这套代码早已缺乏维护，网上能找到的资料很少。更麻烦的是，机器里还保存了多份名字相近的 GmSSL 源码和二进制文件。它们显示的版本号几乎相同，但实际代码并不完全一样。

这个问题已经困扰我们好几年。过去只知道“必须使用原来的 C 服务端”，却没人能解释为什么换一个实现就会失败。

如果完全依靠人工一点点排查，我很可能需要花几周甚至更长时间，最后还未必能找到真正原因。

## 第一版纯 Java 服务端跑起来了，但握手失败

借助 AI，我们先快速搭建了一个独立的 Netty + KonaSSL Demo，并解决了最基础的一批问题：

- Netty 依赖缺失；
- `ClientAuth` 类找不到；
- Netty 各模块版本不一致；
- 编译通过但运行时找不到 `MultithreadEventExecutorGroup`；
- 证书路径写死，换目录后找不到文件；
- KonaSSL Provider 没有加载到修改后的 JAR；
- JVM 参数放到了主类后面，实际没有作为系统属性生效；
- TLCP 双证书的加载方式不正确。

这些问题解决之后，纯 Java TLCP 服务端终于正常启动：

```text
纯 Java TLCP Echo Server 已启动
0.0.0.0:5557
cipher=TLCP_ECC_SM4_CBC_SM3
clientAuth=NONE
```

但客户端一连接，服务端就收到：

```text
javax.net.ssl.SSLHandshakeException:
(decrypt_error) Received fatal alert: decrypt_error
```

看到 `decrypt_error`，第一反应通常是：

- 加密私钥不正确；
- SM4 解密失败；
- 加密证书和私钥不匹配；
- 客户端无法解密预主密钥。

但详细握手日志显示，失败发生得更早。

客户端发送 `ClientHello`，服务端依次返回：

```text
ServerHello
Certificate
ServerKeyExchange
ServerHelloDone
```

随后客户端立即返回 fatal alert 51：

```text
decrypt_error
```

它甚至没有发送 `ClientKeyExchange`。

这意味着问题并不是后续的 SM4 数据解密，而是客户端在验证 `ServerKeyExchange` 数字签名时失败了。

这是整个排查过程中的第一个重要突破。

## Fork KonaSSL，开始进入协议实现内部

普通配置已经无法解决问题，我们决定直接 fork KonaSSL 源码。

这一步如果放在以前，成本会非常高：需要先理解 KonaSSL 的代码结构、TLCP 状态机、SM2 签名实现和 Netty `SSLEngine` 调用链。

AI 在这里发挥了非常明显的作用。它可以快速完成：

- 定位 `SM2ServerKeyExchange` 的生成代码；
- 跟踪签名证书、加密证书和私钥的使用位置；
- 增加可开关的旧版 GmSSL 兼容模式；
- 打印 ClientRandom、ServerRandom、证书包和签名值；
- 修改、编译并替换本地 KonaSSL JAR；
- 根据每次客户端重连结果继续调整假设。

我们最开始怀疑的是 SM2 ID。

标准 SM2 常见的默认 ID 是：

```text
1234567812345678
```

有些 GmSSL 版本则可能使用：

```text
anonym@gmssl.org
```

我们分别测试了这些值，但客户端依旧返回 `decrypt_error`。

接着，我们尝试确认旧 GmSSL 的 `EVP_SignFinal` 到底生成 SM2 签名还是 ECDSA 签名，并编写了本地 C 验证程序。验证结果表明，Java 生成的 SM2 签名在数学上是正确的，旧 GmSSL 也可以验证。

证书 DER 编码同样完全一致。

到了这里，问题变得非常诡异：

> 算法正确，证书正确，签名也能被旧 GmSSL 验证，为什么那个客户端仍然拒绝？

## 一次网络监听问题，差点让排查走错方向

为了获得可靠对照，我们决定重新运行原来的 C 服务端。

但 C 服务端启动后，客户端看起来完全没有连接迹象。Wireshark 中只能看到：

```text
SYN
RST, ACK
```

进一步检查才发现，GmSSL 在 Windows 上默认监听的是 IPv6：

```text
[::]:5557
```

而客户端通过 IPv4 连接，所以系统直接返回 RST。

给 GmSSL 增加 `-4` 参数之后，它才真正监听：

```text
0.0.0.0:5557
```

这是一个很小的参数，却可能造成非常大的误判。如果没有把 TCP 层和 TLCP 层分开分析，我们可能会把“根本没有建立 TCP 连接”误认为“C 服务端兼容，而 Java 服务端不兼容”。

## 同样叫 GmSSL 2.5.4，行为却不一样

接下来出现了整个过程里最关键的转折。

我们自己重新编译的 GmSSL 2.5.4 服务端也失败了，同样在发送 `ServerKeyExchange` 后收到 `decrypt_error`。

这让事情一度陷入僵局。

后来我想起机器里还有另一份很老的 GmSSL：

```text
D:\openssl\GmSSL-GmSSL-v2 (1)\GmSSL-GmSSL-v2\apps\gmssl.exe
```

我告诉 AI：“试试这个，这个好像可以。”

我们停止当前服务端，换成这个二进制，并使用完全相同的证书、私钥、端口和密码套件启动。

日志里终于出现了期待已久的内容：

```text
SSL_accept:SSLv3/TLS read client key exchange
SSL_accept:SSLv3/TLS read change cipher spec
SSL_accept:SSLv3/TLS read finished
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:SSLv3/TLS write finished
```

那一刻非常激动。

因为这不只是“服务端连上了”，而是我们终于获得了一个真正可靠的成功基准。

也正是在这一刻，我们确定：

> 问题不是证书，不是客户端完全不支持 TLCP，也不是 KonaSSL 的基础能力不足，而是不同 GmSSL 2.5.4 源码之间存在实现差异。

## 真正的根因：一个非标准 SM2 ID，加上一个历史长度 bug

成功基准出现后，AI 立即开始对比两份 GmSSL 源码。

最终差异集中到了 `statem_gmtls.c` 中的 `ServerKeyExchange` 构造逻辑。

### 第一个特殊行为：使用加密证书 Subject 作为 SM2 ID

可用版本没有使用标准默认 SM2 ID，而是调用：

```c
id = X509_NAME_oneline(
    X509_get_subject_name(x509), NULL, 0);
```

这里的 `x509` 不是签名证书，而是加密证书。

所以实际 SM2 ID 类似：

```text
/C=CN/ST=BJ/L=FengTai /O=Beijing DAOER Technology LTD./OU=BSRC of TASS/CN=server enc (SM2)
```

它的组合方式也非常特殊：

- SM2 ID 来自加密证书 Subject；
- 计算 Z 值使用签名公钥；
- 最终使用签名私钥完成签名。

只要 SM2 ID 不同，计算出的 Z 值就不同，客户端验证 `ServerKeyExchange` 时一定会失败。

### 第二个特殊行为：签名证书数据时少了最后 3 字节

真正隐蔽的问题来自这段代码：

```c
p = ret;
l2n3(n, p);
*l = n;
```

实际分配和写入的数据是：

```text
3 字节证书长度 + n 字节证书 DER
```

正常情况下，返回长度应该是：

```c
*l = n + 3;
```

但这个旧版本返回的却是：

```c
*l = n;
```

因此后续签名时，虽然数据开头包含 3 字节长度，但参与签名的总长度仍然只有 `n`。

最终真正签进去的是：

```text
3 字节证书长度
+
证书 DER 的前 n-3 字节
```

也就是说，证书 DER 的最后 3 字节被漏掉了。

这是一个非常典型的历史兼容 bug：

- 从协议规范看，它是错的；
- 从现代 KonaSSL 的实现看，完整签名才是正确的；
- 但旧客户端和旧服务端使用了同样的错误逻辑；
- 错误的双方反而可以正常通信；
- 任何“修正”过的服务端都会被旧客户端拒绝。

## 为什么客户端返回的是 `decrypt_error`

这个错误名称很容易把人带偏。

在这里，`decrypt_error` 并不表示 SM4 应用数据解密失败，也不是客户端解不开预主密钥。

客户端在收到以下消息后：

```text
ServerHello
Certificate
ServerKeyExchange
ServerHelloDone
```

需要验证服务端的 SM2 签名。

标准 KonaSSL 签名的是：

```text
标准 SM2 Z
+ ClientRandom
+ ServerRandom
+ 完整证书包
```

旧客户端期待的却是：

```text
特殊 SM2 Z
+ ClientRandom
+ ServerRandom
+ 3 字节长度
+ 缺少最后 3 字节的证书 DER
```

两边签名输入不同，验证必然失败，于是客户端返回 fatal alert 51。

所以整个问题可以用一句话概括：

> 不是 KonaSSL 不支持 TLCP，而是旧客户端依赖一个老 GmSSL 版本的非标准 SM2 ID 和历史长度 bug。

## 在 Java 中精确复刻旧行为

找到根因之后，我们在 fork 的 KonaSSL 中增加了兼容模式。

兼容逻辑包括：

1. 使用加密证书的 OpenSSL 风格 Subject 作为 SM2 ID；
2. 使用签名公钥参与 SM2 Z 值计算；
3. 使用签名私钥生成 SM2 签名；
4. 构造 3 字节证书长度头；
5. 只签入证书 DER 的前 `length - 3` 字节；
6. 保留标准 KonaSSL 路径，只有开启兼容开关时才模拟旧行为。

重新编译 `kona-ssl-1.0.22-gmssl-compat.jar`，启动 Netty Java 服务端。

随后日志中出现：

```text
TLCP 握手成功:
remote=/192.168.138.71
protocol=TLCPv1.1
cipher=TLCP_ECC_SM4_CBC_SM3
```

紧接着第二个客户端也成功：

```text
TLCP 握手成功:
remote=/192.168.145.41
protocol=TLCPv1.1
cipher=TLCP_ECC_SM4_CBC_SM3
```

服务端随后持续收到并返回加密应用数据。

这一次，真的成功了。

困扰我们几年的问题，终于有了明确答案，也终于不再依赖只能在特定平台运行的 C 服务端。

## AI 在这次排查中真正做了什么

这次经历让我对 AI 辅助开发有了更具体的认识。

AI 并不是简单地给出一句“试试更换依赖”或者从网上复制一个示例。它更像一个可以持续协作、快速执行和不断修正假设的技术伙伴。

在这次排查中，AI 帮助完成了：

- 从零搭建 Netty + KonaSSL 的纯 Java TLCP Demo；
- 整理并修复运行时依赖；
- 正确加载原有双证书和私钥；
- fork 并修改 KonaSSL 源码；
- 构建本地兼容 JAR；
- 分析完整 TLCP 握手日志；
- 判断 `decrypt_error` 实际发生在签名验证阶段；
- 编写 C 验证程序验证 Java 签名；
- 检查证书 DER 是否一致；
- 使用 Wireshark/TShark 区分 TCP、TLCP 和不同来源客户端；
- 发现 GmSSL 默认 IPv6 监听问题；
- 对比多份同版本 GmSSL 源码；
- 定位非标准 SM2 ID；
- 定位证书包长度的历史 bug；
- 在 Java 中精确复刻旧行为；
- 启动服务端并等待真实客户端自动重连验证。

更重要的是，它能够保留排查上下文。

一次失败不会让分析重新从零开始，而是变成下一次判断的证据：

- 换 SM2 ID 失败，排除默认 ID 假设；
- Java 签名能被 C 验证，排除算法实现错误；
- DER 完全相同，排除证书编码差异；
- 自己编译的 C 服务端也失败，说明版本号不能代表实现一致；
- 另一份老二进制成功，立即转向源码差异比较；
- 找到长度 bug 后，兼容实现一次验证成功。

如果靠我一个人完成这些事情，需要不断查资料、理解陌生源码、编写验证工具、切换环境和记录每个实验结果。任何一个错误方向，都可能浪费几天时间。

AI 把大量机械工作、源码检索、实验设计和交叉验证压缩到了很短的时间里。

真正有价值的并不是“AI 替我写了几段代码”，而是：

> AI 帮我把一个多年无人维护、资料稀少、客户端源码丢失的问题，变成了一组可以逐步验证和排除的工程问题。

## 这次排查带来的几个经验

### 1. 协议兼容不等于符合最新标准

对于老系统，“正确实现”有时反而无法通信。

只要历史版本的客户端和服务端共同依赖某个 bug，这个 bug 就已经成为事实协议的一部分。迁移时不能只看规范，还必须研究真实线上字节流和旧源码行为。

### 2. 相同版本号不代表相同实现

多份 GmSSL 都显示为 2.5.4，但其中一份可以握手，另一份不可以。

版本信息只能作为线索，最终仍然需要比较二进制哈希、构建配置和源码差异。

### 3. 错误名称不一定代表真正原因

`decrypt_error` 看起来像解密失败，实际却是 `ServerKeyExchange` 签名验证失败。

排查协议问题时，必须结合状态机和消息顺序判断错误发生的位置。

### 4. 一定要建立可靠的成功基准

在没有成功基准之前，所有假设都可能建立在误判上。

找到那份真正能够完成握手的 GmSSL 二进制，是整个排查过程最关键的转折点。

### 5. AI 最适合处理这种跨领域、长链路问题

这个问题同时涉及：

- Java；
- Netty；
- JSSE 和 `SSLEngine`；
- KonaSSL；
- C 和 OpenSSL/GmSSL；
- TLCP 状态机；
- SM2 签名和 Z 值；
- X.509 双证书；
- Windows 网络监听；
- Wireshark 抓包；
- Gradle、Maven 和本地 JAR。

传统排查往往会被这些技术边界切碎，而 AI 可以在同一个上下文里持续追踪整个链路。

## 写在最后

当日志里第一次出现：

```text
TLCP 握手成功
```

我真的非常激动。

它解决的不只是一次连接失败，而是一个困扰团队多年的历史问题。过去我们只能把老 C 库和旧环境继续保留下去，不敢轻易升级，也无法真正跨平台。

现在我们不仅有了纯 Java 实现，还知道了旧系统为什么特殊、为什么标准实现连不上，以及怎样用可控的兼容开关保留这段历史行为。

老代码不可怕，没人维护也不可怕。

最可怕的是问题一直停留在“它就是不能换”，却没人知道为什么。

这一次，我和 AI 一起把这个“为什么”找到了。

而当一个多年遗留问题终于可以被解释、复现、修复并验证时，那种成就感，可能正是程序员最享受的时刻之一。
