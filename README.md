# 多协议代理一键部署脚本 v3.0.5

一个简单易用的多协议代理部署脚本，支持 **13 种主流协议**，服务端/客户端一键安装，适用于 Alpine、Debian、Ubuntu、CentOS 等 Linux 发行版。

> 🙏 **声明**：本人只是一个搬运工，脚本灵感来源于网络上的各种优秀项目，特别感谢 [mack-a/v2ray-agent](https://github.com/mack-a/v2ray-agent) 八合一脚本的启发。

---

## 🆕 v3.0.5 更新

- 修复 SS2022-ShadowTLS 套壳协议运行时 CPU 占用 100% 的问题

- 减少数据库查询次数，菜单响应速度提升

- 修复卸载功能

---

## ✨ 支持协议

| # | 协议 | 特点 | 推荐场景 |
|---|------|------|----------|
| 1 | **VLESS + Reality** | 抗封锁能力强，无需域名 | 🌟 首选推荐 |
| 2 | **VLESS + Reality + XHTTP** | 多路复用，性能更优 | 高并发场景 |
| 3 | **VLESS + WS + TLS** | CDN 友好，可作回落 | 被墙 IP 救活 |
| 4 | **VMess + WS** | 回落分流/免流 | 端口复用 |
| 5 | **VLESS-XTLS-Vision** | TLS主协议，支持回落 | ⭐ 稳定传输 |
| 6 | **SOCKS5** | 经典代理协议 | 🔥 通用性强 |
| 7 | **Shadowsocks 2022** | 新版加密，性能好 | SS 用户迁移 |
| 8 | **Hysteria2** | UDP 加速，端口跳跃 | 🔥 游戏/视频 |
| 9 | **Trojan** | TLS主协议，支持回落 | ⭐ 伪装 HTTPS |
| 10 | **Snell v4** | Surge 专用协议 (支持 ShadowTLS 插件) | iOS/Mac 用户 |
| 11 | **Snell v5** | Surge 5.0 新版协议 (支持 ShadowTLS 插件) | 最新 Surge |
| 12 | **AnyTLS** | 多协议 TLS 代理 | 抗审查能力强 |
| 13 | **TUIC v5** | QUIC 协议，低延迟 | 新兴协议 |


> 💡 **ShadowTLS 插件**：Snell v4、Snell v5、SS2022 安装时可选择启用 ShadowTLS (v3) 插件，实现 TLS 流量伪装，抗检测能力更强。

### 📊 协议特性对比

| 协议 | 过 CDN | 多路复用 | 可做回落 | 需要域名 | 传输层 |
|------|:------:|:--------:|:--------:|:--------:|:------:|
| VLESS + Reality | ❌ | ❌ | ❌ | ❌ | TCP |
| VLESS + XHTTP | ❌ | ✅ | ❌ | ❌ | HTTP/2 |
| VLESS + WS | ✅ | ❌ | ✅ | ✅ | WebSocket |
| VMess + WS | ✅ | ❌ | ✅ | ✅ | WebSocket |
| VLESS-Vision | ❌ | ❌ | ✅(主) | ✅ | XTLS |
| Trojan | ❌ | ❌ | ✅(主) | ✅ | TLS |
| Hysteria2 | ❌ | ✅ | ❌ | ✅ | QUIC |
| TUIC v5 | ❌ | ✅ | ❌ | ✅ | QUIC |
| AnyTLS | ❌ | ❌ | ❌ | ❌ | TLS |
| ShadowTLS 套壳 | ❌ | ❌ | ❌ | ❌ | TLS 伪装 |

### 🎯 协议选择指南

**抗封锁首选：**
- **VLESS + Reality** - 无需域名，流量特征像正常 TLS，抗封锁能力最强
- **AnyTLS** - 多协议 TLS 代理，抗审查能力强

**被墙 IP 救活：**
- **VLESS + WS + TLS** - 可套 CDN（如 Cloudflare），IP 被墙也能用
- **VMess + WS** - 同样支持 CDN，兼容性好

**高性能传输：**
- **VLESS + XHTTP** - HTTP/2 多路复用，高并发场景性能优异
- **Hysteria2** - QUIC 协议，UDP 加速，游戏/视频体验好
- **TUIC v5** - QUIC 协议，低延迟

**端口复用：**
- **VLESS-Vision / Trojan** - 作为 TLS 主协议监听 443
- **VLESS-WS / VMess-WS** - 作为回落子协议，共享 443 端口

**特殊场景：**
- **Snell v4/v5** - Surge 专用，iOS/Mac 用户首选
- **ShadowTLS 套壳** - TLS 流量伪装，配合 Snell/SS 使用，抗检测能力强

---

## 🚀 快速开始

### 一键安装服务端

```bash
wget -O vless-server.sh https://raw.githubusercontent.com/Chil30/vless-all-in-one/main/vless-server.sh && chmod +x vless-server.sh && bash vless-server.sh
```

### 服务端安装

```bash
vless
# 选择 1) 安装新协议
# 选择协议 (推荐 1-VLESS+Reality)
# 确认安装
```

安装完成后显示：
- **JOIN 码** - 复制给客户端使用
- **分享链接** - 可导入 v2rayN、Clash、小火箭等
- **二维码** - 手机扫码导入
- **订阅链接** - Clash/Surge/V2Ray/Loon 订阅

### 一键安装客户端

```bash
wget -O vless-client.sh https://raw.githubusercontent.com/Chil30/vless-all-in-one/main/vless-client.sh && chmod +x vless-client.sh && bash vless-client.sh
```

### 客户端安装

```bash
vlessc
# 选择 2) 安装客户端 (JOIN码)
# 粘贴服务端的 JOIN 码
# 选择代理模式 (推荐 TUN)
```

---


## 📡 订阅服务使用

### 订阅链接格式

安装需要证书的协议 (VLESS-Vision/VLESS-WS/Trojan) 后，自动生成订阅链接：

```
https://你的域名:8443/sub/随机UUID/clash   # Clash/Clash Verge
https://你的域名:8443/sub/随机UUID/surge   # Surge
https://你的域名:8443/sub/随机UUID/v2ray   # V2Ray/通用
```

### 订阅管理

```bash
vless
# 主菜单选择「订阅服务管理」
# 1) 查看订阅链接
# 2) 更新订阅内容
# 3) 外部节点管理
# 4) 重新配置
# 5) 停用订阅服务
```

### 订阅特性

- ✅ 自动包含所有已安装协议
- ✅ 安装/卸载协议后自动更新
- ✅ HTTPS 加密传输
- ✅ 伪装网页，访问根路径显示正常网站
- ✅ 随机 UUID 路径，防止被扫描
- ✅ 外部节点管理，多机聚合订阅

---

## 🌐 WARP 分流功能

### 两种模式

| 模式 | 协议 | 特点 | 适用场景 |
|------|------|------|----------|
| **WGCF** | UDP/WireGuard | Xray 内置，性能好 | UDP 未被封锁 |
| **官方客户端** | TCP/SOCKS5 | 绕过 UDP 封锁，稳定 | UDP 被封锁环境 |

### 分流规则

| 规则 | 说明 |
|------|------|
| OpenAI/ChatGPT | openai.com, chatgpt.com, ai.com 等 |
| Netflix | netflix.com 及相关域名 |
| 流媒体 | Netflix + Disney+ + HBO + Hulu + Spotify |
| 全部流量 | 所有代理流量走 WARP |
| 自定义 | 自定义域名列表（英文逗号分隔） |

### 使用方法

```bash
vless
# 主菜单选择「分流管理 (WARP)」
# 1) WARP 管理 - 配置/切换 WGCF 或官方客户端
# 2) 配置分流规则 - 选择预设或自定义域名
# 3) 测试分流效果
```

### WARP 模式切换

- **WGCF → 官方客户端**：UDP 被封锁时切换
- **官方客户端 → WGCF**：追求更好性能时切换
- 切换后自动更新 Xray/Sing-box 配置

---

## 🔌 端口复用说明

### 工作原理

```
客户端 → 443 端口 → VLESS-Vision/Trojan (TLS主协议)
                              ↓ 回落
                         VLESS-WS (子协议，监听 127.0.0.1)
                         VMess-WS (子协议，监听 127.0.0.1)
```

### 使用方法

1. **先安装 TLS 主协议** (VLESS-Vision 或 Trojan)
2. **再安装回落子协议** (VLESS-WS 或 VMess-WS)
3. 子协议自动识别为回落模式，推荐随机内部端口
4. 订阅链接自动使用 443 端口

### 优势

- 🔒 只需开放 443 端口，防火墙配置简单
- 🎭 流量特征像正常 HTTPS 网站
- 📱 多协议共用一个端口，客户端配置简单

---


## ⚡ Hysteria2 端口跳跃

### 什么是端口跳跃

端口跳跃 (Port Hopping) 是 Hysteria2 的抗封锁特性：
- 服务端用 iptables 将一段端口范围（如 20000-50000）转发到实际监听端口
- 客户端在这个范围内随机切换端口连接
- 流量分散在多个端口，更难被识别和封锁

### 工作原理

```
客户端 → 随机端口 (20000-50000) → iptables NAT → Hysteria2 (15999)
         ↓ 定时切换
客户端 → 另一个随机端口 → iptables NAT → Hysteria2 (15999)
```

### 安装时配置

```
端口跳跃(Port Hopping)
说明：会将一段 UDP 端口范围重定向到 15999
是否启用端口跳跃? [y/N]: y
起始端口 [回车默认 20000]: 
结束端口 [回车默认 50000]: 
```

### 客户端配置

启用端口跳跃后，脚本生成的链接仍使用实际端口（如 15999），会显示提示：

```
⚠ 端口跳跃已启用
客户端请手动将端口改为: 20000-50000
```

**需要手动修改客户端端口为范围格式：**
- 原端口：`15999`
- 改为：`20000-50000`

### 客户端支持情况

| 客户端 | 支持端口范围 | 配置方式 |
|--------|-------------|----------|
| Shadowrocket | ✅ | 端口填 `20000-50000` |
| Stash | ✅ | 端口填 `20000-50000` |
| Surge | ✅ | 端口填 `20000-50000` |
| Clash Meta | ✅ | `port: 20000-50000` |
| NekoBox | ✅ | 端口填 `20000-50000` |
| V2RayN | ✅ | 端口填 `20000-50000` |
| V2RayNG | ✅ | 端口填 `20000-50000` |

### 验证端口跳跃是否生效

```bash
# 检查 iptables 规则
iptables -t nat -L PREROUTING -n | grep REDIRECT

# 应该看到类似输出：
# REDIRECT udp -- 0.0.0.0/0 0.0.0.0/0 udp dpts:20000:50000 redir ports 15999
```

### 适用场景

- ✅ 有独立公网 IP 的 VPS
- ✅ 经常被封端口的网络环境
- ❌ NAT 机器（只有固定端口映射）
- ❌ 端口受限的云服务商

---

## 🖥️ 界面预览

### 主菜单 (服务端已安装)
```
═════════════════════════════════════════════
      多协议代理 一键部署 v3.0.4 [服务端]
      作者: Chil30  快捷命令: vless
      https://github.com/Chil30/vless-all-in-one
═════════════════════════════════════════════
  服务端管理
  系统: ubuntu | 架构: Xray+Sing-box 双核
  状态: ● 运行中
  协议: VLESS+Reality, Hysteria2
  端口: 10999, 15999
  分流: OpenAI→WARP
─────────────────────────────────────────────
  1) 安装新协议 (多协议共存)
  2) 查看所有协议配置
  3) 订阅服务管理
  4) 管理协议服务
  5) 分流管理 (WARP)
  6) BBR 网络优化
  7) 卸载指定协议
  8) 完全卸载
  9) 查看运行日志
  u) 检查更新
  0) 退出
─────────────────────────────────────────────
```


### 协议选择
```
─────────────────────────────────────────────
  选择代理协议
─────────────────────────────────────────────
  1) VLESS + Reality (推荐, 抗封锁)
  2) VLESS + Reality + XHTTP (多路复用)
  3) VLESS + WS + TLS (CDN友好, 可作回落)
  4) VMess + WS (回落分流/免流)
  5) VLESS-XTLS-Vision (TLS主协议, 支持回落)
  6) SOCKS5 (经典代理)
  7) Shadowsocks 2022 (新版加密)
  8) Hysteria2 (UDP加速, 高速)
  9) Trojan (TLS主协议, 支持回落)
─────────────────────────────────────────────
  Surge 专属 (支持 ShadowTLS 插件)
─────────────────────────────────────────────
  10) Snell v4 (Surge专用)
  11) Snell v5 (Surge 5.0新版)
─────────────────────────────────────────────
  其他协议
─────────────────────────────────────────────
  12) AnyTLS (多协议TLS代理)
  13) TUIC v5 (QUIC协议)

  提示: 先装主协议(5/9)占用443，再装WS(3/4)可共用端口
─────────────────────────────────────────────
```

### WARP 管理菜单
```
═════════════════════════════════════════════
      WARP 管理
─────────────────────────────────────────────
  状态: ● 已连接
  模式: 官方客户端 (TCP/SOCKS5)
  代理: 127.0.0.1:40000
  抗 UDP 封锁，稳定性好
─────────────────────────────────────────────
  1) 切换到 WGCF 模式
  2) 重新连接官方客户端
  3) 测试 WARP 连接
  4) 卸载官方客户端
  0) 返回
─────────────────────────────────────────────
```

### 分流规则配置
```
─────────────────────────────────────────────
  配置分流规则

  当前状态
─────────────────────────────────────────────
  WARP: ● 已连接 (官方客户端/TCP)
  代理: 127.0.0.1:40000
  分流: OpenAI/ChatGPT → WARP
─────────────────────────────────────────────
  选择分流模式:

  1) OpenAI/ChatGPT 解锁
  2) Netflix 解锁
  3) 流媒体解锁 (Netflix/Disney+/HBO)
  4) 所有流量走 WARP
  5) 自定义域名规则
  6) 关闭分流
  0) 返回
─────────────────────────────────────────────
```

---

## 📱 客户端推荐

| 平台 | 推荐客户端 | 订阅支持 |
|------|-----------|----------|
| **Windows** | [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) | ✅ Clash 订阅 |
| **Windows** | [V2rayN](https://github.com/2dust/v2rayN) | ✅ V2Ray 订阅 |
| **macOS** | [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) | ✅ Clash 订阅 |
| **macOS** | [Surge](https://nssurge.com/) | ✅ Surge 订阅 |
| **iOS** | [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) | ✅ 通用订阅 |
| **iOS** | [Surge](https://apps.apple.com/app/surge-5/id1442620678) | ✅ Surge 订阅 |
| **Android** | [Clash Meta](https://github.com/MetaCubeX/ClashMetaForAndroid) | ✅ Clash 订阅 |
| **Android** | [V2rayNG](https://github.com/2dust/v2rayNG) | ✅ V2Ray 订阅 |

---

## 🔧 代理模式说明

### 1️⃣ TUN 网卡模式 (推荐)
```
创建虚拟网卡 tun0，修改系统路由表
✅ 全局透明代理，所有应用自动走代理
✅ 支持 TCP/UDP
❌ LXC 容器可能不支持
```

### 2️⃣ 全局代理模式 (iptables)
```
使用 iptables 劫持流量
✅ 兼容性好
✅ 支持纯 IPv6 + WARP 环境
❌ 仅代理 TCP 流量
```

### 3️⃣ SOCKS5 模式
```
仅启动 SOCKS5 代理 (127.0.0.1:10808)
✅ 无需特殊权限，兼容性最好
❌ 需要手动配置应用使用代理
```

---


## 📋 系统要求

### 支持的系统
- Debian 9+ / Ubuntu 18.04+
- CentOS 7+ 
- Alpine Linux 3.12+

### 架构支持
- x86_64 (amd64)
- ARM64 (aarch64)

### WARP 官方客户端限制
- ❌ Alpine Linux 不支持（依赖 glibc）
- ✅ Debian/Ubuntu/CentOS 支持

---

## ❓ 常见问题

### Q: 订阅链接返回 404
- 检查 Nginx 是否运行：`ss -tlnp | grep 8443`
- 检查订阅文件是否存在：`ls /etc/vless-reality/subscription/`
- 重新配置订阅：主菜单 → 订阅管理 → 重新配置

### Q: Clash 订阅导入后部分协议超时
- 检查是否为回落子协议，确认使用 443 端口
- 更新订阅文件：主菜单 → 订阅管理 → 更新订阅内容

### Q: 安装失败，提示依赖安装失败
```bash
# Debian/Ubuntu
apt update && apt install -y curl jq unzip iproute2 nginx

# CentOS
yum install -y curl jq unzip iproute nginx

# Alpine
apk add curl jq unzip iproute2 nginx
```

### Q: TUN 模式启动失败
- LXC 容器不支持 TUN，请使用全局代理或 SOCKS5 模式
- 检查 TUN 模块：`ls -la /dev/net/tun`

### Q: ShadowTLS 服务启动失败
- 确保 Xray 已安装（ShadowTLS 需要后端 Shadowsocks 服务）
- 检查服务状态：`systemctl status vless-shadowtls vless-shadowtls-ss`

### Q: Hysteria2 端口跳跃不生效
- 检查 iptables 规则：`iptables -t nat -L PREROUTING -n | grep REDIRECT`
- 确认 `hop_enable=1`：`cat /etc/vless-reality/hy2.info`
- 重启服务：`systemctl restart vless-hy2`
- NAT 机器不支持端口跳跃（服务商只给固定端口）

### Q: WARP 官方客户端注册失败
- 确保系统不是 Alpine（不支持官方客户端）
- 检查 warp-svc 服务：`systemctl status warp-svc`
- 尝试手动注册：`warp-cli registration new --accept-tos`

### Q: WARP 分流不生效
- 检查 WARP 状态：主菜单 → 分流管理 → WARP 管理 → 测试连接
- 确认分流规则已配置：主菜单 → 分流管理 → 查看当前配置
- 重启代理服务：主菜单 → 管理协议服务 → 重启

---

## 📁 文件位置

```
/etc/vless-reality/
├── config.json           # Xray 主配置文件
├── singbox.json          # Sing-box 配置文件
├── db.json               # JSON 数据库 (协议配置、分流规则)
├── warp.json             # WGCF 配置文件
├── installed_protocols   # 已安装协议列表
├── sub.info              # 订阅服务配置
├── sub_uuid              # 订阅 UUID
├── subscription/         # 订阅文件目录
│   └── {uuid}/
│       ├── clash.yaml    # Clash 订阅
│       ├── surge.conf    # Surge 订阅
│       └── base64        # V2Ray 订阅
├── certs/                # 证书目录
└── ...
```

---


## 🙏 致谢

### 灵感来源
- [mack-a/v2ray-agent](https://github.com/mack-a/v2ray-agent) - 八合一共存脚本

### 核心组件
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) - 代理核心引擎
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box) - Sing-box 核心
- [xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks) - TUN 转 SOCKS5
- [apernet/hysteria](https://github.com/apernet/hysteria) - Hysteria2 协议
- [EAimTY/tuic](https://github.com/EAimTY/tuic) - TUIC 协议
- [ihciah/shadow-tls](https://github.com/ihciah/shadow-tls) - ShadowTLS 协议
- [ViRb3/wgcf](https://github.com/ViRb3/wgcf) - WARP WireGuard 配置生成
- [Cloudflare WARP](https://developers.cloudflare.com/warp-client/) - 官方客户端

---

## ⚠️ 免责声明

- 本脚本仅供学习交流使用
- 请遵守当地法律法规
- 作者不对使用本脚本造成的任何后果负责

---

## 📄 许可证

MIT License

---

## 📝 更新日志

### v3.0.5 (2024-12-29)

- 修复 SS2022-ShadowTLS 套壳协议运行时 CPU 占用 100% 的问题

- 减少数据库查询次数，菜单响应速度提升

- 修复卸载功能

### v3.0.4 (2024-12-29)

- 🏗️ **架构重构**
  - 双核心架构：Xray 处理 TCP/TLS 协议，Sing-box 处理 UDP/QUIC 协议 (Hysteria2/TUIC)

- 🌐 **WARP 分流功能 (双模式)**
  - **WGCF 模式**：Xray 内置 WireGuard，UDP 协议，性能好
  - **官方客户端模式**：TCP/SOCKS5 协议，绕过 UDP 封锁，稳定性强
  - 二选一切换：两种模式可随时切换，自动更新代理配置
  - 预设分流规则：OpenAI/ChatGPT、Netflix、流媒体一键解锁
  - 自定义域名分流：支持自定义域名列表走 WARP 出口
  - 全流量 WARP：可选所有代理流量走 WARP 出口
  - 自动注册：wgcf 自动下载注册，官方客户端自动安装配置
  - IP 获取优化：多 API 源重试，失败时可选重试/跳过/放弃
  - 分流测试：配置后自动测试分流效果

### v3.0.3 (2024-12-28)

- 修复覆盖安装hy2协议iptables规则不清空问题

### v3.0.2 (2024-12-28)

- 🎨 **菜单界面优化**
  - 精简菜单选项，从 16 项减少到 13 项
  - 移除独立的 ShadowTLS 组合菜单项，改为安装时动态询问
  - 新增分类提示：`Surge 专属 (支持 ShadowTLS 插件)` 和 `其他协议`
  - Snell v4、Snell v5、SS2022 安装时询问是否启用 ShadowTLS 插件

- 📦 **代码结构优化**
  - 重新整理模块分隔符和函数分组
  - 新增模块：端口管理、密钥与凭证生成、分享链接生成、连接测试

### v3.0.1 (2024-12-28)

- 📦 **脚本架构重构**
  - 原一键脚本拆分为独立的服务端 (`vless-server.sh`) 和客户端 (`vless-client.sh`)
  - 服务端专注于协议部署和订阅管理，客户端专注于 JOIN 码连接
  - 两个脚本可独立使用，按需下载

- 🆕 **新增 ShadowTLS 套壳协议**
  - Snell v4 + ShadowTLS
  - Snell v5 + ShadowTLS
  - SS2022 + ShadowTLS

- 📱 **Loon/Surge 配置直接输出**
  - 安装协议后终端直接显示 Loon 和 Surge 的配置片段

- 🌐 **外部节点管理 (多机聚合订阅)**
  - 支持添加分享链接和订阅链接
  - 自动解析 Clash YAML 配置

- 💡 **订阅节点命名优化**
  - 节点名称格式：`地区-协议名-IP后缀`

### v3.0 (2024-12-25)

- 📡 **订阅服务支持**
- 🔌 **443 端口复用 (TLS回落机制)**
- 🆕 **新增 VMess+WS、ShadowTLS 协议**

### v2.0 (2024-12-23)

- 🚀 多协议并存支持 (12 种协议)
- 🔒 ACME 真实证书支持
- ⚡ Hysteria2 端口跳跃支持
- ⚡ BBR 拥塞控制优化

### v1.0 (2024-12-21)

- 🎉 首次发布

---

**⭐ 如果觉得有用，欢迎 Star！**