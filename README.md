# 🚀 多协议代理一键部署脚本 v3.0

一个简单易用的多协议代理部署脚本，支持 **15 种主流协议**，服务端/客户端一键安装，适用于 Alpine、Debian、Ubuntu、CentOS 等 Linux 发行版。

> 🙏 **声明**：本人只是一个搬运工，脚本灵感来源于网络上的各种优秀项目，特别感谢 [mack-a/v2ray-agent](https://github.com/mack-a/v2ray-agent) 八合一脚本的启发。

---

## 🆕 v3.0 重大更新

### 📡 订阅服务支持
- **自动生成订阅链接**，支持 Clash/Clash Verge、Surge、V2Ray 格式
- 订阅内容自动包含所有已安装协议
- 基于 Nginx 的 HTTPS 订阅服务，安全可靠
- 订阅 UUID 随机生成，防止被猜测
- 伪装网页支持，支持自定义，路径/var/www/html
- 卸载协议时自动更新订阅内容

### 🔌 443 端口复用 (TLS回落机制)
- **VLESS-Vision / Trojan 作为 TLS 主协议**，监听 443 端口
- **VLESS-WS / VMess-WS 作为回落子协议**，共享主协议 443 端口
- 回落子协议监听本地端口，外部统一通过 443 访问
- 订阅链接自动使用正确的外部端口
- 智能端口推荐：回落子协议自动推荐随机内部端口

### 🆕 新增协议
- **VLESS+gRPC+TLS** - CDN 友好，支持多路复用，高性能传输
- **VMess+WS** - 经典 VMess 协议，支持 443 回落复用/免流
- **ShadowTLS** - TLS 流量伪装协议，配合 Shadowsocks 使用

### 🔧 智能端口管理
- 回落子协议自动识别，推荐随机内部端口
- 独立协议推荐 443/8443 等 HTTPS 端口
- 端口冲突检测增强，显示占用协议名称
- 安装提示优化，明确显示端口用途

### 🎲 随机 SNI 优化
- SNI 配置从固定域名改为随机选择
- 支持常见大站域名随机轮换
- 提高流量伪装的隐蔽性

### 🛡️ 安全增强
- 订阅路径使用随机 UUID，防止被扫描
- 敏感配置文件权限优化

---

## 🔥 核心特性

### 🔀 多协议并存
- 支持同时部署多个代理协议，无需卸载重装
- Xray 系协议自动合并为单一配置，共享核心进程
- 独立协议 (HY2/TUIC/Snell/ShadowTLS 等) 各自独立运行
- 统一的协议注册/注销管理机制

### 📡 订阅服务
- 自动生成 Clash/Surge/V2Ray 格式订阅
- HTTPS 加密传输，安全可靠
- 伪装网页，防止被识别
- 协议变更自动更新订阅内容

### 🔌 端口复用
- TLS 主协议 (Vision/Trojan) 支持 WS 回落
- 流量特征更隐蔽，像正常 HTTPS 网站
- 无需开放多个端口，防火墙配置更简单

### 🔒 ACME 真实证书
- 自动申请 Let's Encrypt 证书
- 支持 Trojan/Hysteria2/TUIC/VLESS-WS/VLESS-Vision 协议
- 证书自动续期，无需手动维护

### ⚡ BBR 拥塞控制
- 自动检测并启用 BBR 内核模块
- 显著提升网络传输性能和稳定性

---

## ✨ 支持协议

| # | 协议 | 特点 | 推荐场景 |
|---|------|------|----------|
| 1 | **VLESS + Reality** | 抗封锁能力强，无需域名 | 🌟 首选推荐 |
| 2 | **VLESS + Reality + XHTTP** | 多路复用，性能更优 | 高并发场景 |
| 3 | **VLESS + WS + TLS** | CDN 友好，可作回落 | 被墙 IP 救活 |
| 4 | **VLESS + gRPC + TLS** | CDN 友好，多路复用 | 🆕 高性能传输 |
| 5 | **VMess + WS** | 回落分流/免流 | 端口复用 |
| 6 | **VLESS-XTLS-Vision** | TLS主协议，支持回落 | ⭐ 稳定传输 |
| 7 | **SOCKS5** | 经典代理协议 | 🔥 通用性强 |
| 8 | **Shadowsocks 2022** | 新版加密，性能好 | SS 用户迁移 |
| 9 | **Hysteria2** | UDP 加速，端口跳跃 | 🔥 游戏/视频 |
| 10 | **Trojan** | TLS主协议，支持回落 | ⭐ 伪装 HTTPS |
| 11 | **Snell v4** | Surge 专用协议 | iOS/Mac 用户 |
| 12 | **Snell v5** | Surge 5.0 新版协议 | 最新 Surge |
| 13 | **AnyTLS** | 多协议 TLS 代理 | 抗审查能力强 |
| 14 | **ShadowTLS** | TLS 流量伪装 | 新增协议 |
| 15 | **TUIC v5** | QUIC 协议，低延迟 | 新兴协议 |

### 📊 协议特性对比

| 协议 | 过 CDN | 多路复用 | 可做回落 | 需要域名 | 传输层 |
|------|:------:|:--------:|:--------:|:--------:|:------:|
| VLESS + Reality | ❌ | ❌ | ❌ | ❌ | TCP |
| VLESS + XHTTP | ❌ | ✅ | ❌ | ❌ | HTTP/2 |
| VLESS + WS | ✅ | ❌ | ✅ | ✅ | WebSocket |
| VLESS + gRPC | ✅ | ✅ | ❌ | ✅ | gRPC |
| VMess + WS | ✅ | ❌ | ✅ | ✅ | WebSocket |
| VLESS-Vision | ❌ | ❌ | ✅(主) | ✅ | XTLS |
| Trojan | ❌ | ❌ | ✅(主) | ✅ | TLS |
| Hysteria2 | ❌ | ✅ | ❌ | ✅ | QUIC |
| TUIC v5 | ❌ | ✅ | ❌ | ✅ | QUIC |

### 🎯 协议选择指南

**抗封锁首选：**
- **VLESS + Reality** - 无需域名，流量特征像正常 TLS，抗封锁能力最强

**被墙 IP 救活：**
- **VLESS + WS + TLS** - 可套 CDN（如 Cloudflare），IP 被墙也能用
- **VLESS + gRPC + TLS** - 同样支持 CDN，且有多路复用，性能更好

**高性能传输：**
- **VLESS + XHTTP** - HTTP/2 多路复用，高并发场景性能优异
- **VLESS + gRPC** - gRPC 多路复用，适合大流量传输
- **Hysteria2** - QUIC 协议，UDP 加速，游戏/视频体验好

**端口复用：**
- **VLESS-Vision / Trojan** - 作为 TLS 主协议监听 443
- **VLESS-WS / VMess-WS** - 作为回落子协议，共享 443 端口

**特殊场景：**
- **Snell v4/v5** - Surge 专用，iOS/Mac 用户首选
- **ShadowTLS** - TLS 流量伪装，配合 SS 使用
- **AnyTLS** - 多协议 TLS 代理，抗审查能力强

---

## 🚀 快速开始

### 一键安装

```bash
wget -O vless.sh https://raw.githubusercontent.com/Chil30/vless-all-in-one/main/vless.sh && chmod +x vless.sh && bash vless.sh
```

### 服务端安装

```bash
vless
# 选择 1) 安装服务端
# 选择协议 (推荐 6-VLESS-Vision 或 1-VLESS+Reality)
# 确认安装
```

安装完成后显示：
- **JOIN 码** - 复制给客户端使用
- **分享链接** - 可导入 v2rayN、Clash、小火箭等
- **二维码** - 手机扫码导入
- **订阅链接** - Clash/Surge/V2Ray 订阅

### 客户端安装

```bash
vless
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
# 主菜单选择「订阅管理」
# 1) 查看订阅链接
# 2) 更新订阅内容
# 3) 重新配置
# 4) 停用订阅服务
```

### 订阅特性

- ✅ 自动包含所有已安装协议
- ✅ 安装/卸载协议后自动更新
- ✅ HTTPS 加密传输
- ✅ 伪装网页，访问根路径显示正常网站
- ✅ 随机 UUID 路径，防止被扫描

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
      多协议代理 一键部署 v3.0
      作者: Chil30  快捷命令: vless
═════════════════════════════════════════════
  状态: ● 运行中
  角色: 服务端
  协议: VLESS-Vision, VLESS-WS, VMess-WS
─────────────────────────────────────────────
  1) 查看配置
  2) 添加协议
  3) 订阅管理
  4) 管理协议服务
  5) BBR 网络优化
  6) 卸载指定协议
  7) 完全卸载
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
  4) VLESS + gRPC + TLS (CDN友好, 多路复用)
  5) VMess + WS (回落分流/免流)
  6) VLESS-XTLS-Vision (TLS主协议, 支持回落)
  7) SOCKS5 (经典代理)
  8) Shadowsocks 2022 (新版加密)
  9) Hysteria2 (UDP加速, 高速)
  10) Trojan (TLS主协议, 支持回落)
  11) Snell v4 (Surge专用)
  12) Snell v5 (Surge 5.0新版)
  13) AnyTLS (多协议TLS代理)
  14) ShadowTLS (TLS流量伪装)
  15) TUIC v5 (QUIC协议)

  提示: 先装主协议(6/10)占用443，再装WS(3/5)可共用端口
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

---

## 📁 文件位置

```
/etc/vless-reality/
├── config.json           # Xray 主配置文件
├── installed_protocols   # 已安装协议列表
├── vless-vision.info     # VLESS-Vision 配置
├── vless-ws.info         # VLESS-WS 配置
├── vmess-ws.info         # VMess-WS 配置
├── trojan.info           # Trojan 配置
├── shadowtls.info        # ShadowTLS 配置
├── shadowtls-ss.json     # ShadowTLS 后端 SS 配置
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
- [xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks) - TUN 转 SOCKS5
- [apernet/hysteria](https://github.com/apernet/hysteria) - Hysteria2 协议
- [EAimTY/tuic](https://github.com/EAimTY/tuic) - TUIC 协议
- [ihciah/shadow-tls](https://github.com/ihciah/shadow-tls) - ShadowTLS 协议

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

### v3.0 (2025-12-25)
- 📡 **订阅服务支持**
  - 自动生成 Clash/Surge/V2Ray 格式订阅链接
  - 基于 Nginx 的 HTTPS 订阅服务
  - 伪装网页支持
  - 订阅 UUID 随机生成，防止被扫描
  - 卸载协议时自动更新/清理订阅
- 🔌 **443 端口复用 (TLS回落机制)**
  - VLESS-Vision / Trojan 作为 TLS 主协议
  - VLESS-WS / VMess-WS 作为回落子协议
  - 订阅链接自动使用正确的外部端口
  - 智能端口推荐：回落子协议推荐随机内部端口
- 🆕 **新增协议**
  - VMess+WS - 支持 443 回落复用/免流
  - ShadowTLS - TLS 流量伪装协议
- 🔧 **功能优化**
  - SNI 配置优化，随机选择常用未墙大站域名
  - 端口推荐逻辑优化，回落子协议不再推荐 443
  - Clash 订阅默认端口改为 7897 (Clash Verge 默认)
  - 卸载协议时自动清理相关订阅配置
  - Trojan 支持作为 TLS 主协议进行 WS 回落
- 🛡️ **安全增强**
  - Nginx 配置添加 `server_tokens off`
  - 订阅路径使用随机 UUID

### v2.0 (2025-12-23)
- 🚀 多协议并存支持 (12 种协议)
- 🔒 ACME 真实证书支持
- 🔌 智能端口推荐
- ⚡ Hysteria2 端口跳跃支持
- ⚡ BBR 拥塞控制优化
- 🔧 端口冲突检测

### v1.0 (2025-12-21)
- 🎉 首次发布

---

**⭐ 如果觉得有用，欢迎 Star！**
