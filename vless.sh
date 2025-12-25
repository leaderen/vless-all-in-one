#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
#  多协议代理一键部署脚本 v3.0
#  支持协议: VLESS+Reality / VLESS+Reality+XHTTP / VLESS+WS / VMess+WS / 
#           VLESS-XTLS-Vision / /VLESS+gRPC+TLS/ SOCKS5 / SS2022 / HY2 / Trojan / 
#           Snell v4 / Snell v5 / AnyTLS / TUIC / ShadowTLS (共15种)
#  适配: Alpine/Debian/Ubuntu/CentOS
#  核心特性: 
#    - 多协议共存 / BBR优化 / Watchdog 守护 / FwMark 内核级防死锁
#    - 📡 订阅服务: 自动生成 Clash/Surge/V2Ray 格式订阅链接
#    - 🔌 443端口复用: Vision/Trojan 主协议 + WS 回落子协议
#  
#  作者: Chil30
#  项目地址: https://github.com/Chil30/vless-all-in-one
#═══════════════════════════════════════════════════════════════════════════════

readonly VERSION="3.0"
readonly AUTHOR="Chil30"
readonly REPO_URL="https://github.com/Chil30/vless-all-in-one"
readonly CFG="/etc/vless-reality"
readonly SOCKS_PORT="10808"
readonly REDIR_PORT="10809"
readonly TUN_IP="10.0.85.1"
readonly TUN_GW="10.0.85.2"
readonly FWMARK="255"

# 颜色
R='\e[31m'; G='\e[32m'; Y='\e[33m'; C='\e[36m'; W='\e[97m'; D='\e[2m'; NC='\e[0m'
set -o pipefail

# 系统检测
if [[ -f /etc/alpine-release ]]; then
    DISTRO="alpine"
elif [[ -f /etc/redhat-release ]]; then
    DISTRO="centos"
elif [[ -f /etc/lsb-release ]] && grep -q "Ubuntu" /etc/lsb-release; then
    DISTRO="ubuntu"
elif [[ -f /etc/os-release ]] && grep -q "Ubuntu" /etc/os-release; then
    DISTRO="ubuntu"
else
    DISTRO="debian"
fi

#═══════════════════════════════════════════════════════════════════════════════
# 多协议管理系统
#═══════════════════════════════════════════════════════════════════════════════

# 协议分类定义
XRAY_PROTOCOLS="vless vless-xhttp vless-ws vless-grpc vmess-ws vless-vision trojan socks ss2022"
INDEPENDENT_PROTOCOLS="hy2 tuic snell snell-v5 anytls shadowtls"

# 协议注册和状态管理
register_protocol() {
    local protocol=$1
    mkdir -p "$CFG"
    echo "$protocol" >> "$CFG/installed_protocols"
    sort -u "$CFG/installed_protocols" -o "$CFG/installed_protocols" 2>/dev/null
}

unregister_protocol() {
    local protocol=$1
    [[ -f "$CFG/installed_protocols" ]] && sed -i "/^$protocol$/d" "$CFG/installed_protocols"
}

get_installed_protocols() {
    [[ -f "$CFG/installed_protocols" ]] && cat "$CFG/installed_protocols" || echo ""
}

is_protocol_installed() {
    local protocol=$1
    [[ -f "$CFG/installed_protocols" ]] && grep -q "^$protocol$" "$CFG/installed_protocols"
}

get_xray_protocols() {
    local installed=$(get_installed_protocols)
    local p  # 使用不同的变量名避免污染调用者的 protocol 变量
    for p in $XRAY_PROTOCOLS; do
        if echo "$installed" | grep -q "^$p$"; then
            echo "$p"
        fi
    done
}

get_independent_protocols() {
    local installed=$(get_installed_protocols)
    local p  # 使用不同的变量名避免污染调用者的 protocol 变量
    for p in $INDEPENDENT_PROTOCOLS; do
        if echo "$installed" | grep -q "^$p$"; then
            echo "$p"
        fi
    done
}

# 生成 Xray 多 inbounds 配置
generate_xray_config() {
    local xray_protocols=$(get_xray_protocols)
    [[ -z "$xray_protocols" ]] && return 1
    
    mkdir -p "$CFG"
    cat > "$CFG/config.json" << 'EOF'
{
    "log": {"loglevel": "warning"},
    "inbounds": [],
    "outbounds": [{"protocol": "freedom"}]
}
EOF
    
    # 为每个 Xray 协议添加 inbound，并统计成功数量
    local success_count=0
    local failed_protocols=""
    local p  # 使用局部变量避免污染调用者
    for p in $xray_protocols; do
        if add_xray_inbound "$p"; then
            ((success_count++))
        else
            _warn "协议 $p 配置生成失败，跳过"
            failed_protocols+="$p "
        fi
    done
    
    # 检查是否至少有一个 inbound 成功添加
    if [[ $success_count -eq 0 ]]; then
        _err "没有任何协议配置成功生成"
        return 1
    fi
    
    # 验证最终配置文件的 JSON 格式
    if ! jq empty "$CFG/config.json" 2>/dev/null; then
        _err "生成的 Xray 配置文件 JSON 格式错误"
        return 1
    fi
    
    # 检查 inbounds 数组是否为空
    local inbound_count=$(jq '.inbounds | length' "$CFG/config.json" 2>/dev/null)
    if [[ "$inbound_count" == "0" || -z "$inbound_count" ]]; then
        _err "Xray 配置中没有有效的 inbound"
        return 1
    fi
    
    if [[ -n "$failed_protocols" ]]; then
        _warn "以下协议配置失败: $failed_protocols"
    fi
    
    _ok "Xray 配置生成成功 ($success_count 个协议)"
    return 0
}

# 添加 Xray inbound 配置
add_xray_inbound() {
    local protocol=$1
    local info_file="$CFG/${protocol}.info"
    [[ ! -f "$info_file" ]] && return 1
    
    # 清除可能残留的变量，避免污染
    local uuid="" port="" sni="" short_id="" public_key="" private_key="" path=""
    local password="" username="" method="" psk="" version=""
    local ipv4="" ipv6="" server_ip="" stls_password=""
    
    # 从 info 文件读取配置
    source "$info_file"
    
    local inbound_json
    
    # === 自动检测是否安装了主协议 (Vision/Trojan/Reality) ===
    local has_master=false
    if [[ -f "$CFG/vless-vision.info" || -f "$CFG/vless.info" || -f "$CFG/trojan.info" ]]; then
        has_master=true
    fi

    # === 自动检测是否安装了副协议 (WS) 以便配置回落 ===
    local ws_fallback_entries=""

    # 1) vless-ws 回落
    if [[ -f "$CFG/vless-ws.info" ]]; then
        local ws_port=$(grep "^port=" "$CFG/vless-ws.info" | cut -d= -f2)
        local ws_path=$(grep "^path=" "$CFG/vless-ws.info" | cut -d= -f2)
        if [[ -n "$ws_port" && -n "$ws_path" ]]; then
            ws_fallback_entries+=",{\"path\": \"$ws_path\", \"dest\": $ws_port, \"xver\": 0}"
        fi
    fi

    # 2) vmess-ws 回落
    if [[ -f "$CFG/vmess-ws.info" ]]; then
        local vmess_port=$(grep "^port=" "$CFG/vmess-ws.info" | cut -d= -f2)
        local vmess_path=$(grep "^path=" "$CFG/vmess-ws.info" | cut -d= -f2)
        if [[ -n "$vmess_port" && -n "$vmess_path" ]]; then
            ws_fallback_entries+=",{\"path\": \"$vmess_path\", \"dest\": $vmess_port, \"xver\": 0}"
        fi
    fi
    
    # 构建 fallback 数组
    local fallback_array='[{"dest": "127.0.0.1:80", "xver": 0}'
    if [[ -n "$ws_fallback_entries" ]]; then
        fallback_array+="$ws_fallback_entries"
    fi
    fallback_array+=']'

    case "$protocol" in
        vless)
            # Reality (主协议)
            inbound_json=$(cat << EOF
{
    "port": $port, "listen": "::", "protocol": "vless",
    "settings": {
        "clients": [{"id": "$uuid", "flow": "xtls-rprx-vision"}], 
        "decryption": "none"
    },
    "streamSettings": {
        "network": "tcp", "security": "reality",
        "realitySettings": {"show": false, "dest": "$sni:443", "xver": 0, "serverNames": ["$sni"], "privateKey": "$private_key", "shortIds": ["$short_id"]}
    },
    "sniffing": {"enabled": true, "destOverride": ["http", "tls"]},
    "tag": "vless-reality"
}
EOF
)
            ;;
        vless-vision)
            # Vision (主协议) - 使用预构建的 fallback_array
            inbound_json=$(cat << EOF
{
    "port": $port, "listen": "::", "protocol": "vless",
    "settings": {
        "clients": [{"id": "$uuid", "flow": "xtls-rprx-vision"}],
        "decryption": "none",
        "fallbacks": $fallback_array
    },
    "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
            "rejectUnknownSni": false,
            "minVersion": "1.2",
            "alpn": ["h2", "http/1.1"],
            "certificates": [{
                "certificateFile": "$CFG/certs/server.crt",
                "keyFile": "$CFG/certs/server.key"
            }]
        }
    },
    "tag": "vless-vision"
}
EOF
)
            ;;
        vless-ws)
            # WS (副协议) - 关键修改：如果存在主协议，则降级为内部非 TLS 模式
            if [[ "$has_master" == "true" ]]; then
                # === 融合模式：监听本地，关闭 TLS，等待 Vision 回落 ===
                inbound_json=$(cat << EOF
{
    "port": $port, "listen": "127.0.0.1", "protocol": "vless",
    "settings": {
        "clients": [{"id": "$uuid"}], 
        "decryption": "none"
    },
    "streamSettings": {
        "network": "ws",
        "security": "none", 
        "wsSettings": {"path": "$path", "headers": {"Host": "$sni"}}
    },
    "sniffing": {"enabled": true, "destOverride": ["http", "tls"]},
    "tag": "vless-ws"
}
EOF
)
            else
                # === 独立模式：保持原样 (监听 0.0.0.0, 开启 TLS) ===
                inbound_json=$(cat << EOF
{
    "port": $port, "listen": "::", "protocol": "vless",
    "settings": {
        "clients": [{"id": "$uuid"}], 
        "decryption": "none",
        "fallbacks": [{"dest": "127.0.0.1:80", "xver": 0}]
    },
    "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
            "certificates": [{
                "certificateFile": "$CFG/certs/server.crt",
                "keyFile": "$CFG/certs/server.key"
            }]
        },
        "wsSettings": {"path": "$path", "headers": {"Host": "$sni"}}
    },
    "sniffing": {"enabled": true, "destOverride": ["http", "tls"]},
    "tag": "vless-ws"
}
EOF
)
            fi
            ;;
        vless-xhttp)
            # Reality+XHTTP协议不需要fallback，因为它会伪装成目标网站
            inbound_json=$(cat << EOF
{
    "port": $port, "listen": "::", "protocol": "vless",
    "settings": {
        "clients": [{"id": "$uuid"}], 
        "decryption": "none"
    },
    "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
            "path": "$path", 
            "mode": "auto",
            "host": "$sni"
        },
        "security": "reality",
        "realitySettings": {"show": false, "dest": "$sni:443", "xver": 0, "serverNames": ["$sni"], "privateKey": "$private_key", "shortIds": ["$short_id"]}
    },
    "sniffing": {"enabled": true, "destOverride": ["http", "tls"]},
    "tag": "vless-xhttp"
}
EOF
)
            ;;
        vmess-ws)
            if [[ "$has_master" == "true" ]]; then
                # 回落子协议：内部监听
                inbound_json=$(cat << EOF
{
    "port": $port, "listen": "127.0.0.1", "protocol": "vmess",
    "settings": {
        "clients": [{"id": "$uuid", "alterId": 0, "security": "auto"}]
    },
    "streamSettings": {
        "network": "ws", "security": "none",
        "wsSettings": {"path": "$path", "headers": {"Host": "$sni"}}
    },
    "tag": "vmess-ws"
}
EOF
)
            else
                # 独立运行：自己走 ws+tls（证书沿用脚本现有证书目录）
                inbound_json=$(cat << EOF
{
    "port": $port, "listen": "::", "protocol": "vmess",
    "settings": {
        "clients": [{"id": "$uuid", "alterId": 0, "security": "auto"}]
    },
    "streamSettings": {
        "network": "ws", "security": "tls",
        "tlsSettings": {
            "certificates": [{"certificateFile": "$CFG/certs/server.crt", "keyFile": "$CFG/certs/server.key"}],
            "alpn": ["http/1.1"]
        },
        "wsSettings": {"path": "$path", "headers": {"Host": "$sni"}}
    },
    "tag": "vmess-ws"
}
EOF
)
            fi
            ;;
        vless-grpc)
            # VLESS+gRPC+TLS (独立协议，支持 CDN)
            inbound_json=$(cat << EOF
{
    "port": $port, "listen": "::", "protocol": "vless",
    "settings": {
        "clients": [{"id": "$uuid"}],
        "decryption": "none"
    },
    "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
            "certificates": [{
                "certificateFile": "$CFG/certs/server.crt",
                "keyFile": "$CFG/certs/server.key"
            }],
            "alpn": ["h2"]
        },
        "grpcSettings": {
            "serviceName": "$path"
        }
    },
    "sniffing": {"enabled": true, "destOverride": ["http", "tls"]},
    "tag": "vless-grpc"
}
EOF
)
            ;;
        trojan)
            # Trojan (主协议) - 使用预构建的 fallback_array，支持 WS 回落
            inbound_json=$(cat << EOF
{
    "port": $port, "listen": "::", "protocol": "trojan",
    "settings": {
        "clients": [{"password": "$password"}],
        "fallbacks": $fallback_array
    },
    "streamSettings": {
        "network": "tcp", "security": "tls",
        "tlsSettings": {
            "certificates": [{
                "certificateFile": "$CFG/certs/server.crt",
                "keyFile": "$CFG/certs/server.key"
            }]
        }
    },
    "tag": "trojan"
}
EOF
)
            ;;
        socks)
            inbound_json=$(cat << EOF
{
    "port": $port, "listen": "::", "protocol": "socks",
    "settings": {
        "auth": "password",
        "accounts": [{"user": "$username", "pass": "$password"}],
        "udp": true,
        "ip": "::"
    },
    "tag": "socks5"
}
EOF
)
            ;;
        ss2022)
            inbound_json=$(cat << EOF
{
    "port": $port, "listen": "::", "protocol": "shadowsocks",
    "settings": {
        "method": "$method",
        "password": "$password",
        "network": "tcp,udp"
    },
    "tag": "ss2022"
}
EOF
)
            ;;
    esac
    
    if [[ -n "$inbound_json" ]]; then
        local temp_config=$(mktemp)
        if ! echo "$inbound_json" | jq -c '.' > /tmp/inbound.json 2>/dev/null; then
            _err "生成的 $protocol inbound JSON 格式错误"
            echo "$inbound_json"
            return 1
        fi
        if ! jq '.inbounds += [input]' "$CFG/config.json" /tmp/inbound.json > "$temp_config" 2>/dev/null; then
            _err "合并 $protocol 配置到 Xray 配置文件失败"
            rm -f /tmp/inbound.json "$temp_config"
            return 1
        fi
        mv "$temp_config" "$CFG/config.json"
        rm -f /tmp/inbound.json
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 基础工具函数
#═══════════════════════════════════════════════════════════════════════════════
_line()  { echo -e "${D}─────────────────────────────────────────────${NC}"; }
_dline() { echo -e "${C}═════════════════════════════════════════════${NC}"; }
_info()  { echo -e "  ${C}▸${NC} $1"; }
_ok()    { echo -e "  ${G}✓${NC} $1"; }
_err()   { echo -e "  ${R}✗${NC} $1"; }
_warn()  { echo -e "  ${Y}!${NC} $1"; }
_item()  { echo -e "  ${G}$1${NC}) $2"; }
_pause() { echo ""; read -rp "  按回车继续..."; }

_header() {
    clear; echo ""
    _dline
    echo -e "      ${W}多协议代理${NC} ${D}一键部署${NC} ${C}v${VERSION}${NC}"
    echo -e "      ${D}作者: ${AUTHOR}  快捷命令: vless${NC}"
    echo -e "      ${D}${REPO_URL}${NC}"
    _dline
}

# 安全加载配置文件，自动清除可能的变量污染
# 用法: safe_source_config "$CFG/${protocol}.info" || { _err "配置加载失败"; return 1; }
safe_source_config() {
    local config_file="$1"
    
    # 检查文件是否存在
    [[ ! -f "$config_file" ]] && return 1
    
    # 清除常用配置变量，避免污染
    unset uuid port sni short_id public_key private_key path
    unset password username method psk version
    unset ipv4 ipv6 server_ip stls_password ss_backend_port
    unset hop_enable hop_start hop_end outer_port
    unset sub_uuid sub_port sub_domain sub_https
    
    # 加载配置
    source "$config_file"
    return 0
}

get_protocol() {
    # 多协议模式下返回主协议或第一个协议
    if [[ -f "$CFG/installed_protocols" ]]; then
        # 优先返回 Xray 主协议
        for proto in vless vless-vision vless-ws vless-xhttp trojan socks ss2022; do
            if grep -q "^$proto$" "$CFG/installed_protocols" 2>/dev/null; then
                echo "$proto"
                return
            fi
        done
        # 返回第一个已安装的协议
        head -1 "$CFG/installed_protocols" 2>/dev/null
    elif [[ -f "$CFG/protocol" ]]; then
        cat "$CFG/protocol"
    else
        echo "vless"
    fi
}

get_protocol_name() {
    case "$1" in
        vless) echo "VLESS+Reality" ;;
        vless-xhttp) echo "VLESS+Reality+XHTTP" ;;
        vless-vision) echo "VLESS-XTLS-Vision" ;;
        vless-ws) echo "VLESS+WS+TLS" ;;
        vless-grpc) echo "VLESS+gRPC+TLS" ;;
        vmess-ws) echo "VMess+WS" ;;
        ss2022) echo "Shadowsocks 2022" ;;
        hy2) echo "Hysteria2" ;;
        trojan) echo "Trojan" ;;
        snell) echo "Snell v4" ;;
        snell-v5) echo "Snell v5" ;;
        tuic) echo "TUIC v5" ;;
        socks) echo "SOCKS5" ;;
        anytls) echo "AnyTLS" ;;
        shadowtls) echo "ShadowTLS" ;;
        *) echo "未知" ;;
    esac
}

check_root()      { [[ $EUID -ne 0 ]] && { _err "请使用 root 权限运行"; exit 1; }; }
check_cmd()       { command -v "$1" &>/dev/null; }
check_installed() { [[ -d "$CFG" && ( -f "$CFG/config.json" || -f "$CFG/config.yaml" || -f "$CFG/config.conf" || -f "$CFG/info" ) ]]; }
get_role()        { [[ -f "$CFG/role" ]] && cat "$CFG/role" || echo ""; }
get_mode()        { [[ -f "$CFG/mode" ]] && cat "$CFG/mode" || echo "tun"; }
is_paused()       { [[ -f "$CFG/paused" ]]; }

get_mode_name() {
    case "$1" in
        tun) echo "TUN网卡" ;;
        global) echo "全局代理" ;;
        socks) echo "SOCKS5代理" ;;
        *) echo "未知" ;;
    esac
}

#═══════════════════════════════════════════════════════════════════════════════
# 核心功能：强力清理 & 时间同步
#═══════════════════════════════════════════════════════════════════════════════
force_cleanup() {
    svc stop vless-watchdog 2>/dev/null
    svc stop vless-tun 2>/dev/null
    svc stop vless-global 2>/dev/null
    svc stop vless-reality 2>/dev/null
    killall tun2socks xray hysteria snell-server tuic-server 2>/dev/null
    ip link del tun0 2>/dev/null
    while ip rule show | grep -q "lookup 55"; do ip rule del lookup 55 2>/dev/null; done
    ip route flush table 55 2>/dev/null
    rm -f /tmp/vless-tun-info /tmp/vless-tun-routes
    
    # 清理 Hysteria2 端口跳跃 NAT 规则（从配置文件读取实际范围）
    if [[ -f "$CFG/hy2.info" ]]; then
        local hop_enable="" hop_start="" hop_end="" port=""
        source "$CFG/hy2.info" 2>/dev/null
        if [[ -n "$port" ]]; then
            local hs="${hop_start:-20000}"
            local he="${hop_end:-50000}"
            # 无论是否启用端口跳跃，都尝试清理可能存在的规则
            iptables -t nat -D PREROUTING -p udp --dport ${hs}:${he} -j REDIRECT --to-ports ${port} 2>/dev/null
            iptables -t nat -D OUTPUT -p udp --dport ${hs}:${he} -j REDIRECT --to-ports ${port} 2>/dev/null
        fi
    fi
    
    # 兜底清理：动态列出并删除所有 REDIRECT 规则（更彻底）
    # 清理 PREROUTING 链中的 REDIRECT 规则
    iptables -t nat -S PREROUTING 2>/dev/null | grep -E "REDIRECT.*--to-ports" | while read -r rule; do
        # 将 -A 替换为 -D 来删除规则
        local del_rule=$(echo "$rule" | sed 's/^-A/-D/')
        eval "iptables -t nat $del_rule" 2>/dev/null || true
    done
    
    # 清理 OUTPUT 链中的 REDIRECT 规则
    iptables -t nat -S OUTPUT 2>/dev/null | grep -E "REDIRECT.*--to-ports" | while read -r rule; do
        local del_rule=$(echo "$rule" | sed 's/^-A/-D/')
        eval "iptables -t nat $del_rule" 2>/dev/null || true
    done
    
    iptables -t nat -D OUTPUT -p tcp -j VLESS_PROXY 2>/dev/null
    iptables -t nat -F VLESS_PROXY 2>/dev/null
    iptables -t nat -X VLESS_PROXY 2>/dev/null
    ip6tables -t nat -D OUTPUT -p tcp -j VLESS_PROXY 2>/dev/null
    ip6tables -t nat -F VLESS_PROXY 2>/dev/null
    ip6tables -t nat -X VLESS_PROXY 2>/dev/null
}

sync_time() {
    _info "同步系统时间..."
    
    # 方法1: 使用HTTP获取时间 (最快最可靠)
    local http_time=$(timeout 5 curl -sI --connect-timeout 3 --max-time 5 http://www.baidu.com 2>/dev/null | grep -i "^date:" | cut -d' ' -f2-)
    if [[ -n "$http_time" ]]; then
        if date -s "$http_time" &>/dev/null; then
            _ok "时间同步完成 (HTTP)"
            return 0
        fi
    fi
    
    # 方法2: 使用ntpdate (如果可用)
    if command -v ntpdate &>/dev/null; then
        if timeout 5 ntpdate -s pool.ntp.org &>/dev/null; then
            _ok "时间同步完成 (NTP)"
            return 0
        fi
    fi
    
    # 方法3: 使用timedatectl (systemd系统)
    if command -v timedatectl &>/dev/null; then
        if timeout 5 timedatectl set-ntp true &>/dev/null; then
            _ok "时间同步完成 (systemd)"
            return 0
        fi
    fi
    
    # 如果所有方法都失败，跳过时间同步
    _warn "时间同步失败，继续安装..."
    return 0
}

#═══════════════════════════════════════════════════════════════════════════════
# 多协议管理函数
#═══════════════════════════════════════════════════════════════════════════════

# 列出已安装的协议 (兼容函数，实际使用 get_installed_protocols)
list_installed_protocols() {
    get_installed_protocols
}

# 查看已安装协议配置 (已整合到 show_all_protocols_info)
# list_and_show_configs() - 已删除，使用 show_all_protocols_info 替代

# 显示特定协议配置 (已整合到 show_single_protocol_info)
# show_protocol_config() - 已删除，使用 show_single_protocol_info 替代

# 管理服务菜单 (已整合到 manage_protocol_services)
# manage_services() - 已删除，使用 manage_protocol_services 替代

# 以下服务管理函数已整合到 start_services/stop_services
# start_all_protocol_services() - 已删除
# stop_all_protocol_services() - 已删除  
# restart_all_protocol_services() - 已删除

# 旧的卸载函数已删除，使用 uninstall_specific_protocol() 替代

#═══════════════════════════════════════════════════════════════════════════════
# 网络工具
#═══════════════════════════════════════════════════════════════════════════════
get_ipv4() { curl -4 -sf --connect-timeout 5 ip.sb 2>/dev/null || curl -4 -sf --connect-timeout 5 ifconfig.me 2>/dev/null; }
get_ipv6() { curl -6 -sf --connect-timeout 5 ip.sb 2>/dev/null || curl -6 -sf --connect-timeout 5 ifconfig.me 2>/dev/null; }

# 通过DNS检查域名的IP解析 (兼容性增强)
check_domain_dns() {
    local domain=$1
    local dns_ip=""
    local ip_type=4
    local public_ip=""
    
    # 优先使用 dig
    if command -v dig &>/dev/null; then
        dns_ip=$(dig @1.1.1.1 +time=2 +short "$domain" 2>/dev/null | grep -E "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$" | head -1)
        
        # 如果Cloudflare DNS失败，尝试Google DNS
        if [[ -z "$dns_ip" ]]; then
            dns_ip=$(dig @8.8.8.8 +time=2 +short "$domain" 2>/dev/null | grep -E "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$" | head -1)
        fi
    fi
    
    # 回退到 nslookup
    if [[ -z "$dns_ip" ]] && command -v nslookup &>/dev/null; then
        dns_ip=$(nslookup "$domain" 1.1.1.1 2>/dev/null | awk '/^Address: / { print $2 }' | grep -v "1.1.1.1" | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" | head -1)
    fi
    
    # 回退到 getent
    if [[ -z "$dns_ip" ]] && command -v getent &>/dev/null; then
        dns_ip=$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | head -1)
    fi
    
    # 如果IPv4解析失败，尝试IPv6
    if [[ -z "$dns_ip" ]] || echo "$dns_ip" | grep -q "timed out"; then
        _warn "无法通过DNS获取域名 IPv4 地址"
        _info "尝试检查域名 IPv6 地址..."
        
        if command -v dig &>/dev/null; then
            dns_ip=$(dig @2606:4700:4700::1111 +time=2 aaaa +short "$domain" 2>/dev/null | head -1)
        elif command -v getent &>/dev/null; then
            dns_ip=$(getent ahostsv6 "$domain" 2>/dev/null | awk '{print $1}' | head -1)
        fi
        ip_type=6
        
        if [[ -z "$dns_ip" ]] || echo "$dns_ip" | grep -q "network unreachable"; then
            _err "无法通过DNS获取域名IPv6地址"
            return 1
        fi
    fi
    
    # 获取服务器公网IP
    if [[ $ip_type -eq 4 ]]; then
        public_ip=$(get_ipv4)
    else
        public_ip=$(get_ipv6)
    fi
    
    # 比较DNS解析IP与服务器IP
    if [[ "$public_ip" != "$dns_ip" ]]; then
        _err "域名解析IP与当前服务器IP不一致"
        _warn "请检查域名解析是否生效以及正确"
        echo -e "  ${G}当前VPS IP：${NC}$public_ip"
        echo -e "  ${G}DNS解析 IP：${NC}$dns_ip"
        return 1
    else
        _ok "域名IP校验通过"
        return 0
    fi
}

gen_uuid()  { cat /proc/sys/kernel/random/uuid 2>/dev/null || printf '%04x%04x-%04x-%04x-%04x-%04x%04x%04x\n' $RANDOM $RANDOM $RANDOM $(($RANDOM&0x0fff|0x4000)) $(($RANDOM&0x3fff|0x8000)) $RANDOM $RANDOM $RANDOM; }

# === 新增函数：检查脚本内部记录的端口占用 ===
# 返回 0 表示被占用，1 表示未被占用
is_internal_port_occupied() {
    local check_port="$1"
    # 遍历所有已安装协议的 info 文件
    for info_file in "$CFG"/*.info; do
        [[ ! -f "$info_file" ]] && continue
        
        # 读取该协议使用的端口
        local used_port=$(grep "^port=" "$info_file" | cut -d= -f2)
        
        # 如果端口匹配
        if [[ "$used_port" == "$check_port" ]]; then
            # 获取协议名称用于提示
            local proto_name=$(basename "$info_file" .info)
            echo "$proto_name" # 输出占用该端口的协议名
            return 0
        fi
    done
    return 1
}

# 优化后的端口生成函数 - 增加端口冲突检测和最大尝试次数
gen_port() {
    local port
    local max_attempts=100  # 最大尝试次数，防止无限循环
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        port=$(shuf -i 10000-60000 -n 1 2>/dev/null || echo $((RANDOM % 50000 + 10000)))
        # 检查端口是否被占用 (TCP 和 UDP)
        if ! ss -tuln 2>/dev/null | grep -q ":$port " && ! netstat -tuln 2>/dev/null | grep -q ":$port "; then
            echo "$port"
            return 0
        fi
        ((attempt++))
    done
    
    # 达到最大尝试次数，返回一个随机端口并警告
    _warn "无法找到空闲端口（尝试 $max_attempts 次），使用随机端口" >&2
    echo "$port"
    return 1
}

# 智能端口推荐
# 参数: $1=协议类型
recommend_port() {
    local protocol="$1"
    
    # 检查是否已安装主协议（Vision/Trojan/Reality），用于判断 WS 协议是否为回落子协议
    local has_master=false
    if [[ -f "$CFG/vless-vision.info" || -f "$CFG/vless.info" || -f "$CFG/trojan.info" ]]; then
        has_master=true
    fi
    
    case "$protocol" in
        vless-ws|vmess-ws)
            # 如果已有主协议，这些是回落子协议，监听本地，随机端口即可
            if [[ "$has_master" == "true" ]]; then
                gen_port
            else
                # 独立运行时才需要 HTTPS 端口
                if ! ss -tuln 2>/dev/null | grep -q ":443 " && ! is_internal_port_occupied "443" >/dev/null; then
                    echo "443"
                elif ! ss -tuln 2>/dev/null | grep -q ":8443 " && ! is_internal_port_occupied "8443" >/dev/null; then
                    echo "8443"
                else
                    gen_port
                fi
            fi
            ;;
        vless|vless-xhttp|vless-vision|trojan|anytls|shadowtls)
            # 这些协议需要对外暴露，优先使用 HTTPS 端口
            if ! ss -tuln 2>/dev/null | grep -q ":443 " && ! is_internal_port_occupied "443" >/dev/null; then
                echo "443"
            elif ! ss -tuln 2>/dev/null | grep -q ":8443 " && ! is_internal_port_occupied "8443" >/dev/null; then
                echo "8443"
            elif ! ss -tuln 2>/dev/null | grep -q ":2096 " && ! is_internal_port_occupied "2096" >/dev/null; then
                echo "2096"
            else
                gen_port
            fi
            ;;
        hy2|tuic)
            # UDP 协议直接随机
            while true; do
                local p=$(gen_port)
                if ! is_internal_port_occupied "$p" >/dev/null; then
                    echo "$p"
                    break
                fi
            done
            ;;
        *)
            gen_port
            ;;
    esac
}

# 交互式端口选择
ask_port() {
    local protocol="$1"
    local recommend=$(recommend_port "$protocol")
    
    # 检查是否已安装主协议
    local has_master=false
    if [[ -f "$CFG/vless-vision.info" || -f "$CFG/vless.info" || -f "$CFG/trojan.info" ]]; then
        has_master=true
    fi
    
    echo "" >&2
    _line >&2
    echo -e "  ${W}端口配置${NC}" >&2
    
    # 根据协议类型和是否有主协议显示不同的提示
    case "$protocol" in
        vless-ws|vmess-ws)
            if [[ "$has_master" == "true" ]]; then
                # 回落子协议，内部端口
                echo -e "  ${D}(作为回落子协议，监听本地，外部通过 443 访问)${NC}" >&2
                echo -e "  ${C}建议: ${G}$recommend${NC} (内部端口，随机即可)" >&2
            elif [[ "$recommend" == "443" ]]; then
                echo -e "  ${C}建议: ${G}443${NC} (标准 HTTPS 端口)" >&2
            else
                local owner_443=$(is_internal_port_occupied "443")
                if [[ -n "$owner_443" ]]; then
                    echo -e "  ${Y}注意: 443 端口已被 [$owner_443] 协议占用${NC}" >&2
                fi
                echo -e "  ${C}建议: ${G}$recommend${NC} (已自动避开冲突)" >&2
            fi
            ;;
        vless|vless-xhttp|vless-vision|trojan)
            if [[ "$recommend" == "443" ]]; then
                echo -e "  ${C}建议: ${G}443${NC} (标准 HTTPS 端口)" >&2
            else
                local owner_443=$(is_internal_port_occupied "443")
                if [[ -n "$owner_443" ]]; then
                    echo -e "  ${Y}注意: 443 端口已被 [$owner_443] 协议占用${NC}" >&2
                fi
                echo -e "  ${C}建议: ${G}$recommend${NC} (已自动避开冲突)" >&2
            fi
            ;;
        *)
            echo -e "  ${C}建议: ${G}$recommend${NC}" >&2
            ;;
    esac
    
    echo "" >&2
    
    while true; do
        read -rp "  请输入端口 [回车使用 $recommend]: " custom_port
        
        # 如果用户直接回车，使用推荐端口
        if [[ -z "$custom_port" ]]; then
            custom_port="$recommend"
        fi
        
        # 0. 验证端口格式 (必须是1-65535的数字)
        if ! [[ "$custom_port" =~ ^[0-9]+$ ]] || [[ $custom_port -lt 1 ]] || [[ $custom_port -gt 65535 ]]; then
            _err "无效端口: $custom_port" >&2
            _warn "端口必须是 1-65535 之间的数字" >&2
            continue # 跳过本次循环，让用户重输
        fi
        
        # 0.1 检查是否使用了系统保留端口
        if [[ $custom_port -lt 1024 && $custom_port -ne 80 && $custom_port -ne 443 ]]; then
            _warn "端口 $custom_port 是系统保留端口，可能需要特殊权限" >&2
            read -rp "  是否继续使用? [y/N]: " use_reserved
            if [[ ! "$use_reserved" =~ ^[yY]$ ]]; then
                continue
            fi
        fi
        
        # 1. 检查是否被脚本内部其他协议占用 (最重要的一步！)
        local conflict_proto=$(is_internal_port_occupied "$custom_port")
        if [[ -n "$conflict_proto" ]]; then
            _err "端口 $custom_port 已被已安装的 [$conflict_proto] 占用！" >&2
            _warn "不同协议不能共用同一端口，请更换其他端口。" >&2
            continue # 跳过本次循环，让用户重输
        fi
        
        # 2. 检查系统端口占用 (Nginx 等外部程序)
        if ss -tuln 2>/dev/null | grep -q ":$custom_port " || netstat -tuln 2>/dev/null | grep -q ":$custom_port "; then
            _warn "端口 $custom_port 系统占用中" >&2
            read -rp "  是否强制使用? (可能导致启动失败) [y/N]: " force
            if [[ "$force" =~ ^[yY]$ ]]; then
                echo "$custom_port"
                return
            else
                continue
            fi
        else
            # 端口干净，通过
            echo "$custom_port"
            return
        fi
    done
}

# 生成 ShortID (兼容无 xxd 的系统)
gen_sid() {
    if command -v xxd &>/dev/null; then
        head -c 4 /dev/urandom 2>/dev/null | xxd -p
    elif command -v od &>/dev/null; then
        head -c 4 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n'
    else
        printf '%08x' $RANDOM
    fi
}

# 清理被污染的配置文件
clean_corrupted_info_files() {
    local info_files=("$CFG"/*.info)
    for info_file in "${info_files[@]}"; do
        [[ ! -f "$info_file" ]] && continue
        
        # 检查文件是否包含颜色代码或特殊字符 (兼容性修复)
        # 使用 $'\x1b' 语法正确匹配 ANSI 转义序列
        if grep -q $'\x1b\[' "$info_file" 2>/dev/null || grep -qE '[▸✓✗]' "$info_file" 2>/dev/null; then
            local proto=$(basename "$info_file" .info)
            _warn "检测到损坏的配置文件: $info_file"
            _info "正在清理..."
            
            # 提取有效的配置行（只保留 key=value 格式的行）
            local temp_file=$(mktemp)
            grep '^[a-zA-Z_][a-zA-Z0-9_]*=' "$info_file" > "$temp_file" 2>/dev/null || true
            
            if [[ -s "$temp_file" ]]; then
                mv "$temp_file" "$info_file"
                _ok "配置文件已修复: $info_file"
            else
                rm -f "$info_file" "$temp_file"
                _warn "配置文件已删除（无有效配置）: $info_file"
            fi
        fi
    done
}

# 证书诊断函数
diagnose_certificate() {
    local domain="$1"
    
    echo ""
    _info "证书诊断报告："
    
    # 检查证书文件
    if [[ -f "$CFG/certs/server.crt" && -f "$CFG/certs/server.key" ]]; then
        _ok "证书文件存在"
        
        # 检查证书有效期
        local expiry=$(openssl x509 -in "$CFG/certs/server.crt" -noout -enddate 2>/dev/null | cut -d= -f2)
        if [[ -n "$expiry" ]]; then
            _ok "证书有效期: $expiry"
        fi
    else
        _err "证书文件不存在"
    fi
    
    # 检查端口监听
    if [[ -f "$CFG/vless-ws.info" ]]; then
        local port=""
        source "$CFG/vless-ws.info"
        if ss -tlnp | grep -q ":$port "; then
            _ok "端口 $port 正在监听"
        else
            _err "端口 $port 未监听"
        fi
    fi
    
    # DNS解析检查
    local resolved_ip=$(dig +short "$domain" 2>/dev/null | head -1)
    local server_ip=$(get_ipv4)
    if [[ "$resolved_ip" == "$server_ip" ]]; then
        _ok "DNS解析正确: $domain -> $resolved_ip"
    else
        _warn "DNS解析问题: $domain -> $resolved_ip (期望: $server_ip)"
    fi
    
    echo ""
}

# 创建伪装网页
create_fake_website() {
    local domain="$1"
    local protocol="$2"
    local custom_nginx_port="$3"  # 新增：自定义 Nginx 端口
    local web_dir="/var/www/html"
    
    # 根据系统确定 nginx 配置目录
    local nginx_conf_dir=""
    local nginx_conf_file=""
    if [[ -d "/etc/nginx/sites-available" ]]; then
        nginx_conf_dir="/etc/nginx/sites-available"
        nginx_conf_file="$nginx_conf_dir/vless-fake"
    elif [[ -d "/etc/nginx/conf.d" ]]; then
        nginx_conf_dir="/etc/nginx/conf.d"
        nginx_conf_file="$nginx_conf_dir/vless-fake.conf"
    elif [[ -d "/etc/nginx/http.d" ]]; then
        # Alpine
        nginx_conf_dir="/etc/nginx/http.d"
        nginx_conf_file="$nginx_conf_dir/vless-fake.conf"
    else
        nginx_conf_dir="/etc/nginx/conf.d"
        nginx_conf_file="$nginx_conf_dir/vless-fake.conf"
        mkdir -p "$nginx_conf_dir"
    fi
    
    # 删除旧配置，确保使用最新配置
    rm -f "$nginx_conf_file" /etc/nginx/sites-enabled/vless-fake 2>/dev/null
    # 同时删除可能冲突的 vless-sub.conf
    rm -f /etc/nginx/conf.d/vless-sub.conf 2>/dev/null
    
    # 创建网页目录
    mkdir -p "$web_dir"
    
    # 创建简单的伪装网页
    cat > "$web_dir/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        p { color: #666; line-height: 1.6; }
        .footer { text-align: center; margin-top: 40px; color: #999; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Our Website</h1>
        <p>This is a simple website hosted on our server. We provide various web services and solutions for our clients.</p>
        <p>Our team is dedicated to delivering high-quality web hosting and development services. Feel free to contact us for more information about our services.</p>
        <div class="footer">
            <p>&copy; 2024 Web Services. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
EOF
    
    # 检查是否有SSL证书，决定使用Nginx
    if [[ -n "$domain" ]] && [[ -f "/etc/vless-reality/certs/server.crt" ]]; then
        # 安装Nginx（如果未安装）
        if ! command -v nginx >/dev/null 2>&1; then
            _info "安装Nginx..."
            case "$DISTRO" in
                alpine) apk add --no-cache nginx >/dev/null 2>&1 ;;
                centos) yum install -y nginx >/dev/null 2>&1 ;;
                debian|ubuntu) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx >/dev/null 2>&1 ;;
            esac
        fi
        
        # 启用Nginx服务
        svc enable nginx 2>/dev/null
        
        # 根据协议选择Nginx监听端口和模式
        local nginx_port="80"
        local nginx_listen="127.0.0.1:$nginx_port"
        local nginx_comment="作为Xray的fallback后端"
        local nginx_ssl=""
        
        if [[ "$protocol" == "vless" || "$protocol" == "vless-xhttp" ]]; then
            # Reality协议：Nginx独立运行，提供HTTP订阅服务
            nginx_port="${custom_nginx_port:-8080}"
            nginx_listen="0.0.0.0:$nginx_port"
            nginx_comment="独立提供订阅服务 (HTTP)，不与Reality冲突"
        elif [[ "$protocol" == "vless-vision" || "$protocol" == "vless-ws" || "$protocol" == "vmess-ws" || "$protocol" == "trojan" ]]; then
            # 证书协议：Nginx 同时监听 80 (fallback) 和自定义端口 (HTTPS订阅)
            nginx_port="${custom_nginx_port:-8443}"
            nginx_listen="127.0.0.1:80"  # fallback 后端
            nginx_comment="80端口作为fallback，${nginx_port}端口提供HTTPS订阅"
            nginx_ssl="ssl"
        fi
        
        # 配置Nginx
        if [[ "$protocol" == "vless-vision" || "$protocol" == "vless-ws" || "$protocol" == "vmess-ws" || "$protocol" == "trojan" ]]; then
            # 证书协议：双端口配置
            cat > "$nginx_conf_file" << EOF
# Fallback 后端 (供 Xray 回落使用)
server {
    listen 127.0.0.1:80;
    server_name $domain;
    
    root $web_dir;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    server_tokens off;
}

# HTTPS 订阅服务 (独立端口)
server {
    listen 0.0.0.0:$nginx_port ssl http2;
    server_name $domain;
    
    ssl_certificate /etc/vless-reality/certs/server.crt;
    ssl_certificate_key /etc/vless-reality/certs/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    root $web_dir;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # 订阅文件目录 - v2ray 映射到 base64
    location ~ ^/sub/([a-f0-9-]+)/v2ray\$ {
        alias $CFG/subscription/\$1/base64;
        default_type text/plain;
        add_header Content-Type "text/plain; charset=utf-8";
    }
    
    # 订阅文件目录 - clash
    location ~ ^/sub/([a-f0-9-]+)/clash\$ {
        alias $CFG/subscription/\$1/clash.yaml;
        default_type text/yaml;
    }
    
    # 订阅文件目录 - surge
    location ~ ^/sub/([a-f0-9-]+)/surge\$ {
        alias $CFG/subscription/\$1/surge.conf;
        default_type text/plain;
    }
    
    # 订阅文件目录 - 通用
    location /sub/ {
        alias $CFG/subscription/;
        autoindex off;
        default_type text/plain;
    }
    
    server_tokens off;
}
EOF
        else
            # Reality协议：单端口配置
            cat > "$nginx_conf_file" << EOF
server {
    listen $nginx_listen;  # $nginx_comment
    server_name $domain;
    
    root $web_dir;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # 订阅文件目录 - v2ray 映射到 base64
    location ~ ^/sub/([a-f0-9-]+)/v2ray\$ {
        alias $CFG/subscription/\$1/base64;
        default_type text/plain;
        add_header Content-Type "text/plain; charset=utf-8";
    }
    
    # 订阅文件目录 - clash
    location ~ ^/sub/([a-f0-9-]+)/clash\$ {
        alias $CFG/subscription/\$1/clash.yaml;
        default_type text/yaml;
    }
    
    # 订阅文件目录 - surge
    location ~ ^/sub/([a-f0-9-]+)/surge\$ {
        alias $CFG/subscription/\$1/surge.conf;
        default_type text/plain;
    }
    
    # 订阅文件目录 - 通用
    location /sub/ {
        alias $CFG/subscription/;
        autoindex off;
        default_type text/plain;
    }
    
    # 隐藏Nginx版本
    server_tokens off;
}
EOF
        fi
        
        # 如果使用 sites-available 模式，创建软链接
        if [[ "$nginx_conf_dir" == "/etc/nginx/sites-available" ]]; then
            mkdir -p /etc/nginx/sites-enabled
            rm -f /etc/nginx/sites-enabled/default
            ln -sf "$nginx_conf_file" /etc/nginx/sites-enabled/vless-fake
        fi
        
        # 测试Nginx配置
        _info "配置Nginx并启动Web服务..."
        if nginx -t 2>/dev/null; then
            # 强制重启 Nginx 确保新配置生效（直接用 systemctl，更可靠）
            if [[ "$DISTRO" == "alpine" ]]; then
                rc-service nginx stop 2>/dev/null
                sleep 1
                rc-service nginx start 2>/dev/null
            else
                systemctl stop nginx 2>/dev/null
                sleep 1
                systemctl start nginx 2>/dev/null
            fi
            sleep 1
            
            # 验证端口是否监听（兼容不同系统）
            local port_listening=false
            if ss -tlnp 2>/dev/null | grep -qE ":${nginx_port}\s|:${nginx_port}$"; then
                port_listening=true
            elif netstat -tlnp 2>/dev/null | grep -q ":${nginx_port} "; then
                port_listening=true
            fi
            
            # 检查服务状态
            local nginx_running=false
            if [[ "$DISTRO" == "alpine" ]]; then
                rc-service nginx status &>/dev/null && nginx_running=true
            else
                systemctl is-active nginx &>/dev/null && nginx_running=true
            fi
            
            if [[ "$nginx_running" == "true" && "$port_listening" == "true" ]]; then
                _ok "伪装网页已创建并启动"
                _ok "Web服务器运行正常，订阅链接可用"
                if [[ "$protocol" == "vless" || "$protocol" == "vless-xhttp" ]]; then
                    _ok "伪装网页: http://$domain:$nginx_port"
                elif [[ "$protocol" == "vless-vision" || "$protocol" == "vless-ws" || "$protocol" == "vmess-ws" || "$protocol" == "trojan" ]]; then
                    _ok "伪装网页: https://$domain:$nginx_port"
                fi
                echo -e "  ${D}提示: 自定义伪装网页请将 HTML 文件放入 $web_dir${NC}"
            elif [[ "$nginx_running" == "true" ]]; then
                _ok "伪装网页已创建"
                _warn "端口 $nginx_port 未监听，请检查 Nginx 配置"
            else
                _ok "伪装网页已创建"
                _warn "Nginx 服务未运行，请手动启动: systemctl start nginx"
            fi
        else
            _warn "Nginx配置测试失败"
            echo "配置错误详情："
            nginx -t
            rm -f "$nginx_conf_file" /etc/nginx/sites-enabled/vless-fake 2>/dev/null
        fi
    fi
    
}

gen_sni() { 
    # 精简的稳定 SNI 列表（国内可访问、常用、不易被封）
    local s=(
        "www.microsoft.com" "www.apple.com" "www.cloudflare.com" 
        "www.amazon.com" "gateway.icloud.com" "www.bing.com"
    )
    echo "${s[$((RANDOM % ${#s[@]}))]}"
}

gen_xhttp_path() {
    # 生成随机XHTTP路径，避免与Web服务器默认路由冲突
    local path="/$(head -c 32 /dev/urandom 2>/dev/null | base64 | tr -d '/+=' | head -c 8)"
    # 确保路径不为空
    if [[ -z "$path" || "$path" == "/" ]]; then
        path="/xhttp$(printf '%04x' $RANDOM)"
    fi
    echo "$path"
}
gen_password() { head -c 16 /dev/urandom 2>/dev/null | base64 | tr -d '/+=' | head -c 16 || printf '%s%s' $RANDOM $RANDOM | md5sum | head -c 16; }

urlencode() {
    local s="$1" i c o=""
    for ((i=0; i<${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            [-_.~a-zA-Z0-9]) o+="$c" ;;
            *) printf -v c '%%%02x' "'$c"; o+="$c" ;;
        esac
    done
    echo "$o"
}

gen_vless_link() {
    local ip="$1" port="$2" uuid="$3" pbk="$4" sid="$5" sni="$6"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=reality&type=tcp&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&flow=xtls-rprx-vision#${uuid:0:8}-reality"
}

gen_vless_xhttp_link() {
    local ip="$1" port="$2" uuid="$3" pbk="$4" sid="$5" sni="$6" path="${7:-/}"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=reality&type=xhttp&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&path=$(urlencode "$path")&mode=auto#${uuid:0:8}-reality-xhttp"
}

gen_vmess_ws_link() {
    local ip="$1" port="$2" uuid="$3" sni="$4" path="$5"
    local clean_ip="${ip#[}"
    clean_ip="${clean_ip%]}"

    # VMess ws 链接：vmess://base64(json)
    # 注意：allowInsecure=true 允许自签名证书
    local json
    json=$(cat <<EOF
{"v":"2","ps":"VMess-WS-${clean_ip}","add":"${clean_ip}","port":"${port}","id":"${uuid}","aid":"0","scy":"auto","net":"ws","type":"none","host":"${sni}","path":"${path}","tls":"tls","sni":"${sni}","allowInsecure":true}
EOF
)
    printf 'vmess://%s\n' "$(echo -n "$json" | base64 -w 0 2>/dev/null || echo -n "$json" | base64 | tr -d '\n')"
}

gen_qr() { printf '%s\n' "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=$(urlencode "$1")"; }



# 生成各协议分享链接
gen_hy2_link() {
    local ip="$1" port="$2" password="$3" sni="$4"
    # 链接始终使用实际端口，端口跳跃需要客户端手动配置
    printf '%s\n' "hysteria2://${password}@${ip}:${port}?sni=${sni}&insecure=1#HY2-${ip}"
}

gen_trojan_link() {
    local ip="$1" port="$2" password="$3" sni="$4"
    printf '%s\n' "trojan://${password}@${ip}:${port}?security=tls&sni=${sni}&type=tcp&allowInsecure=1#Trojan-${ip}"
}

gen_vless_ws_link() {
    local ip="$1" port="$2" uuid="$3" sni="$4" path="${5:-/}"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=tls&sni=${sni}&type=ws&host=${sni}&path=$(urlencode "$path")&allowInsecure=1#VLESS-WS-${ip}"
}

gen_vless_grpc_link() {
    local ip="$1" port="$2" uuid="$3" sni="$4" service_name="${5:-grpc}"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=tls&sni=${sni}&type=grpc&serviceName=${service_name}&allowInsecure=1#VLESS-gRPC-${ip}"
}

gen_vless_vision_link() {
    local ip="$1" port="$2" uuid="$3" sni="$4"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=tls&sni=${sni}&type=tcp&flow=xtls-rprx-vision&allowInsecure=1#VLESS-Vision-${ip}"
}

gen_ss2022_link() {
    local ip="$1" port="$2" method="$3" password="$4"
    local userinfo=$(printf '%s:%s' "$method" "$password" | base64 -w 0 2>/dev/null || printf '%s:%s' "$method" "$password" | base64)
    printf '%s\n' "ss://${userinfo}@${ip}:${port}#SS2022-${ip}"
}

gen_snell_link() {
    local ip="$1" port="$2" psk="$3" version="${4:-4}"
    # Snell 没有标准URI格式，使用自定义格式
    printf '%s\n' "snell://${psk}@${ip}:${port}?version=${version}#Snell-${ip}"
}

gen_tuic_link() {
    local ip="$1" port="$2" uuid="$3" password="$4" sni="$5"
    printf '%s\n' "tuic://${uuid}:${password}@${ip}:${port}?congestion_control=bbr&alpn=h3&sni=${sni}&udp_relay_mode=native&allow_insecure=1#TUIC-${ip}"
}

gen_anytls_link() {
    local ip="$1" port="$2" password="$3" sni="$4"
    printf '%s\n' "anytls://${password}@${ip}:${port}?sni=${sni}&allowInsecure=1#AnyTLS-${ip}"
}

gen_shadowtls_link() {
    local ip="$1" port="$2" password="$3" method="$4" sni="$5" stls_password="$6"
    # ShadowTLS链接格式：ss://method:password@server:port#name + ShadowTLS参数
    local ss_link=$(echo -n "${method}:${password}" | base64 -w 0)
    printf '%s\n' "ss://${ss_link}@${ip}:${port}?plugin=shadow-tls;host=${sni};password=${stls_password}#ShadowTLS-${ip}"
}

gen_snell_v5_link() {
    local ip="$1" port="$2" psk="$3" version="${4:-5}"
    # Snell v5 使用自定义格式
    printf '%s\n' "snell://${psk}@${ip}:${port}?version=${version}#Snell-v5-${ip}"
}

gen_socks_link() {
    local ip="$1" port="$2" username="$3" password="$4"
    if [[ -n "$username" && -n "$password" ]]; then
        # Telegram 格式的 SOCKS5 代理链接
        printf '%s\n' "https://t.me/socks?server=${ip}&port=${port}&user=${username}&pass=${password}"
    else
        printf '%s\n' "socks5://${ip}:${port}#SOCKS5-${ip}"
    fi
}

test_connection() {
    local role=$(get_role)
    if [[ "$role" == "server" ]]; then
        # 检查所有已安装协议的端口
        local installed=$(get_installed_protocols)
        for proto in $installed; do
            if [[ -f "$CFG/${proto}.info" ]]; then
                # 清除变量避免污染
                local port="" uuid="" password="" sni="" psk=""
                source "$CFG/${proto}.info"
                if ss -tlnp 2>/dev/null | grep -q ":$port " || ss -ulnp 2>/dev/null | grep -q ":$port "; then
                    _ok "$(get_protocol_name $proto) 端口 $port 已监听"
                else
                    _err "$(get_protocol_name $proto) 端口 $port 未监听"
                fi
            fi
        done
    else
        _info "验证代理效果..."
        
        # 先检查本地 SOCKS5 代理是否可用
        if ! ss -tlnp 2>/dev/null | grep -q ":$SOCKS_PORT "; then
            _err "本地 SOCKS5 代理未监听 (端口 $SOCKS_PORT)"
            return 1
        fi
        
        local start=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
        local result=$(curl -x socks5h://127.0.0.1:$SOCKS_PORT -sf -m 10 ip.sb 2>/dev/null)
        local end=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
        local latency=$((end - start))
        if [[ -n "$result" ]]; then
             local location=$(curl -x socks5h://127.0.0.1:$SOCKS_PORT -sf -m 5 "http://ip-api.com/line/$result?fields=country" 2>/dev/null)
             _ok "代理已生效!"
             echo -e "  出口IP: ${G}$result${NC} ${D}($location)${NC}  延迟: ${G}${latency}ms${NC}"
        else
             _err "代理连接超时，请检查服务端状态"
             # 显示调试信息
             echo -e "  ${D}调试: 检查客户端日志 journalctl -u vless-* -n 20${NC}"
        fi
    fi
}

test_latency() {
    local ip="$1" port="$2" proto="${3:-tcp}" start end
    start=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
    
    # UDP协议无法用TCP测试
    if [[ "$proto" == "hy2" || "$proto" == "tuic" ]]; then
        # 用ping测试基本延迟
        if ping -c 1 -W 2 "$ip" &>/dev/null; then
            end=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
            echo "$((end-start))ms"
        else
            echo "UDP"
        fi
    else
        # 优先使用 nc (netcat)，更通用且跨平台兼容性更好
        if command -v nc &>/dev/null; then
            if timeout 3 nc -z -w 2 "$ip" "$port" 2>/dev/null; then
                end=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
                echo "$((end-start))ms"
            else
                echo "超时"
            fi
        # 回退到 bash /dev/tcp（某些系统可能不支持）
        elif timeout 3 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            end=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
            echo "$((end-start))ms"
        else
            echo "超时"
        fi
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 安装依赖 (v3.3 适配 CentOS)
#═══════════════════════════════════════════════════════════════════════════════
install_deps() {
    _info "检查系统依赖..."
    if [[ "$DISTRO" == "alpine" ]]; then
        _info "更新软件包索引..."
        if ! timeout 60 apk update 2>&1 | grep -E '^(fetch|OK)' | sed 's/^/  /'; then
            if ! apk update &>/dev/null; then
                _err "更新软件包索引失败（可能超时）"
                return 1
            fi
        fi
        
        local deps="curl jq unzip iproute2 iptables ip6tables gcompat openssl socat bind-tools"
        _info "安装依赖: $deps"
        if ! timeout 180 apk add --no-cache $deps 2>&1 | grep -E '^(\(|OK|Installing|Executing)' | sed 's/^/  /'; then
            # 检查实际安装结果
            local missing=""
            for dep in $deps; do
                apk info -e "$dep" &>/dev/null || missing="$missing $dep"
            done
            if [[ -n "$missing" ]]; then
                _err "依赖安装失败:$missing"
                return 1
            fi
        fi
        _ok "依赖安装完成"
    elif [[ "$DISTRO" == "centos" ]]; then
        _info "安装 EPEL 源..."
        if ! timeout 120 yum install -y epel-release 2>&1 | grep -E '^(Installing|Verifying|Complete)' | sed 's/^/  /'; then
            if ! rpm -q epel-release &>/dev/null; then
                _err "EPEL 源安装失败（可能超时）"
                return 1
            fi
        fi
        
        local deps="curl jq unzip iproute iptables vim-common openssl socat bind-utils"
        _info "安装依赖: $deps"
        if ! timeout 300 yum install -y $deps 2>&1 | grep -E '^(Installing|Verifying|Complete|Downloading)' | sed 's/^/  /'; then
            # 检查实际安装结果
            local missing=""
            for dep in $deps; do
                rpm -q "$dep" &>/dev/null || missing="$missing $dep"
            done
            if [[ -n "$missing" ]]; then
                _err "依赖安装失败:$missing"
                return 1
            fi
        fi
        _ok "依赖安装完成"
    elif [[ "$DISTRO" == "debian" || "$DISTRO" == "ubuntu" ]]; then
        _info "更新软件包索引..."
        # 移除 -qq 让用户能看到进度，避免交互卡住
        if ! DEBIAN_FRONTEND=noninteractive apt-get update 2>&1 | grep -E '^(Hit|Get|Fetched|Reading)' | head -10 | sed 's/^/  /'; then
            # 即使 grep 没匹配到也继续，只要 apt-get 成功即可
            :
        fi
        
        local deps="curl jq unzip iproute2 xxd openssl socat dnsutils"
        _info "安装依赖: $deps"
        # 使用 DEBIAN_FRONTEND 避免交互，显示简化进度，移除 timeout 避免死锁
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y $deps 2>&1 | grep -E '^(Setting up|Unpacking|Processing|Get:|Fetched)' | sed 's/^/  /'; then
            # 检查实际安装结果
            if ! dpkg -l $deps >/dev/null 2>&1; then
                _err "依赖安装失败"
                return 1
            fi
        fi
        _ok "依赖安装完成"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# ACME 证书管理
#═══════════════════════════════════════════════════════════════════════════════

# 安装 acme.sh
install_acme_tool() {
    if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
        _ok "acme.sh 已安装"
        return 0
    fi
    
    _info "安装 acme.sh 证书申请工具..."
    if curl -s https://get.acme.sh | sh -s email=admin@example.com >/dev/null 2>&1; then
        _ok "acme.sh 安装成功"
        export PATH="$HOME/.acme.sh:$PATH"
        return 0
    else
        _err "acme.sh 安装失败"
        return 1
    fi
}

# 申请 ACME 证书
# 参数: $1=域名
get_acme_cert() {
    local domain=$1
    local protocol="${2:-unknown}"
    local cert_dir="$CFG/certs"
    mkdir -p "$cert_dir"
    
    # 检查是否已有相同域名的证书
    if [[ -f "$CFG/cert_domain" ]]; then
        local existing_domain=$(cat "$CFG/cert_domain")
        if [[ "$existing_domain" == "$domain" && -f "$cert_dir/server.crt" && -f "$cert_dir/server.key" ]]; then
            _ok "检测到相同域名的现有证书，跳过申请"
            # 检查证书是否仍然有效
            if openssl x509 -in "$cert_dir/server.crt" -noout -checkend 2592000 >/dev/null 2>&1; then
                _ok "现有证书仍然有效（30天以上）"
                
                # 读取自定义 nginx 端口（如果有）
                local custom_port=""
                [[ -f "$CFG/.nginx_port_tmp" ]] && custom_port=$(cat "$CFG/.nginx_port_tmp")
                
                # 确保Web服务器也启动（复用证书时也需要）
                create_fake_website "$domain" "$protocol" "$custom_port"
                
                diagnose_certificate "$domain"
                return 0
            else
                _warn "现有证书即将过期，重新申请..."
            fi
        fi
    fi
    
    # 先检查域名解析 (快速验证)
    _info "检查域名解析..."
    if ! check_domain_dns "$domain"; then
        _err "域名解析检查失败，无法申请 Let's Encrypt 证书"
        echo ""
        echo -e "  ${Y}选项：${NC}"
        echo -e "  1) 使用自签证书 (安全性较低，易被识别)"
        echo -e "  2) 重新输入域名"
        echo -e "  3) 退出安装"
        echo ""
        read -rp "  请选择 [1-3]: " choice
        
        case "$choice" in
            1)
                _warn "将使用自签证书"
                return 1  # 返回失败，让调用方使用自签证书
                ;;
            2)
                return 2  # 返回特殊值，表示需要重新输入域名
                ;;
            3|"")
                _info "已退出安装"
                exit 0
                ;;
            *)
                _err "无效选择，退出安装"
                exit 0
                ;;
        esac
    fi
    
    # 域名解析通过，询问是否申请证书
    echo ""
    _ok "域名解析验证通过！"
    echo ""
    echo -e "  ${Y}接下来将申请 Let's Encrypt 证书：${NC}"
    echo -e "  • 域名: ${G}$domain${NC}"
    echo -e "  • 证书有效期: 90天 (自动续期)"
    echo -e "  • 申请过程需要临时占用80端口"
    echo ""
    read -rp "  是否继续申请证书? [Y/n]: " confirm_cert
    
    if [[ "$confirm_cert" =~ ^[nN]$ ]]; then
        _info "已取消证书申请"
        return 2  # 返回特殊值，表示需要重新选择
    fi
    
    # 用户确认后再安装 acme.sh
    _info "安装证书申请工具..."
    install_acme_tool || return 1
    
    local acme_sh="$HOME/.acme.sh/acme.sh"
    
    # 临时停止可能占用 80 端口的服务（兼容 Alpine/systemd）
    local nginx_was_running=false
    if svc status nginx 2>/dev/null; then
        nginx_was_running=true
        _info "临时停止 Nginx..."
        svc stop nginx
    fi
    
    _info "正在为 $domain 申请证书 (Let's Encrypt)..."
    echo ""
    
    # 获取服务器IP用于错误提示
    local server_ip=$(get_ipv4)
    [[ -z "$server_ip" ]] && server_ip=$(get_ipv6)
    
    # 构建 reloadcmd（兼容 systemd 和 OpenRC）
    local reload_cmd="chmod 600 $cert_dir/server.key; chmod 644 $cert_dir/server.crt; chown root:root $cert_dir/server.key $cert_dir/server.crt; if command -v systemctl >/dev/null 2>&1; then systemctl restart vless-reality vless-hy2 vless-trojan 2>/dev/null || true; elif command -v rc-service >/dev/null 2>&1; then rc-service vless-reality restart 2>/dev/null || true; rc-service vless-hy2 restart 2>/dev/null || true; rc-service vless-trojan restart 2>/dev/null || true; fi"
    
    # 使用 standalone 模式申请证书，显示实时进度
    local acme_log="/tmp/acme_output.log"
    if timeout 180 "$acme_sh" --issue -d "$domain" --standalone --httpport 80 --force 2>&1 | tee "$acme_log" | grep -E "^\[|Verify finished|Cert success|error|Error" | sed 's/^/  /'; then
        echo ""
        _ok "证书申请成功，安装证书..."
        
        # 安装证书到指定目录，并设置权限和自动重启服务
        "$acme_sh" --install-cert -d "$domain" \
            --key-file       "$cert_dir/server.key"  \
            --fullchain-file "$cert_dir/server.crt" \
            --reloadcmd      "$reload_cmd" >/dev/null 2>&1
        
        rm -f "$acme_log"
        
        # 恢复 Nginx
        if [[ "$nginx_was_running" == "true" ]]; then
            svc start nginx
        fi
        
        _ok "证书已配置到 $cert_dir"
        _ok "证书自动续期已启用 (60天后)"
        
        # 读取自定义 nginx 端口（如果有）
        local custom_port=""
        [[ -f "$CFG/.nginx_port_tmp" ]] && custom_port=$(cat "$CFG/.nginx_port_tmp")
        
        # 创建简单的伪装网页
        create_fake_website "$domain" "$protocol" "$custom_port"
        
        # 验证证书文件
        if [[ -f "$cert_dir/server.crt" && -f "$cert_dir/server.key" ]]; then
            _ok "证书文件验证通过"
            # 运行证书诊断
            diagnose_certificate "$domain"
        else
            _err "证书文件不存在"
            return 1
        fi
        
        return 0
    else
        echo ""
        # 恢复 Nginx
        if [[ "$nginx_was_running" == "true" ]]; then
            svc start nginx
        fi
        
        _err "证书申请失败！"
        echo ""
        _err "详细错误信息："
        cat "$acme_log" 2>/dev/null | grep -E "(error|Error|ERROR|fail|Fail|FAIL)" | head -5 | while read -r line; do
            _err "  $line"
        done
        rm -f "$acme_log"
        echo ""
        _err "常见问题检查："
        _err "  1. 域名是否正确解析到本机 IP: $server_ip"
        _err "  2. 80 端口是否在防火墙中开放"
        _err "  3. 域名是否已被其他证书占用"
        _err "  4. 是否有其他程序占用80端口"
        echo ""
        _warn "回退到自签名证书模式..."
        return 1
    fi
}

# 检测并设置证书和 Nginx 配置（统一入口）
# 返回: 0=成功（有证书和Nginx），1=失败（无证书或用户取消）
# 设置全局变量: CERT_DOMAIN, NGINX_PORT
setup_cert_and_nginx() {
    local protocol="$1"
    local default_nginx_port="8443"
    
    # 全局变量，供调用方使用
    CERT_DOMAIN=""
    NGINX_PORT="$default_nginx_port"
    
    # === 回落子协议检测：如果是 WS 协议且有主协议，跳过 Nginx 配置 ===
    local is_fallback_mode=false
    if [[ "$protocol" == "vless-ws" || "$protocol" == "vmess-ws" ]]; then
        if [[ -f "$CFG/vless-vision.info" || -f "$CFG/trojan.info" ]]; then
            is_fallback_mode=true
        fi
    fi
    
    # 检测是否已有证书
    if [[ -f "$CFG/cert_domain" && -f "$CFG/certs/server.crt" ]]; then
        # 验证证书是否有效
        if openssl x509 -in "$CFG/certs/server.crt" -noout -checkend 2592000 >/dev/null 2>&1; then
            CERT_DOMAIN=$(cat "$CFG/cert_domain")
            
            # 回落模式：只设置证书域名，跳过 Nginx 配置
            if [[ "$is_fallback_mode" == "true" ]]; then
                _ok "检测到现有证书: $CERT_DOMAIN (回落模式，跳过 Nginx)"
                return 0
            fi
            
            # 读取已有的订阅配置
            if [[ -f "$CFG/sub.info" ]]; then
                source "$CFG/sub.info" 2>/dev/null
                NGINX_PORT="${sub_port:-$default_nginx_port}"
            fi
            
            _ok "检测到现有证书: $CERT_DOMAIN"
            
            # 检查 Nginx 配置文件是否存在
            local nginx_conf_exists=false
            if [[ -f "/etc/nginx/conf.d/vless-fake.conf" ]] || [[ -f "/etc/nginx/sites-available/vless-fake" ]]; then
                nginx_conf_exists=true
            fi
            
            # 检查订阅文件是否存在
            local sub_uuid=$(get_sub_uuid)  # 使用统一的函数获取或生成 UUID
            local sub_files_exist=false
            if [[ -f "$CFG/subscription/$sub_uuid/base64" ]]; then
                sub_files_exist=true
            fi
            
            # 如果 Nginx 配置或订阅文件不存在，重新配置
            if [[ "$nginx_conf_exists" == "false" ]] || [[ "$sub_files_exist" == "false" ]]; then
                _info "配置订阅服务 (端口: $NGINX_PORT)..."
                create_fake_website "$CERT_DOMAIN" "$protocol" "$NGINX_PORT"
                generate_sub_files
                setup_nginx_sub "$NGINX_PORT" "$CERT_DOMAIN" "true"
            else
                # 检查 Nginx 配置是否有正确的订阅路由 (使用 alias 指向 subscription 目录)
                local nginx_conf_valid=false
                if grep -q "alias.*subscription" "/etc/nginx/conf.d/vless-fake.conf" 2>/dev/null; then
                    nginx_conf_valid=true
                fi
                
                if [[ "$nginx_conf_valid" == "false" ]]; then
                    _warn "检测到旧版 Nginx 配置，正在更新..."
                    create_fake_website "$CERT_DOMAIN" "$protocol" "$NGINX_PORT"
                fi
                
                _ok "订阅服务端口: $NGINX_PORT"
                
                # 确保订阅文件是最新的
                generate_sub_files
                
                # 确保 Nginx 运行
                if ! ss -tlnp 2>/dev/null | grep -qE ":${NGINX_PORT}\s|:${NGINX_PORT}$"; then
                    _info "启动 Nginx 服务..."
                    systemctl stop nginx 2>/dev/null
                    sleep 1
                    systemctl start nginx 2>/dev/null || rc-service nginx start 2>/dev/null
                    sleep 1
                fi
                
                # 再次检查端口是否监听
                if ss -tlnp 2>/dev/null | grep -qE ":${NGINX_PORT}\s|:${NGINX_PORT}$"; then
                    _ok "Nginx 服务运行正常"
                    _ok "伪装网页: https://$CERT_DOMAIN:$NGINX_PORT"
                else
                    _warn "Nginx 端口 $NGINX_PORT 未监听，尝试重新配置..."
                    create_fake_website "$CERT_DOMAIN" "$protocol" "$NGINX_PORT"
                    setup_nginx_sub "$NGINX_PORT" "$CERT_DOMAIN" "true"
                fi
            fi
            
            return 0
        fi
    fi
    
    # 没有证书，询问用户
    echo ""
    _line
    echo -e "  ${W}证书配置模式${NC}"
    echo -e "  ${G}1)${NC} 使用真实域名 (推荐 - 自动申请 Let's Encrypt 证书)"
    echo -e "  ${G}2)${NC} 无域名 (使用自签证书 - 安全性较低，易被识别)"
    echo ""
    read -rp "  请选择 [1-2，默认 2]: " cert_choice
    
    if [[ "$cert_choice" == "1" ]]; then
        echo -e "  ${Y}提示: 域名必须已解析到本机 IP${NC}"
        read -rp "  请输入你的域名: " input_domain
        
        if [[ -n "$input_domain" ]]; then
            CERT_DOMAIN="$input_domain"
            
            # 保存端口到临时文件，供 create_fake_website 使用
            echo "$NGINX_PORT" > "$CFG/.nginx_port_tmp" 2>/dev/null
            
            # 申请证书（内部会调用 create_fake_website）
            if get_acme_cert "$CERT_DOMAIN" "$protocol"; then
                echo "$CERT_DOMAIN" > "$CFG/cert_domain"
                # 配置订阅服务
                setup_nginx_sub "$NGINX_PORT" "$CERT_DOMAIN" "true"
                rm -f "$CFG/.nginx_port_tmp"
                return 0
            else
                _warn "证书申请失败，使用自签证书"
                gen_self_cert "$CERT_DOMAIN"
                echo "$CERT_DOMAIN" > "$CFG/cert_domain"
                rm -f "$CFG/.nginx_port_tmp"
                return 1
            fi
        fi
    fi
    
    # 使用自签证书
    gen_self_cert "localhost"
    return 1
}

# SNI配置交互式询问
# 参数: $1=默认SNI (可选), $2=已申请的域名 (可选)
ask_sni_config() {
    local default_sni="${1:-$(gen_sni)}"
    local cert_domain="${2:-}"
    
    echo "" >&2
    _line >&2
    echo -e "  ${W}SNI 配置${NC}" >&2
    
    # 生成一个真正的随机 SNI（用于"更隐蔽"选项）
    local random_sni=$(gen_sni)
    
    # 如果有证书域名，询问是否使用
    if [[ -n "$cert_domain" ]]; then
        echo -e "  ${G}1${NC}) 使用证书域名 (${G}$cert_domain${NC}) - 推荐" >&2
        echo -e "  ${G}2${NC}) 使用随机SNI (${G}$random_sni${NC}) - 更隐蔽" >&2
        echo -e "  ${G}3${NC}) 自定义SNI" >&2
        echo "" >&2
        
        local sni_choice=""
        while true; do
            read -rp "  请选择 [1-3，默认 1]: " sni_choice
            
            if [[ -z "$sni_choice" ]]; then
                sni_choice="1"
            fi
            
            if [[ "$sni_choice" == "1" ]]; then
                echo "$cert_domain"
                return 0
            elif [[ "$sni_choice" == "2" ]]; then
                echo "$random_sni"
                return 0
            elif [[ "$sni_choice" == "3" ]]; then
                break
            else
                _err "无效选择: $sni_choice" >&2
                _warn "请输入 1、2 或 3" >&2
            fi
        done
    else
        # 没有证书域名时（如Reality协议），提供随机SNI和自定义选项
        echo -e "  ${G}1${NC}) 使用随机SNI (${G}$default_sni${NC}) - 推荐" >&2
        echo -e "  ${G}2${NC}) 自定义SNI" >&2
        echo "" >&2
        
        local sni_choice=""
        while true; do
            read -rp "  请选择 [1-2，默认 1]: " sni_choice
            
            if [[ -z "$sni_choice" ]]; then
                sni_choice="1"
            fi
            
            if [[ "$sni_choice" == "1" ]]; then
                echo "$default_sni"
                return 0
            elif [[ "$sni_choice" == "2" ]]; then
                break
            else
                _err "无效选择: $sni_choice" >&2
                _warn "请输入 1 或 2" >&2
            fi
        done
    fi
    
    # 自定义SNI输入
    while true; do
        echo "" >&2
        echo -e "  ${C}请输入自定义SNI域名 (回车使用随机SNI):${NC}" >&2
        read -rp "  SNI: " custom_sni
        
        if [[ -z "$custom_sni" ]]; then
            # 重新生成一个随机SNI
            local new_random_sni=$(gen_sni)
            echo -e "  ${G}使用随机SNI: $new_random_sni${NC}" >&2
            echo "$new_random_sni"
            return 0
        else
            # 基本域名格式验证
            if [[ "$custom_sni" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
                echo "$custom_sni"
                return 0
            else
                _err "无效SNI格式: $custom_sni" >&2
                _warn "SNI格式示例: www.example.com" >&2
            fi
        fi
    done
}

# 证书配置交互式询问
# 参数: $1=默认SNI (可选)
ask_cert_config() {
    local default_sni="${1:-bing.com}"
    local protocol="${2:-unknown}"
    
    # 检查是否已有 ACME 证书，如果有则直接复用
    if [[ -f "$CFG/cert_domain" && -f "$CFG/certs/server.crt" ]]; then
        local existing_domain=$(cat "$CFG/cert_domain")
        local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
        if [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"R11"* ]]; then
            _ok "检测到现有 ACME 证书: $existing_domain，自动复用" >&2
            echo "$existing_domain"
            return 0
        fi
    fi
    
    # 所有提示信息输出到 stderr，避免污染返回值
    echo "" >&2
    _line >&2
    echo -e "  ${W}证书配置模式${NC}" >&2
    echo -e "  ${G}1${NC}) 使用真实域名 (推荐 - 自动申请 Let's Encrypt 证书)" >&2
    echo -e "  ${Y}2${NC}) 无域名 (使用自签证书 - 安全性较低，易被识别)" >&2
    echo "" >&2
    
    local cert_mode=""
    local domain=""
    local use_acme=false
    
    # 验证证书模式选择
    while true; do
        read -rp "  请选择 [1-2，默认 2]: " cert_mode
        
        # 如果用户直接回车，使用默认选项 2
        if [[ -z "$cert_mode" ]]; then
            cert_mode="2"
        fi
        
        # 验证输入是否为有效选项
        if [[ "$cert_mode" == "1" || "$cert_mode" == "2" ]]; then
            break
        else
            _err "无效选择: $cert_mode" >&2
            _warn "请输入 1 或 2" >&2
        fi
    done
    
    if [[ "$cert_mode" == "1" ]]; then
        # 域名输入循环，支持重新输入
        while true; do
            echo "" >&2
            echo -e "  ${C}提示: 域名必须已解析到本机 IP${NC}" >&2
            read -rp "  请输入你的域名: " domain
            
            if [[ -z "$domain" ]]; then
                _warn "域名不能为空，使用自签证书" >&2
                gen_self_cert "$default_sni" >&2
                domain=""
                break
            else
                # 基本域名格式验证
                if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
                    _err "无效域名格式: $domain" >&2
                    _warn "域名格式示例: example.com 或 sub.example.com" >&2
                    continue
                fi
                local cert_result
                get_acme_cert "$domain" "$protocol" >&2
                cert_result=$?
                
                if [[ $cert_result -eq 0 ]]; then
                    # ACME 成功
                    use_acme=true
                    echo "$domain" > "$CFG/cert_domain"
                    break
                elif [[ $cert_result -eq 2 ]]; then
                    # 需要重新输入域名，继续循环
                    continue
                else
                    # ACME 失败，使用自签证书，返回空字符串
                    gen_self_cert "$default_sni" >&2
                    domain=""
                    break
                fi
            fi
        done
    else
        # 无域名模式：使用自签证书，返回空字符串表示没有真实域名
        gen_self_cert "$default_sni" >&2
        domain=""
    fi
    
    # 只返回域名到 stdout（空字符串表示使用了自签证书）
    echo "$domain"
}

# 安装 tun2socks (TUN模式必需)
install_tun2socks() {
    [[ -x "/usr/local/bin/tun2socks" ]] && { _ok "tun2socks 已安装"; return 0; }
    
    local arch=$(uname -m) t2s_arch
    case $arch in
        x86_64)  t2s_arch="amd64" ;;
        aarch64) t2s_arch="arm64" ;;
        armv7l)  t2s_arch="armv7" ;;
        *) _warn "不支持的架构，跳过tun2socks安装"; return 1 ;;
    esac
    
    _info "安装 tun2socks..."
    local tmp=$(mktemp -d)
    if curl -sLo "$tmp/t2s.zip" --connect-timeout 60 "https://github.com/xjasonlyu/tun2socks/releases/latest/download/tun2socks-linux-${t2s_arch}.zip"; then
        unzip -oq "$tmp/t2s.zip" -d "$tmp/" 2>/dev/null
        local bin=$(find "$tmp" -name "tun2socks*" -type f | head -1)
        if [[ -n "$bin" ]]; then
            mv "$bin" /usr/local/bin/tun2socks
            chmod +x /usr/local/bin/tun2socks
            rm -rf "$tmp"
            _ok "tun2socks 已安装"
            return 0
        else
            rm -rf "$tmp"
            _err "tun2socks 安装失败"
            return 1
        fi
    else
        rm -rf "$tmp"
        _err "tun2socks 下载失败"
        return 1
    fi
}

# 修复 SELinux 上下文 (CentOS/RHEL)
fix_selinux_context() {
    # 仅在 CentOS/RHEL 且 SELinux 启用时执行
    if [[ "$DISTRO" != "centos" ]]; then
        return 0
    fi
    
    # 检查 SELinux 是否启用
    if ! command -v getenforce &>/dev/null || [[ "$(getenforce 2>/dev/null)" == "Disabled" ]]; then
        return 0
    fi
    
    _info "配置 SELinux 上下文..."
    
    # 允许自定义端口
    if command -v semanage &>/dev/null; then
        local port="$1"
        if [[ -n "$port" ]]; then
            semanage port -a -t http_port_t -p tcp "$port" 2>/dev/null || true
            semanage port -a -t http_port_t -p udp "$port" 2>/dev/null || true
        fi
    fi
    
    # 恢复文件上下文
    if command -v restorecon &>/dev/null; then
        restorecon -Rv /usr/local/bin/xray /usr/local/bin/hysteria /usr/local/bin/snell-server \
            /usr/local/bin/tuic-server /usr/local/bin/anytls-server /usr/local/bin/shadow-tls \
            /etc/vless-reality 2>/dev/null || true
    fi
    
    # 允许网络连接
    if command -v setsebool &>/dev/null; then
        setsebool -P httpd_can_network_connect 1 2>/dev/null || true
    fi
}

install_xray() {
    check_cmd xray && { _ok "Xray 已安装"; return 0; }
    
    local arch=$(uname -m) xarch
    case $arch in
        x86_64)  xarch="64" ;;
        aarch64) xarch="arm64-v8a" ;;
        armv7l)  xarch="arm32-v7a" ;;
        *) _err "不支持的架构: $arch"; return 1 ;;
    esac

    _info "安装 Xray..."
    local tmp=$(mktemp -d)
    if curl -sLo "$tmp/xray.zip" --connect-timeout 30 "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${xarch}.zip"; then
        unzip -oq "$tmp/xray.zip" -d "$tmp/" || { rm -rf "$tmp"; _err "解压失败"; return 1; }
        install -m 755 "$tmp/xray" /usr/local/bin/xray
        mkdir -p /usr/local/share/xray
        [[ -f "$tmp/geoip.dat" ]] && install -m 644 "$tmp/geoip.dat" /usr/local/share/xray/
        [[ -f "$tmp/geosite.dat" ]] && install -m 644 "$tmp/geosite.dat" /usr/local/share/xray/
        rm -rf "$tmp"
        
        # 修复 SELinux 上下文
        fix_selinux_context
        
        _ok "Xray 已安装"
    else
        rm -rf "$tmp"; _err "下载 Xray 失败"; return 1
    fi
}

# 安装 Hysteria2
install_hysteria() {
    check_cmd hysteria && { _ok "Hysteria2 已安装"; return 0; }
    
    local arch=$(uname -m) harch
    case $arch in
        x86_64)  harch="amd64" ;;
        aarch64) harch="arm64" ;;
        armv7l)  harch="armv7" ;;
        *) _err "不支持的架构: $arch"; return 1 ;;
    esac

    _info "安装 Hysteria2..."
    if curl -sLo /usr/local/bin/hysteria --connect-timeout 60 "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${harch}"; then
        chmod +x /usr/local/bin/hysteria
        _ok "Hysteria2 已安装"
    else
        _err "下载 Hysteria2 失败"; return 1
    fi
}

# 安装 Snell
install_snell() {
    check_cmd snell-server && { _ok "Snell 已安装"; return 0; }
    
    local arch=$(uname -m) sarch
    case $arch in
        x86_64)  sarch="amd64" ;;
        aarch64) sarch="aarch64" ;;
        armv7l)  sarch="armv7l" ;;
        *) _err "不支持的架构: $arch"; return 1 ;;
    esac

    _info "安装 Snell v4..."
    local tmp=$(mktemp -d)
    if curl -sLo "$tmp/snell.zip" --connect-timeout 60 "https://dl.nssurge.com/snell/snell-server-v4.1.1-linux-${sarch}.zip"; then
        unzip -oq "$tmp/snell.zip" -d "$tmp/" 2>/dev/null
        install -m 755 "$tmp/snell-server" /usr/local/bin/snell-server
        rm -rf "$tmp"
        _ok "Snell 已安装"
    else
        rm -rf "$tmp"; _err "下载 Snell 失败"; return 1
    fi
}

# 安装 Snell v5
install_snell_v5() {
    check_cmd snell-server-v5 && { _ok "Snell v5 已安装"; return 0; }
    
    local arch=$(uname -m) sarch
    case $arch in
        x86_64)  sarch="amd64" ;;
        aarch64) sarch="aarch64" ;;
        armv7l)  sarch="armv7l" ;;
        *) _err "不支持的架构: $arch"; return 1 ;;
    esac

    _info "安装 Snell v5..."
    local tmp=$(mktemp -d)
    
    # 获取最新版本号
    local latest_version
    latest_version=$(curl -s "https://api.github.com/repos/surge-networks/snell/releases/latest" | grep '"tag_name"' | cut -d'"' -f4 | sed 's/^v//')
    if [[ -z "$latest_version" ]]; then
        latest_version="5.0.1"  # fallback 版本
        _warn "无法获取最新版本，使用默认版本 $latest_version"
    else
        _info "检测到最新版本: v$latest_version"
    fi
    
    if curl -sLo "$tmp/snell-v5.zip" --connect-timeout 60 "https://dl.nssurge.com/snell/snell-server-v${latest_version}-linux-${sarch}.zip"; then
        unzip -oq "$tmp/snell-v5.zip" -d "$tmp/" 2>/dev/null
        install -m 755 "$tmp/snell-server" /usr/local/bin/snell-server-v5
        rm -rf "$tmp"
        _ok "Snell v5 已安装"
    else
        rm -rf "$tmp"; _err "下载 Snell v5 失败"; return 1
    fi
}

# 安装 AnyTLS
install_anytls() {
    check_cmd anytls-server && { _ok "AnyTLS 已安装"; return 0; }
    
    local arch=$(uname -m) aarch
    case $arch in
        x86_64)  aarch="amd64" ;;
        aarch64) aarch="arm64" ;;
        armv7l)  aarch="armv7" ;;
        *) _err "不支持的架构: $arch"; return 1 ;;
    esac

    _info "安装 AnyTLS..."
    local tmp=$(mktemp -d)
    local version="v0.0.11"  # 使用最新版本
    if curl -sLo "$tmp/anytls.zip" --connect-timeout 60 "https://github.com/anytls/anytls-go/releases/download/${version}/anytls_${version#v}_linux_${aarch}.zip"; then
        unzip -oq "$tmp/anytls.zip" -d "$tmp/" 2>/dev/null
        install -m 755 "$tmp/anytls-server" /usr/local/bin/anytls-server
        install -m 755 "$tmp/anytls-client" /usr/local/bin/anytls-client
        rm -rf "$tmp"
        _ok "AnyTLS 已安装"
    else
        rm -rf "$tmp"; _err "下载 AnyTLS 失败"; return 1
    fi
}

# 安装 ShadowTLS
install_shadowtls() {
    check_cmd shadow-tls && { _ok "ShadowTLS 已安装"; return 0; }
    
    local arch=$(uname -m) aarch
    case $arch in
        x86_64)  aarch="x86_64-unknown-linux-musl" ;;
        aarch64) aarch="aarch64-unknown-linux-musl" ;;
        armv7l)  aarch="armv7-unknown-linux-musleabihf" ;;
        *) _err "不支持的架构: $arch"; return 1 ;;
    esac

    _info "安装 ShadowTLS..."
    local tmp=$(mktemp -d)
    local version="v0.2.25"  # 使用最新稳定版本
    if curl -sLo "$tmp/shadow-tls" --connect-timeout 60 "https://github.com/ihciah/shadow-tls/releases/download/${version}/shadow-tls-${aarch}"; then
        install -m 755 "$tmp/shadow-tls" /usr/local/bin/shadow-tls
        rm -rf "$tmp"
        _ok "ShadowTLS 已安装"
    else
        rm -rf "$tmp"; _err "下载 ShadowTLS 失败"; return 1
    fi
}

# 安装 TUIC (服务端和客户端)
install_tuic() {
    local role="${1:-server}"
    local bin_path bin_name
    
    if [[ "$role" == "server" ]]; then
        bin_name="tuic-server"
        bin_path="/usr/local/bin/tuic-server"
    else
        bin_name="tuic-client"
        bin_path="/usr/local/bin/tuic-client"
    fi
    
    # 检查是否已安装且为有效的 ELF 文件
    if [[ -x "$bin_path" ]] && file "$bin_path" 2>/dev/null | grep -qE "ELF.*executable"; then
        _ok "$bin_name 已安装"
        return 0
    fi
    
    # 删除可能存在的损坏文件
    [[ -f "$bin_path" ]] && rm -f "$bin_path"
    
    local arch=$(uname -m) tarch
    case $arch in
        x86_64)  tarch="x86_64-unknown-linux-gnu" ;;
        aarch64) tarch="aarch64-unknown-linux-gnu" ;;
        armv7l)  tarch="armv7-unknown-linux-gnueabihf" ;;
        *) _err "不支持的架构: $arch"; return 1 ;;
    esac

    _info "安装 TUIC v5..."
    local tmp=$(mktemp -d)
    local download_url
    
    if [[ "$role" == "server" ]]; then
        download_url="https://github.com/EAimTY/tuic/releases/download/tuic-server-1.0.0/tuic-server-1.0.0-${tarch}"
    else
        download_url="https://github.com/EAimTY/tuic/releases/download/tuic-client-1.0.0/tuic-client-1.0.0-${tarch}"
    fi
    
    _info "下载 $bin_name..."
    if curl -fSL -o "$tmp/$bin_name" --connect-timeout 30 --retry 3 "$download_url" 2>/dev/null; then
        # 验证下载的文件是否为 ELF 二进制
        if file "$tmp/$bin_name" 2>/dev/null | grep -qE "ELF.*executable"; then
            install -m 755 "$tmp/$bin_name" "$bin_path"
            rm -rf "$tmp"
            _ok "$bin_name 已安装"
            return 0
        else
            _err "下载的文件不是有效的可执行文件"
            rm -rf "$tmp"
            return 1
        fi
    else
        rm -rf "$tmp"
        _err "下载 $bin_name 失败"
        return 1
    fi
}

# 生成通用自签名证书 (适配 Xray/Hysteria/Trojan)
gen_self_cert() {
    local domain="${1:-localhost}"
    mkdir -p "$CFG/certs"
    
    # 如果已有证书，检查是否应该保护
    if [[ -f "$CFG/certs/server.crt" ]]; then
        # 方法1: 检查是否有 cert_domain 文件（说明是用户申请的真实证书）
        if [[ -f "$CFG/cert_domain" ]]; then
            local saved_domain=$(cat "$CFG/cert_domain")
            _ok "检测到已申请的证书 ($saved_domain)，跳过自签名证书生成"
            return 0
        fi
        
        # 方法2: 检查证书签发者（兼容各种 CA）
        local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
        # Let's Encrypt 系列
        if [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"R11"* ]] || [[ "$issuer" == *"E1"* ]] || [[ "$issuer" == *"E5"* ]]; then
            _ok "检测到 Let's Encrypt 证书，跳过自签名证书生成"
            return 0
        fi
        # 其他常见 CA
        if [[ "$issuer" == *"ZeroSSL"* ]] || [[ "$issuer" == *"Buypass"* ]] || [[ "$issuer" == *"DigiCert"* ]] || [[ "$issuer" == *"Comodo"* ]] || [[ "$issuer" == *"GlobalSign"* ]]; then
            _ok "检测到 CA 签发的证书，跳过自签名证书生成"
            return 0
        fi
    fi
    
    rm -f "$CFG/certs/server.crt" "$CFG/certs/server.key"
    
    _info "生成自签名证书..."
    # Xray/Go 需要标准的自签名证书 (隐含 CA:TRUE)
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout "$CFG/certs/server.key" -out "$CFG/certs/server.crt" \
        -subj "/CN=$domain" -days 36500 2>/dev/null
    
    chmod 600 "$CFG/certs/server.key"
}


#═══════════════════════════════════════════════════════════════════════════════
# 配置生成
#═══════════════════════════════════════════════════════════════════════════════

# VLESS+Reality 服务端配置
gen_server_config() {
    local uuid="$1" port="$2" privkey="$3" pubkey="$4" sid="$5" sni="$6"
    mkdir -p "$CFG"

    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件 (供 generate_xray_config 读取)
    cat > "$CFG/vless.info" << EOF
protocol=vless
uuid=$uuid
port=$port
private_key=$privkey
public_key=$pubkey
short_id=$sid
sni=$sni
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "vless"

    # 保存 join 信息
    > "$CFG/vless.join"
    if [[ -n "$ipv4" ]]; then
        local data="REALITY|$ipv4|$port|$uuid|$pubkey|$sid|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_link "$ipv4" "$port" "$uuid" "$pubkey" "$sid" "$sni")
        printf '%s\n' "# IPv4" >> "$CFG/vless.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/vless.join"
        printf '%s\n' "VLESS_V4=$link" >> "$CFG/vless.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="REALITY|[$ipv6]|$port|$uuid|$pubkey|$sid|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_link "[$ipv6]" "$port" "$uuid" "$pubkey" "$sid" "$sni")
        printf '%s\n' "# IPv6" >> "$CFG/vless.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/vless.join"
        printf '%s\n' "VLESS_V6=$link" >> "$CFG/vless.join"
    fi
    echo "server" > "$CFG/role"
}

# VLESS+Reality+XHTTP 服务端配置
gen_vless_xhttp_server_config() {
    local uuid="$1" port="$2" privkey="$3" pubkey="$4" sid="$5" sni="$6" path="${7:-/}"
    mkdir -p "$CFG"
    
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件 (供 generate_xray_config 读取)
    cat > "$CFG/vless-xhttp.info" << EOF
protocol=vless-xhttp
uuid=$uuid
port=$port
private_key=$privkey
public_key=$pubkey
short_id=$sid
sni=$sni
path=$path
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "vless-xhttp"

    # 保存 join 信息
    > "$CFG/vless-xhttp.join"
    if [[ -n "$ipv4" ]]; then
        local data="REALITY-XHTTP|$ipv4|$port|$uuid|$pubkey|$sid|$sni|$path"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_xhttp_link "$ipv4" "$port" "$uuid" "$pubkey" "$sid" "$sni" "$path")
        printf '%s\n' "# IPv4" >> "$CFG/vless-xhttp.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/vless-xhttp.join"
        printf '%s\n' "VLESS_XHTTP_V4=$link" >> "$CFG/vless-xhttp.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="REALITY-XHTTP|[$ipv6]|$port|$uuid|$pubkey|$sid|$sni|$path"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_xhttp_link "[$ipv6]" "$port" "$uuid" "$pubkey" "$sid" "$sni" "$path")
        printf '%s\n' "# IPv6" >> "$CFG/vless-xhttp.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/vless-xhttp.join"
        printf '%s\n' "VLESS_XHTTP_V6=$link" >> "$CFG/vless-xhttp.join"
    fi
    echo "server" > "$CFG/role"
}

# Hysteria2 服务端配置
gen_hy2_server_config() {
    local password="$1" port="$2" sni="${3:-bing.com}"
    # 新增参数（默认兼容旧调用）
    local hop_enable="${4:-0}"
    local hop_start="${5:-20000}"
    local hop_end="${6:-50000}"
    mkdir -p "$CFG"
    
    # 智能证书选择：真实域名用共享证书，随机SNI用独立自签证书
    local cert_file="" key_file=""
    # 常见的随机 SNI 列表（与 gen_sni() 保持一致）
    local common_snis="microsoft.com www.microsoft.com apple.com www.apple.com cloudflare.com www.cloudflare.com amazon.com www.amazon.com gateway.icloud.com bing.com www.bing.com"
    
    if echo "$common_snis" | grep -qw "$sni"; then
        # 随机 SNI：使用独立自签证书
        local hy2_cert_dir="$CFG/certs/hy2"
        mkdir -p "$hy2_cert_dir"
        cert_file="$hy2_cert_dir/server.crt"
        key_file="$hy2_cert_dir/server.key"
        
        if [[ ! -f "$cert_file" ]]; then
            _info "为 Hysteria2 生成独立自签证书 (SNI: $sni)..."
            openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
                -keyout "$key_file" -out "$cert_file" \
                -subj "/CN=$sni" -days 36500 2>/dev/null
            chmod 600 "$key_file"
            _ok "Hysteria2 自签证书生成完成"
        fi
    else
        # 真实域名：尝试使用共享的 Let's Encrypt 证书
        cert_file="$CFG/certs/server.crt"
        key_file="$CFG/certs/server.key"
        
        if [[ -f "$cert_file" && -f "$key_file" ]]; then
            # 检查现有证书的域名是否匹配
            local cert_cn=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed 's/.*CN *= *//')
            if [[ "$cert_cn" == "$sni" ]]; then
                _ok "复用现有证书 (域名: $sni)"
            else
                # 域名不匹配，需要申请新证书
                _info "检测到域名变更，需要申请新证书..."
                if get_acme_cert "$sni" "hy2"; then
                    echo "$sni" > "$CFG/cert_domain"
                    _ok "证书申请成功"
                else
                    _warn "证书申请失败，使用自签证书"
                    gen_self_cert "$sni"
                fi
            fi
        else
            # 没有现有证书，申请新的
            _info "为域名 $sni 申请证书..."
            if get_acme_cert "$sni" "hy2"; then
                echo "$sni" > "$CFG/cert_domain"
                _ok "证书申请成功"
            else
                _warn "证书申请失败，使用自签证书"
                gen_self_cert "$sni"
            fi
        fi
    fi

    cat > "$CFG/hy2.yaml" << EOF
listen: :$port

tls:
  cert: $cert_file
  key: $key_file

auth:
  type: password
  password: $password

# 伪装配置 - 防止主动探测
masquerade:
  type: proxy
  proxy:
    url: https://bing.com/
    rewriteHost: true

# 抗 QoS 优化
ignoreClientBandwidth: true  # 不强制检查客户端带宽，减少误判断流
udpIdleTimeout: 60s           # 延长 UDP 空闲超时

# 带宽配置
bandwidth:
  up: 1 gbps
  down: 1 gbps

# QUIC 配置优化
quic:
  initStreamReceiveWindow: 8388608      # 8MB
  maxStreamReceiveWindow: 8388608       # 8MB
  initConnReceiveWindow: 20971520       # 20MB
  maxConnReceiveWindow: 20971520        # 20MB
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false
EOF
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件
    cat > "$CFG/hy2.info" << EOF
protocol=hy2
password=$password
port=$port
sni=$sni
hop_enable=$hop_enable
hop_start=$hop_start
hop_end=$hop_end
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 兼容性：也保存到主 info 文件
    cp "$CFG/hy2.info" "$CFG/info"
    
    # 注册协议
    register_protocol "hy2"

    > "$CFG/join.txt"
    if [[ -n "$ipv4" ]]; then
        local data="HY2|$ipv4|$port|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_hy2_link "$ipv4" "$port" "$password" "$sni")
        printf '%s\n' "# IPv4" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/join.txt"
        printf '%s\n' "HY2_V4=$link" >> "$CFG/join.txt"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="HY2|[$ipv6]|$port|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_hy2_link "[$ipv6]" "$port" "$password" "$sni")
        printf '%s\n' "# IPv6" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/join.txt"
        printf '%s\n' "HY2_V6=$link" >> "$CFG/join.txt"
    fi
    
    # 端口跳跃提示
    if [[ "$hop_enable" == "1" ]]; then
        printf '%s\n' "" >> "$CFG/join.txt"
        printf '%s\n' "# 端口跳跃已启用" >> "$CFG/join.txt"
        printf '%s\n' "# 客户端请手动将端口改为: ${hop_start}-${hop_end}" >> "$CFG/join.txt"
    fi
    echo "server" > "$CFG/role"
    # 注意：不再写入 $CFG/protocol，因为多协议模式使用 installed_protocols 管理
}

# Trojan 服务端配置
gen_trojan_server_config() {
    local password="$1" port="$2" sni="${3:-bing.com}"
    mkdir -p "$CFG"
    
    # 如果证书不存在，则生成（避免覆盖 ACME 证书）
    if [[ ! -f "$CFG/certs/server.crt" ]]; then
        gen_self_cert "$sni"
    fi

    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件 (供 generate_xray_config 读取)
    cat > "$CFG/trojan.info" << EOF
protocol=trojan
password=$password
port=$port
sni=$sni
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "trojan"

    # 保存 join 信息
    > "$CFG/trojan.join"
    if [[ -n "$ipv4" ]]; then
        local data="TROJAN|$ipv4|$port|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_trojan_link "$ipv4" "$port" "$password" "$sni")
        printf '%s\n' "# IPv4" >> "$CFG/trojan.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/trojan.join"
        printf '%s\n' "TROJAN_V4=$link" >> "$CFG/trojan.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="TROJAN|[$ipv6]|$port|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_trojan_link "[$ipv6]" "$port" "$password" "$sni")
        printf '%s\n' "# IPv6" >> "$CFG/trojan.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/trojan.join"
        printf '%s\n' "TROJAN_V6=$link" >> "$CFG/trojan.join"
    fi
    echo "server" > "$CFG/role"
}

# VLESS+WS+TLS 服务端配置
gen_vless_ws_server_config() {
    local uuid="$1" port="$2" sni="${3:-bing.com}" path="${4:-/vless}"
    mkdir -p "$CFG"
    
    # 如果证书不存在，则生成（避免覆盖 ACME 证书）
    if [[ ! -f "$CFG/certs/server.crt" ]]; then
        gen_self_cert "$sni"
    fi

    # 如果存在主协议（Vision/Trojan），则 VLESS WS 用作回落子协议
    local outer_port="$port"
    if [[ -f "$CFG/vless-vision.info" ]]; then
        outer_port=$(grep "^port=" "$CFG/vless-vision.info" | cut -d= -f2)
    elif [[ -f "$CFG/trojan.info" ]]; then
        outer_port=$(grep "^port=" "$CFG/trojan.info" | cut -d= -f2)
    fi

    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件 (供 generate_xray_config 读取)
    cat > "$CFG/vless-ws.info" << EOF
protocol=vless-ws
uuid=$uuid
port=$port
outer_port=$outer_port
sni=$sni
path=$path
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "vless-ws"

    # 保存 join 信息 (使用 outer_port 作为对外端口)
    > "$CFG/vless-ws.join"
    if [[ -n "$ipv4" ]]; then
        local data="VLESS-WS|$ipv4|$outer_port|$uuid|$sni|$path"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_ws_link "$ipv4" "$outer_port" "$uuid" "$sni" "$path")
        printf '%s\n' "# IPv4" >> "$CFG/vless-ws.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/vless-ws.join"
        printf '%s\n' "VLESS_WS_V4=$link" >> "$CFG/vless-ws.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="VLESS-WS|[$ipv6]|$outer_port|$uuid|$sni|$path"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_ws_link "[$ipv6]" "$outer_port" "$uuid" "$sni" "$path")
        printf '%s\n' "# IPv6" >> "$CFG/vless-ws.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/vless-ws.join"
        printf '%s\n' "VLESS_WS_V6=$link" >> "$CFG/vless-ws.join"
    fi
    echo "server" > "$CFG/role"
}

# VMess+WS 服务端配置
gen_vmess_ws_server_config() {
    local uuid="$1" port="$2" sni="$3" path="$4"

    # 如果存在主协议（Vision/Trojan），则 VMess WS 用作回落子协议：监听 127.0.0.1 内部端口
    local outer_port="$port"
    if [[ -f "$CFG/vless-vision.info" ]]; then
        outer_port=$(grep "^port=" "$CFG/vless-vision.info" | cut -d= -f2)
    elif [[ -f "$CFG/trojan.info" ]]; then
        outer_port=$(grep "^port=" "$CFG/trojan.info" | cut -d= -f2)
    fi

    cat > "$CFG/vmess-ws.info" << EOF
protocol=vmess-ws
port=$port
outer_port=$outer_port
uuid=$uuid
sni=$sni
path=$path
ipv4=$(get_ipv4)
ipv6=$(get_ipv6)
EOF

    register_protocol "vmess-ws"
    # JOIN 格式：VMESSWS|ip|outer_port|uuid|sni|path
    echo "VMESSWS|$(get_ipv4)|$outer_port|$uuid|$sni|$path" > "$CFG/vmess-ws.join"
}

# VLESS+gRPC+TLS 服务端配置 (独立协议，支持 CDN)
gen_vless_grpc_server_config() {
    local uuid="$1" port="$2" sni="${3:-bing.com}" service_name="${4:-grpc}"
    mkdir -p "$CFG"
    
    # 如果证书不存在，则生成（避免覆盖 ACME 证书）
    if [[ ! -f "$CFG/certs/server.crt" ]]; then
        gen_self_cert "$sni"
    fi

    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件
    cat > "$CFG/vless-grpc.info" << EOF
protocol=vless-grpc
uuid=$uuid
port=$port
sni=$sni
path=$service_name
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "vless-grpc"

    # 保存 join 信息
    > "$CFG/vless-grpc.join"
    if [[ -n "$ipv4" ]]; then
        local data="VLESS-GRPC|$ipv4|$port|$uuid|$sni|$service_name"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_grpc_link "$ipv4" "$port" "$uuid" "$sni" "$service_name")
        printf '%s\n' "# IPv4" >> "$CFG/vless-grpc.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/vless-grpc.join"
        printf '%s\n' "VLESS_GRPC_V4=$link" >> "$CFG/vless-grpc.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="VLESS-GRPC|[$ipv6]|$port|$uuid|$sni|$service_name"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_grpc_link "[$ipv6]" "$port" "$uuid" "$sni" "$service_name")
        printf '%s\n' "# IPv6" >> "$CFG/vless-grpc.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/vless-grpc.join"
        printf '%s\n' "VLESS_GRPC_V6=$link" >> "$CFG/vless-grpc.join"
    fi
    echo "server" > "$CFG/role"
}

# VLESS-XTLS-Vision 服务端配置
gen_vless_vision_server_config() {
    local uuid="$1" port="$2" sni="${3:-bing.com}"
    mkdir -p "$CFG"
    
    # 如果证书不存在，则生成（避免覆盖 ACME 证书）
    if [[ ! -f "$CFG/certs/server.crt" ]]; then
        gen_self_cert "$sni"
    fi

    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件 (供 generate_xray_config 读取)
    cat > "$CFG/vless-vision.info" << EOF
protocol=vless-vision
uuid=$uuid
port=$port
sni=$sni
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "vless-vision"

    # 保存 join 信息
    > "$CFG/vless-vision.join"
    if [[ -n "$ipv4" ]]; then
        local data="VLESS-VISION|$ipv4|$port|$uuid|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_vision_link "$ipv4" "$port" "$uuid" "$sni")
        printf '%s\n' "# IPv4" >> "$CFG/vless-vision.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/vless-vision.join"
        printf '%s\n' "VLESS_VISION_V4=$link" >> "$CFG/vless-vision.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="VLESS-VISION|[$ipv6]|$port|$uuid|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_vision_link "[$ipv6]" "$port" "$uuid" "$sni")
        printf '%s\n' "# IPv6" >> "$CFG/vless-vision.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/vless-vision.join"
        printf '%s\n' "VLESS_VISION_V6=$link" >> "$CFG/vless-vision.join"
    fi
    echo "server" > "$CFG/role"
}

# Shadowsocks 2022 服务端配置
gen_ss2022_server_config() {
    local password="$1" port="$2" method="${3:-2022-blake3-aes-128-gcm}"
    mkdir -p "$CFG"

    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件 (供 generate_xray_config 读取)
    cat > "$CFG/ss2022.info" << EOF
protocol=ss2022
password=$password
port=$port
method=$method
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "ss2022"

    # 保存 join 信息
    > "$CFG/ss2022.join"
    if [[ -n "$ipv4" ]]; then
        local data="SS2022|$ipv4|$port|$method|$password"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_ss2022_link "$ipv4" "$port" "$method" "$password")
        printf '%s\n' "# IPv4" >> "$CFG/ss2022.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/ss2022.join"
        printf '%s\n' "SS2022_V4=$link" >> "$CFG/ss2022.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="SS2022|[$ipv6]|$port|$method|$password"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_ss2022_link "[$ipv6]" "$port" "$method" "$password")
        printf '%s\n' "# IPv6" >> "$CFG/ss2022.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/ss2022.join"
        printf '%s\n' "SS2022_V6=$link" >> "$CFG/ss2022.join"
    fi
    echo "server" > "$CFG/role"
}

# Snell v4 服务端配置
gen_snell_server_config() {
    local psk="$1" port="$2" version="${3:-4}"
    mkdir -p "$CFG"

    cat > "$CFG/snell.conf" << EOF
[snell-server]
listen = 0.0.0.0:$port
psk = $psk
ipv6 = true
obfs = off
EOF
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件
    cat > "$CFG/snell.info" << EOF
protocol=snell
psk=$psk
port=$port
version=$version
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 兼容性：也保存到主 info 文件
    cp "$CFG/snell.info" "$CFG/info"
    
    # 注册协议
    register_protocol "snell"

    > "$CFG/join.txt"
    if [[ -n "$ipv4" ]]; then
        local data="SNELL|$ipv4|$port|$psk|$version"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_snell_link "$ipv4" "$port" "$psk" "$version")
        printf '%s\n' "# IPv4" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/join.txt"
        printf '%s\n' "SNELL_V4=$link" >> "$CFG/join.txt"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="SNELL|[$ipv6]|$port|$psk|$version"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_snell_link "[$ipv6]" "$port" "$psk" "$version")
        printf '%s\n' "# IPv6" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/join.txt"
        printf '%s\n' "SNELL_V6=$link" >> "$CFG/join.txt"
    fi
    echo "server" > "$CFG/role"
    # 注意：不再写入 $CFG/protocol，因为多协议模式使用 installed_protocols 管理
}

# TUIC v5 服务端配置
gen_tuic_server_config() {
    local uuid="$1" password="$2" port="$3" sni="${4:-bing.com}"
    mkdir -p "$CFG"
    
    # 智能证书选择：真实域名用共享证书，随机SNI用独立自签证书
    local cert_file="" key_file=""
    # 常见的随机 SNI 列表（与 gen_sni() 保持一致）
    local common_snis="microsoft.com www.microsoft.com apple.com www.apple.com cloudflare.com www.cloudflare.com amazon.com www.amazon.com gateway.icloud.com bing.com www.bing.com"
    
    local server_ip=$(get_ipv4)
    [[ -z "$server_ip" ]] && server_ip=$(get_ipv6)
    [[ -z "$server_ip" ]] && server_ip="$sni"
    
    if echo "$common_snis" | grep -qw "$sni"; then
        # 随机 SNI：使用独立自签证书
        local tuic_cert_dir="$CFG/certs/tuic"
        mkdir -p "$tuic_cert_dir"
        cert_file="$tuic_cert_dir/server.crt"
        key_file="$tuic_cert_dir/server.key"
        
        if [[ ! -f "$cert_file" ]]; then
            _info "为 TUIC 生成独立自签证书 (SNI: $sni)..."
            openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
                -keyout "$key_file" -out "$cert_file" \
                -subj "/CN=$server_ip" -days 36500 \
                -addext "subjectAltName=DNS:$server_ip,IP:$server_ip" \
                -addext "basicConstraints=critical,CA:FALSE" \
                -addext "extendedKeyUsage=serverAuth" 2>/dev/null
            chmod 600 "$key_file"
            _ok "TUIC 自签证书生成完成"
        fi
    else
        # 真实域名：尝试使用共享的 Let's Encrypt 证书
        cert_file="$CFG/certs/server.crt"
        key_file="$CFG/certs/server.key"
        
        if [[ -f "$cert_file" && -f "$key_file" ]]; then
            local cert_cn=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed 's/.*CN *= *//')
            if [[ "$cert_cn" == "$sni" ]]; then
                _ok "复用现有证书 (域名: $sni)"
            else
                _info "检测到域名变更，需要申请新证书..."
                if get_acme_cert "$sni" "tuic"; then
                    echo "$sni" > "$CFG/cert_domain"
                    _ok "证书申请成功"
                else
                    _warn "证书申请失败，使用自签证书"
                    gen_self_cert "$sni"
                fi
            fi
        else
            _info "为域名 $sni 申请证书..."
            if get_acme_cert "$sni" "tuic"; then
                echo "$sni" > "$CFG/cert_domain"
                _ok "证书申请成功"
            else
                _warn "证书申请失败，使用自签证书"
                gen_self_cert "$sni"
            fi
        fi
    fi

    cat > "$CFG/tuic.json" << EOF
{
    "server": "[::]:$port",
    "users": {
        "$uuid": "$password"
    },
    "certificate": "$cert_file",
    "private_key": "$key_file",
    "congestion_control": "bbr",
    "alpn": ["h3"],
    "zero_rtt_handshake": false,
    "auth_timeout": "3s",
    "max_idle_time": "10s",
    "max_external_packet_size": 1500,
    "gc_interval": "3s",
    "gc_lifetime": "15s",
    "log_level": "warn"
}
EOF
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件
    cat > "$CFG/tuic.info" << EOF
protocol=tuic
uuid=$uuid
password=$password
port=$port
sni=$sni
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 兼容性：也保存到主 info 文件
    cp "$CFG/tuic.info" "$CFG/info"
    
    # 注册协议
    register_protocol "tuic"

    > "$CFG/join.txt"
    if [[ -n "$ipv4" ]]; then
        local data="TUIC|$ipv4|$port|$uuid|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_tuic_link "$ipv4" "$port" "$uuid" "$password" "$sni")
        printf '%s\n' "# IPv4" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/join.txt"
        printf '%s\n' "TUIC_V4=$link" >> "$CFG/join.txt"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="TUIC|[$ipv6]|$port|$uuid|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_tuic_link "[$ipv6]" "$port" "$uuid" "$password" "$sni")
        printf '%s\n' "# IPv6" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/join.txt"
        printf '%s\n' "TUIC_V6=$link" >> "$CFG/join.txt"
    fi
    echo "server" > "$CFG/role"
    # 注意：不再写入 $CFG/protocol，因为多协议模式使用 installed_protocols 管理
}

# AnyTLS 服务端配置
gen_anytls_server_config() {
    local password="$1" port="$2" sni="${3:-bing.com}"
    mkdir -p "$CFG"
    # AnyTLS 不需要配置文件，使用命令行参数
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件
    cat > "$CFG/anytls.info" << EOF
protocol=anytls
password=$password
port=$port
sni=$sni
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 兼容性：也保存到主 info 文件
    cp "$CFG/anytls.info" "$CFG/info"
    
    # 注册协议
    register_protocol "anytls"

    > "$CFG/join.txt"
    if [[ -n "$ipv4" ]]; then
        local data="ANYTLS|$ipv4|$port|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_anytls_link "$ipv4" "$port" "$password" "$sni")
        printf '%s\n' "# IPv4" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/join.txt"
        printf '%s\n' "ANYTLS_V4=$link" >> "$CFG/join.txt"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="ANYTLS|[$ipv6]|$port|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_anytls_link "[$ipv6]" "$port" "$password" "$sni")
        printf '%s\n' "# IPv6" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/join.txt"
        printf '%s\n' "ANYTLS_V6=$link" >> "$CFG/join.txt"
    fi
    echo "server" > "$CFG/role"
    # 注意：不再写入 $CFG/protocol，因为多协议模式使用 installed_protocols 管理
}

# ShadowTLS 服务端配置
gen_shadowtls_server_config() {
    local password="$1" port="$2" method="${3:-aes-256-gcm}" sni="${4:-bing.com}" stls_password="$5"
    mkdir -p "$CFG"
    
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # ShadowTLS 需要一个后端 Shadowsocks 服务
    # 使用内部端口作为后端 SS 端口
    local ss_backend_port=$((port + 10000))
    if [[ $ss_backend_port -gt 65535 ]]; then
        ss_backend_port=$((port - 10000))
    fi
    
    # 保存到独立的 info 文件
    cat > "$CFG/shadowtls.info" << EOF
protocol=shadowtls
password=$password
port=$port
method=$method
sni=$sni
stls_password=$stls_password
ss_backend_port=$ss_backend_port
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 生成后端 Shadowsocks 配置 (使用 Xray)
    cat > "$CFG/shadowtls-ss.json" << EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": $ss_backend_port,
    "listen": "127.0.0.1",
    "protocol": "shadowsocks",
    "settings": {
      "method": "$method",
      "password": "$password",
      "network": "tcp,udp"
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}
EOF
    
    # 兼容性：也保存到主 info 文件
    cp "$CFG/shadowtls.info" "$CFG/info"
    
    # 注册协议
    register_protocol "shadowtls"

    > "$CFG/join.txt"
    if [[ -n "$ipv4" ]]; then
        local data="SHADOWTLS|$ipv4|$port|$password|$method|$sni|$stls_password"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_shadowtls_link "$ipv4" "$port" "$password" "$method" "$sni" "$stls_password")
        printf '%s\n' "# IPv4" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/join.txt"
        printf '%s\n' "SHADOWTLS_V4=$link" >> "$CFG/join.txt"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="SHADOWTLS|[$ipv6]|$port|$password|$method|$sni|$stls_password"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_shadowtls_link "[$ipv6]" "$port" "$password" "$method" "$sni" "$stls_password")
        printf '%s\n' "# IPv6" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/join.txt"
        printf '%s\n' "SHADOWTLS_V6=$link" >> "$CFG/join.txt"
    fi
    echo "server" > "$CFG/role"
    # 注意：不再写入 $CFG/protocol，因为多协议模式使用 installed_protocols 管理
}

# SOCKS5 服务端配置
gen_socks_server_config() {
    local username="$1" password="$2" port="$3"
    mkdir -p "$CFG"

    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件 (供 generate_xray_config 读取)
    cat > "$CFG/socks.info" << EOF
protocol=socks
username=$username
password=$password
port=$port
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "socks"

    # 保存 join 信息
    > "$CFG/socks.join"
    if [[ -n "$ipv4" ]]; then
        local data="SOCKS|$ipv4|$port|$username|$password"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local tg_link=$(gen_socks_link "$ipv4" "$port" "$username" "$password")
        local socks_link="socks5://${username}:${password}@${ipv4}:${port}#SOCKS5-${ipv4}"
        printf '%s\n' "# IPv4" >> "$CFG/socks.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/socks.join"
        printf '%s\n' "SOCKS_V4=$tg_link" >> "$CFG/socks.join"
        printf '%s\n' "SOCKS5_V4=$socks_link" >> "$CFG/socks.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="SOCKS|[$ipv6]|$port|$username|$password"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local tg_link="https://t.me/socks?server=[$ipv6]&port=${port}&user=${username}&pass=${password}"
        local socks_link="socks5://${username}:${password}@[$ipv6]:${port}#SOCKS5-[$ipv6]"
        printf '%s\n' "# IPv6" >> "$CFG/socks.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/socks.join"
        printf '%s\n' "SOCKS_V6=$tg_link" >> "$CFG/socks.join"
        printf '%s\n' "SOCKS5_V6=$socks_link" >> "$CFG/socks.join"
    fi
    echo "server" > "$CFG/role"
}

# Snell v5 服务端配置
gen_snell_v5_server_config() {
    local psk="$1" port="$2" version="${3:-5}"
    mkdir -p "$CFG"

    cat > "$CFG/snell-v5.conf" << EOF
[snell-server]
listen = 0.0.0.0:$port
psk = $psk
version = $version
ipv6 = true
obfs = off
EOF
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件
    cat > "$CFG/snell-v5.info" << EOF
protocol=snell-v5
psk=$psk
port=$port
version=$version
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 兼容性：也保存到主 info 文件
    cp "$CFG/snell-v5.info" "$CFG/info"
    
    # 注册协议
    register_protocol "snell-v5"

    > "$CFG/join.txt"
    if [[ -n "$ipv4" ]]; then
        local data="SNELL-V5|$ipv4|$port|$psk|$version"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_snell_v5_link "$ipv4" "$port" "$psk" "$version")
        printf '%s\n' "# IPv4" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/join.txt"
        printf '%s\n' "SNELL_V5_V4=$link" >> "$CFG/join.txt"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="SNELL-V5|[$ipv6]|$port|$psk|$version"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_snell_v5_link "[$ipv6]" "$port" "$psk" "$version")
        printf '%s\n' "# IPv6" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/join.txt"
        printf '%s\n' "SNELL_V5_V6=$link" >> "$CFG/join.txt"
    fi
    echo "server" > "$CFG/role"
    # 注意：不再写入 $CFG/protocol，因为多协议模式使用 installed_protocols 管理
}

#═══════════════════════════════════════════════════════════════════════════════
# 客户端配置生成 (支持所有协议)
#═══════════════════════════════════════════════════════════════════════════════
gen_client_config() {
    local protocol_type="$1"
    shift
    local mode=$(get_mode)
    mkdir -p "$CFG"

    local inbounds='[{"port": '$SOCKS_PORT', "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": true}}]'
    [[ "$mode" == "global" ]] && inbounds='[
        {"port": '$SOCKS_PORT', "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": true}},
        {"port": '$REDIR_PORT', "listen": "::", "protocol": "dokodemo-door", "settings": {"network": "tcp,udp", "followRedirect": true}, "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}}
    ]'

    local sockopt_json=""
    if [[ "$mode" == "tun" ]]; then
        sockopt_json='"sockopt": {"mark": '$FWMARK', "tcpKeepAliveIdle": 100},'
    fi

    case "$protocol_type" in
        vless)
            # 参数: ip port uuid pubkey sid sni
            local ip="$1" port="$2" uuid="$3" pubkey="$4" sid="$5" sni="$6"
            cat > "$CFG/config.json" << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{"address": "$ip", "port": $port, "users": [{"id": "$uuid", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
        "streamSettings": {
            $sockopt_json
            "network": "tcp", "security": "reality",
            "realitySettings": {"show": false, "fingerprint": "chrome", "serverName": "$sni", "publicKey": "$pubkey", "shortId": "$sid", "spiderX": ""}
        }
    }]
}
EOF
            cat > "$CFG/info" << EOF
protocol=vless
server_ip=$ip
port=$port
uuid=$uuid
public_key=$pubkey
short_id=$sid
sni=$sni
EOF
            ;;
        vless-xhttp)
            # 参数: ip port uuid pubkey sid sni path
            local ip="$1" port="$2" uuid="$3" pubkey="$4" sid="$5" sni="$6" path="${7:-/}"
            cat > "$CFG/config.json" << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{"address": "$ip", "port": $port, "users": [{"id": "$uuid", "encryption": "none"}]}]},
        "streamSettings": {
            $sockopt_json
            "network": "xhttp",
            "xhttpSettings": {"path": "$path", "mode": "auto"},
            "security": "reality",
            "realitySettings": {"show": false, "fingerprint": "chrome", "serverName": "$sni", "publicKey": "$pubkey", "shortId": "$sid", "spiderX": ""}
        }
    }]
}
EOF
            cat > "$CFG/info" << EOF
protocol=vless-xhttp
server_ip=$ip
port=$port
uuid=$uuid
public_key=$pubkey
short_id=$sid
sni=$sni
path=$path
EOF
            ;;
        vless-ws)
            # 参数: ip port uuid sni path
            local ip="$1" port="$2" uuid="$3" sni="$4" path="${5:-/vless}"
            cat > "$CFG/config.json" << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{"address": "$ip", "port": $port, "users": [{"id": "$uuid", "encryption": "none"}]}]},
        "streamSettings": {
            $sockopt_json
            "network": "ws",
            "security": "tls",
            "tlsSettings": {"allowInsecure": true, "serverName": "$sni"},
            "wsSettings": {"path": "$path", "headers": {"Host": "$sni"}}
        }
    }]
}
EOF
            cat > "$CFG/info" << EOF
protocol=vless-ws
server_ip=$ip
port=$port
uuid=$uuid
sni=$sni
path=$path
EOF
            ;;
        vless-grpc)
            # 参数: ip port uuid sni serviceName
            local ip="$1" port="$2" uuid="$3" sni="$4" service_name="${5:-grpc}"
            cat > "$CFG/config.json" << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{"address": "$ip", "port": $port, "users": [{"id": "$uuid", "encryption": "none"}]}]},
        "streamSettings": {
            $sockopt_json
            "network": "grpc",
            "security": "tls",
            "tlsSettings": {"allowInsecure": true, "serverName": "$sni", "alpn": ["h2"]},
            "grpcSettings": {"serviceName": "$service_name"}
        }
    }]
}
EOF
            cat > "$CFG/info" << EOF
protocol=vless-grpc
server_ip=$ip
port=$port
uuid=$uuid
sni=$sni
path=$service_name
EOF
            ;;
        vless-vision)
            # 参数: ip port uuid sni
            local ip="$1" port="$2" uuid="$3" sni="$4"
            cat > "$CFG/config.json" << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{"address": "$ip", "port": $port, "users": [{"id": "$uuid", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
        "streamSettings": {
            $sockopt_json
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {"allowInsecure": true, "serverName": "$sni", "alpn": ["h2", "http/1.1"]}
        }
    }]
}
EOF
            cat > "$CFG/info" << EOF
protocol=vless-vision
server_ip=$ip
port=$port
uuid=$uuid
sni=$sni
EOF
            ;;
        socks)
            # 参数: ip port username password
            local ip="$1" port="$2" username="$3" password="$4"
            cat > "$CFG/config.json" << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": [{
        "protocol": "socks",
        "settings": {"servers": [{"address": "$ip", "port": $port, "users": [{"user": "$username", "pass": "$password"}]}]}
    }]
}
EOF
            cat > "$CFG/info" << EOF
protocol=socks
server_ip=$ip
port=$port
username=$username
password=$password
EOF
            ;;
        ss2022)
            # 参数: ip port method password
            local ip="$1" port="$2" method="$3" password="$4"
            cat > "$CFG/config.json" << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": [{
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": "$ip", "port": $port, "method": "$method", "password": "$password"}]}
    }]
}
EOF
            cat > "$CFG/info" << EOF
protocol=ss2022
server_ip=$ip
port=$port
method=$method
password=$password
EOF
            ;;
        trojan)
            # 参数: ip port password sni
            local ip="$1" port="$2" password="$3" sni="$4"
            cat > "$CFG/config.json" << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": [{
        "protocol": "trojan",
        "settings": {"servers": [{"address": "$ip", "port": $port, "password": "$password"}]},
        "streamSettings": {
            $sockopt_json
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {"allowInsecure": true, "serverName": "$sni"}
        }
    }]
}
EOF
            cat > "$CFG/info" << EOF
protocol=trojan
server_ip=$ip
port=$port
password=$password
sni=$sni
EOF
            ;;
        hy2)
            # 参数: ip port password sni
            local ip="$1" port="$2" password="$3" sni="$4"
            cat > "$CFG/hy2.yaml" << EOF
server: $ip:$port
auth: $password
tls:
  sni: $sni
  insecure: true
socks5:
  listen: 127.0.0.1:$SOCKS_PORT
EOF
            cat > "$CFG/info" << EOF
protocol=hy2
server_ip=$ip
port=$port
password=$password
sni=$sni
EOF
            ;;
        snell)
            # 参数: ip port psk version
            local ip="$1" port="$2" psk="$3" version="${4:-4}"
            # Snell 客户端配置 (用于 Surge/Clash)
            cat > "$CFG/config.conf" << EOF
[snell-client]
server = $ip
port = $port
psk = $psk
version = $version
EOF
            cat > "$CFG/info" << EOF
protocol=snell
server_ip=$ip
port=$port
psk=$psk
version=$version
EOF
            _warn "Snell 客户端需要 Surge/Clash 等软件支持"
            ;;
        tuic)
            # 参数: ip port uuid password sni [cert_path]
            local ip="$1" port="$2" uuid="$3" password="$4" sni="$5" cert_path="${6:-}"
            local clean_ip=$(echo "$ip" | tr -d '[]')
            
            # 如果没有传入证书路径，使用默认路径
            if [[ -z "$cert_path" ]]; then
                cert_path="$CFG/certs/server.crt"
            fi
            
            cat > "$CFG/config.json" << EOF
{
    "relay": {
        "server": "$clean_ip:$port",
        "uuid": "$uuid",
        "password": "$password",
        "congestion_control": "bbr",
        "alpn": ["h3"],
        "udp_relay_mode": "native",
        "zero_rtt_handshake": false,
        "certificates": ["$cert_path"]
    },
    "local": {
        "server": "127.0.0.1:$SOCKS_PORT"
    },
    "log_level": "info"
}
EOF
            cat > "$CFG/info" << EOF
protocol=tuic
server_ip=$ip
port=$port
uuid=$uuid
password=$password
sni=$sni
cert_path=$cert_path
EOF
            ;;
        anytls)
            # 参数: ip port password sni
            local ip="$1" port="$2" password="$3" sni="$4"
            # AnyTLS 不需要配置文件，使用命令行参数
            cat > "$CFG/info" << EOF
protocol=anytls
server_ip=$ip
port=$port
password=$password
sni=$sni
EOF
            ;;
        shadowtls)
            # 参数: ip port password method sni stls_password
            local ip="$1" port="$2" password="$3" method="$4" sni="$5" stls_password="$6"
            # ShadowTLS 不需要配置文件，使用命令行参数
            cat > "$CFG/info" << EOF
protocol=shadowtls
server_ip=$ip
port=$port
password=$password
method=$method
sni=$sni
stls_password=$stls_password
EOF
            ;;
        snell-v5)
            # 参数: ip port psk version
            local ip="$1" port="$2" psk="$3" version="${4:-5}"
            # Snell v5 客户端配置 (用于 Surge/Clash)
            cat > "$CFG/config.conf" << EOF
[snell-client]
server = $ip
port = $port
psk = $psk
version = $version
EOF
            cat > "$CFG/info" << EOF
protocol=snell-v5
server_ip=$ip
port=$port
psk=$psk
version=$version
EOF
            _warn "Snell v5 客户端需要 Surge/Clash 等软件支持"
            ;;
    esac
    
    echo "client" > "$CFG/role"
    echo "$protocol_type" > "$CFG/protocol"
    
    # 客户端也需要注册协议
    register_protocol "$protocol_type"
}

#═══════════════════════════════════════════════════════════════════════════════
# 辅助脚本生成
#═══════════════════════════════════════════════════════════════════════════════
create_scripts() {
    cat > "$CFG/tun-up.sh" << EOFSCRIPT
#!/bin/bash
set -e
CFG="/etc/vless-reality"
TUN_IP="$TUN_IP"; TUN_GW="$TUN_GW"
FWMARK="$FWMARK"

ip link del tun0 2>/dev/null || true
ip route flush table 55 2>/dev/null || true
while ip rule show | grep -q "lookup 55"; do ip rule del lookup 55 2>/dev/null || true; done

mkdir -p /dev/net
[[ ! -c /dev/net/tun ]] && mknod /dev/net/tun c 10 200 2>/dev/null || true
echo 1 > /proc/sys/net/ipv4/ip_forward
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "\$f"; done

DEF_GW=\$(ip -4 route show default | grep default | head -1 | awk '{print \$3}')
DEF_DEV=\$(ip -4 route show default | grep default | head -1 | awk '{print \$5}')
LOCAL_IP=\$(ip -4 addr show dev "\$DEF_DEV" | grep "inet " | awk '{print \$2}' | cut -d/ -f1 | head -1)

if [[ -z "\$DEF_GW" || -z "\$DEF_DEV" || -z "\$LOCAL_IP" ]]; then echo "错误：无法获取物理网络信息"; exit 1; fi
echo "\$DEF_GW|\$DEF_DEV|\$LOCAL_IP" > /tmp/vless-tun-info

ip tuntap add mode tun dev tun0
ip link set dev tun0 up mtu 1280
ip -4 addr add \$TUN_IP/30 dev tun0

ip route add default via "\$DEF_GW" dev "\$DEF_DEV" table 55
ip rule add fwmark \$FWMARK lookup 55 pref 900
ip rule add from "\$LOCAL_IP" lookup 55 pref 1000

# 获取服务器 IP 并添加直连路由 (增强兼容性)
SERVER_IP=\$(grep "server_ip=" "\$CFG/info" 2>/dev/null | cut -d= -f2 | tr -d '[]')
if [[ -n "\$SERVER_IP" ]]; then
    # 检查是否为 IPv4
    if [[ "\$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip -4 route add "\$SERVER_IP" via "\$DEF_GW" dev "\$DEF_DEV" 2>/dev/null || true
        echo "\$SERVER_IP" > /tmp/vless-tun-routes
    # 检查是否为 IPv6
    elif [[ "\$SERVER_IP" =~ : ]]; then
        # IPv6 暂不处理，TUN 模式主要用于 IPv4
        echo "IPv6 服务器，跳过路由添加" >&2
    else
        # 域名，尝试解析
        RESOLVED_IP=""
        if command -v dig &>/dev/null; then
            RESOLVED_IP=\$(dig +short "\$SERVER_IP" A 2>/dev/null | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" | head -1)
        fi
        if [[ -z "\$RESOLVED_IP" ]] && command -v getent &>/dev/null; then
            RESOLVED_IP=\$(getent ahostsv4 "\$SERVER_IP" 2>/dev/null | awk '{print \$1}' | head -1)
        fi
        if [[ -z "\$RESOLVED_IP" ]] && command -v nslookup &>/dev/null; then
            RESOLVED_IP=\$(nslookup "\$SERVER_IP" 2>/dev/null | awk '/^Address: / { print \$2 }' | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" | head -1)
        fi
        
        if [[ -n "\$RESOLVED_IP" && "\$RESOLVED_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            ip -4 route add "\$RESOLVED_IP" via "\$DEF_GW" dev "\$DEF_DEV" 2>/dev/null || true
            echo "\$RESOLVED_IP" > /tmp/vless-tun-routes
        else
            echo "警告：无法解析服务器地址 \$SERVER_IP" >&2
        fi
    fi
fi

ip -4 route add 0.0.0.0/1 via \$TUN_GW dev tun0
ip -4 route add 128.0.0.0/1 via \$TUN_GW dev tun0
echo "TUN 模式启动成功"
EOFSCRIPT

    cat > "$CFG/tun-down.sh" << EOFSCRIPT
#!/bin/bash
CFG="/etc/vless-reality"
TUN_GW="$TUN_GW"
FWMARK="$FWMARK"

ip -4 route del 0.0.0.0/1 via \$TUN_GW dev tun0 2>/dev/null || true
ip -4 route del 128.0.0.0/1 via \$TUN_GW dev tun0 2>/dev/null || true

if [[ -f /tmp/vless-tun-info ]]; then
    IFS='|' read -r DEF_GW DEF_DEV LOCAL_IP < /tmp/vless-tun-info
    ip rule del fwmark \$FWMARK lookup 55 2>/dev/null || true
    if [[ -n "\$LOCAL_IP" ]]; then ip rule del from "\$LOCAL_IP" lookup 55 2>/dev/null || true; fi
    ip route flush table 55 2>/dev/null || true
    if [[ -f /tmp/vless-tun-routes ]]; then
        while read -r ip; do
            [[ -n "\$ip" ]] && { ip -4 route del "\$ip" via "\$DEF_GW" dev "\$DEF_DEV" 2>/dev/null || true; }
        done < /tmp/vless-tun-routes
    fi
    rm -f /tmp/vless-tun-info /tmp/vless-tun-routes
fi
ip link del tun0 2>/dev/null || true
echo "TUN 已停止"
EOFSCRIPT

    cat > "$CFG/watchdog.sh" << 'EOFSCRIPT'
#!/bin/bash
CFG="/etc/vless-reality"
LOG_FILE="/var/log/vless-watchdog.log"
FAIL_COUNT=0
MAX_FAIL=3

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"; }

restart_service() {
    local svc="$1"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart "$svc"
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service "$svc" restart
    else
        return 1
    fi
}

# 获取所有需要监控的服务 (支持多协议)
get_all_services() {
    local services=""
    
    if [[ -f "$CFG/installed_protocols" ]]; then
        # Xray 协议列表
        local xray_protos="vless vless-xhttp vless-ws vmess-ws vless-vision trojan socks ss2022"
        local has_xray=false
        
        for proto in $xray_protos; do
            if grep -q "^$proto$" "$CFG/installed_protocols" 2>/dev/null; then
                has_xray=true
                break
            fi
        done
        
        [[ "$has_xray" == "true" ]] && services+="vless-reality:xray "
        
        # 检查独立协议
        grep -q "^hy2$" "$CFG/installed_protocols" 2>/dev/null && services+="vless-hy2:hysteria "
        grep -q "^tuic$" "$CFG/installed_protocols" 2>/dev/null && services+="vless-tuic:tuic-server "
        grep -q "^snell$" "$CFG/installed_protocols" 2>/dev/null && services+="vless-snell:snell-server "
        grep -q "^snell-v5$" "$CFG/installed_protocols" 2>/dev/null && services+="vless-snell-v5:snell-server-v5 "
        grep -q "^anytls$" "$CFG/installed_protocols" 2>/dev/null && services+="vless-anytls:anytls-server "
        grep -q "^shadowtls$" "$CFG/installed_protocols" 2>/dev/null && services+="vless-shadowtls:shadow-tls "
    else
        # 回退到旧的单协议模式
        local proto=$(cat "$CFG/protocol" 2>/dev/null)
        case "$proto" in
            vless|vless-xhttp|vless-ws|vless-grpc|vmess-ws|vless-vision|trojan|socks|ss2022)
                services="vless-reality:xray"
                ;;
            hy2)
                services="vless-hy2:hysteria"
                ;;
            tuic)
                services="vless-tuic:tuic-client"
                ;;
            snell)
                services="vless-snell:snell-server"
                ;;
            snell-v5)
                services="vless-snell-v5:snell-server-v5"
                ;;
            anytls)
                services="vless-anytls:anytls-client"
                ;;
            shadowtls)
                services="vless-shadowtls:shadow-tls"
                ;;
            *)
                services="vless-reality:xray"
                ;;
        esac
    fi
    
    echo "$services"
}

while true; do
    # 监控所有服务的进程状态
    for svc_info in $(get_all_services); do
        IFS=':' read -r svc_name proc_name <<< "$svc_info"
        if ! pgrep -x "$proc_name" > /dev/null; then
            log "CRITICAL: $proc_name process dead. Restarting $svc_name..."
            restart_service "$svc_name"
            sleep 5
        fi
    done
    
    # 连接测试 (仅客户端模式)
    if [[ -f "$CFG/role" ]] && [[ "$(cat "$CFG/role")" == "client" ]]; then
        if curl -x socks5://127.0.0.1:10808 -s --connect-timeout 5 https://www.cloudflare.com > /dev/null; then
            FAIL_COUNT=0
        else
            FAIL_COUNT=$((FAIL_COUNT+1))
            log "WARNING: Connection failed ($FAIL_COUNT/$MAX_FAIL)"
        fi
        
        if [[ $FAIL_COUNT -ge $MAX_FAIL ]]; then
            log "ERROR: Max failures reached. Restarting services..."
            if [[ -f "$CFG/mode" && "$(cat "$CFG/mode")" == "tun" ]]; then
                restart_service vless-tun
            fi
            # 重启所有服务
            for svc_info in $(get_all_services); do
                IFS=':' read -r svc_name proc_name <<< "$svc_info"
                restart_service "$svc_name"
            done
            FAIL_COUNT=0
            sleep 20
        fi
    fi
    
    sleep 60
done
EOFSCRIPT

    cat > "$CFG/global-up.sh" << 'EOFSCRIPT'
#!/bin/bash
CFG="/etc/vless-reality"; REDIR_PORT=10809

# 从 info 文件读取服务器 IP（兼容所有协议）
if [[ -f "$CFG/info" ]]; then
    PROXY_HOST=$(grep "^server_ip=" "$CFG/info" | cut -d'=' -f2 | tr -d '[]')
else
    # 回退到 Xray 配置格式
    PROXY_HOST=$(jq -r '.outbounds[0].settings.vnext[0].address // .outbounds[0].settings.servers[0].address // empty' "$CFG/config.json" 2>/dev/null)
fi

[[ -z "$PROXY_HOST" ]] && { echo "无法获取服务器地址"; exit 1; }

PROXY_IP4=$(getent ahostsv4 "$PROXY_HOST" 2>/dev/null | awk '{print $1}' | sort -u || echo "$PROXY_HOST")
PROXY_IP6=$(getent ahostsv6 "$PROXY_HOST" 2>/dev/null | awk '{print $1}' | sort -u)
iptables -t nat -F VLESS_PROXY 2>/dev/null; iptables -t nat -X VLESS_PROXY 2>/dev/null; iptables -t nat -N VLESS_PROXY
for cidr in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do iptables -t nat -A VLESS_PROXY -d $cidr -j RETURN; done
for ip in $PROXY_IP4; do iptables -t nat -A VLESS_PROXY -d "$ip" -j RETURN; done
iptables -t nat -A VLESS_PROXY -p tcp -j REDIRECT --to-ports $REDIR_PORT
iptables -t nat -D OUTPUT -p tcp -j VLESS_PROXY 2>/dev/null; iptables -t nat -A OUTPUT -p tcp -j VLESS_PROXY
ip6tables -t nat -F VLESS_PROXY 2>/dev/null; ip6tables -t nat -X VLESS_PROXY 2>/dev/null; ip6tables -t nat -N VLESS_PROXY
for cidr in ::1/128 fe80::/10 fc00::/7; do ip6tables -t nat -A VLESS_PROXY -d $cidr -j RETURN; done
for ip in $PROXY_IP6; do ip6tables -t nat -A VLESS_PROXY -d "$ip" -j RETURN; done
ip6tables -t nat -A VLESS_PROXY -p tcp -j REDIRECT --to-ports $REDIR_PORT
ip6tables -t nat -D OUTPUT -p tcp -j VLESS_PROXY 2>/dev/null; ip6tables -t nat -A OUTPUT -p tcp -j VLESS_PROXY
EOFSCRIPT

    cat > "$CFG/global-down.sh" << 'EOFSCRIPT'
#!/bin/bash
iptables -t nat -D OUTPUT -p tcp -j VLESS_PROXY 2>/dev/null
iptables -t nat -F VLESS_PROXY 2>/dev/null; iptables -t nat -X VLESS_PROXY 2>/dev/null
ip6tables -t nat -D OUTPUT -p tcp -j VLESS_PROXY 2>/dev/null
ip6tables -t nat -F VLESS_PROXY 2>/dev/null; ip6tables -t nat -X VLESS_PROXY 2>/dev/null
EOFSCRIPT

    # === Hysteria2 端口跳跃规则脚本 ===
    # 只有当安装了 hy2 时才生成
    if grep -q "^hy2$" "$CFG/installed_protocols" 2>/dev/null; then
        cat > "$CFG/hy2-nat.sh" << 'EOFSCRIPT'
#!/bin/bash
CFG=/etc/vless-reality

# 未安装/无 info 直接退出
[[ ! -f "$CFG/hy2.info" ]] && exit 0
source "$CFG/hy2.info" 2>/dev/null

# 兜底默认值
hop_start="${hop_start:-20000}"
hop_end="${hop_end:-50000}"

# 简单校验
if ! [[ "$hop_start" =~ ^[0-9]+$ && "$hop_end" =~ ^[0-9]+$ ]] || [[ "$hop_start" -ge "$hop_end" ]]; then
  exit 0
fi

# 先尝试删除旧规则（无论开关状态）
iptables -t nat -D PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null
iptables -t nat -D OUTPUT -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null

# 如果关闭了端口跳跃，清理完规则后直接退出
[[ "${hop_enable:-0}" != "1" ]] && exit 0

# 将指定 UDP 范围重定向到 hy2 主端口
iptables -t nat -C PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null \
  || iptables -t nat -A PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port

iptables -t nat -C OUTPUT -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null \
  || iptables -t nat -A OUTPUT -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port
EOFSCRIPT
    fi

    chmod +x "$CFG"/*.sh
}


#═══════════════════════════════════════════════════════════════════════════════
# 服务管理
#═══════════════════════════════════════════════════════════════════════════════
create_service() {
    local role=$(get_role) mode=$(get_mode)
    # 支持传入协议参数，否则使用 get_protocol 获取
    local protocol="${1:-$(get_protocol)}"
    
    # 清除可能残留的变量
    local port="" password="" sni="" stls_password="" server_ip=""
    
    # 根据协议和角色确定启动命令
    local exec_cmd exec_name
    if [[ "$role" == "server" ]]; then
        case "$protocol" in
            vless|vless-xhttp|vless-ws|vless-grpc|vmess-ws|vless-vision|trojan)
                exec_cmd="/usr/local/bin/xray run -c $CFG/config.json"
                exec_name="xray"
                ;;
            socks|ss2022)
                exec_cmd="/usr/local/bin/xray run -c $CFG/config.json"
                exec_name="xray"
                ;;
            hy2)
                exec_cmd="/usr/local/bin/hysteria server -c $CFG/hy2.yaml"
                exec_name="hysteria"
                ;;
            snell)
                exec_cmd="/usr/local/bin/snell-server -c $CFG/snell.conf"
                exec_name="snell-server"
                ;;
            snell-v5)
                exec_cmd="/usr/local/bin/snell-server-v5 -c $CFG/snell-v5.conf"
                exec_name="snell-server-v5"
                ;;
            tuic)
                exec_cmd="/usr/local/bin/tuic-server -c $CFG/tuic.json"
                exec_name="tuic-server"
                ;;
            anytls)
                # 确保配置文件存在并加载
                if [[ ! -f "$CFG/anytls.info" ]]; then
                    _err "AnyTLS 配置文件不存在: $CFG/anytls.info"
                    return 1
                fi
                source "$CFG/anytls.info"
                # 验证必要参数
                if [[ -z "$port" || -z "$password" ]]; then
                    _err "AnyTLS 配置不完整: port=$port, password=$password"
                    return 1
                fi
                exec_cmd="/usr/local/bin/anytls-server -l 0.0.0.0:${port} -p ${password}"
                exec_name="anytls-server"
                ;;
            shadowtls)
                # 确保配置文件存在并加载
                if [[ ! -f "$CFG/shadowtls.info" ]]; then
                    _err "ShadowTLS 配置文件不存在: $CFG/shadowtls.info"
                    return 1
                fi
                source "$CFG/shadowtls.info"
                # 验证必要参数
                if [[ -z "$port" || -z "$stls_password" ]]; then
                    _err "ShadowTLS 配置不完整: port=$port, stls_password=$stls_password"
                    return 1
                fi
                # ShadowTLS 服务：监听外部端口，转发到本地 SS 后端
                exec_cmd="/usr/local/bin/shadow-tls --v3 server --listen 0.0.0.0:${port} --server 127.0.0.1:${ss_backend_port:-26182} --tls ${sni:-www.microsoft.com}:443 --password ${stls_password}"
                exec_name="shadow-tls"
                ;;
        esac
    else
        # 客户端
        case "$protocol" in
            vless|vless-xhttp|vless-ws|vless-grpc|vmess-ws|vless-vision|trojan)
                exec_cmd="/usr/local/bin/xray run -c $CFG/config.json"
                exec_name="xray"
                ;;
            socks|ss2022)
                exec_cmd="/usr/local/bin/xray run -c $CFG/config.json"
                exec_name="xray"
                ;;
            hy2)
                exec_cmd="/usr/local/bin/hysteria client -c $CFG/hy2.yaml"
                exec_name="hysteria"
                ;;
            snell)
                # Snell 客户端需要 Surge/Clash，这里只是占位
                exec_cmd="echo 'Snell client requires Surge/Clash'"
                exec_name="snell-client"
                ;;
            snell-v5)
                # Snell v5 客户端需要 Surge/Clash，这里只是占位
                exec_cmd="echo 'Snell v5 client requires Surge/Clash'"
                exec_name="snell-v5-client"
                ;;
            tuic)
                exec_cmd="/usr/local/bin/tuic-client -c $CFG/config.json"
                exec_name="tuic-client"
                ;;
            anytls)
                if [[ -f "$CFG/info" ]]; then
                    source "$CFG/info"
                fi
                exec_cmd="/usr/local/bin/anytls-client -l 127.0.0.1:$SOCKS_PORT -s ${server_ip:-}:${port:-} -p ${password:-}"
                exec_name="anytls-client"
                ;;
            shadowtls)
                if [[ -f "$CFG/info" ]]; then
                    source "$CFG/info"
                fi
                # ShadowTLS 客户端监听内部端口，SS 客户端连接它
                local stls_listen_port=$((SOCKS_PORT + 1))  # 10809
                exec_cmd="/usr/local/bin/shadow-tls --v3 client --listen 127.0.0.1:${stls_listen_port} --server ${server_ip:-}:${port:-} --sni ${sni:-www.microsoft.com} --password ${stls_password:-}"
                exec_name="shadow-tls"
                ;;
        esac
    fi
    
    # 对于 Xray 协议，使用统一的服务名；对于独立协议，使用独立服务名
    local service_name
    if echo "$XRAY_PROTOCOLS" | grep -q "$protocol"; then
        service_name="vless-reality"
    else
        service_name="vless-${protocol}"
    fi
    
    if [[ "$DISTRO" == "alpine" ]]; then
        # 处理 OpenRC 的 command/args，避免无参数时 command_args 变成整条命令
        local openrc_cmd="${exec_cmd%% *}"
        local openrc_args=""
        [[ "$exec_cmd" == *" "* ]] && openrc_args="${exec_cmd#* }"

        # 根据是否有参数生成不同的服务文件 (修复空参数问题)
        if [[ -n "$openrc_args" ]]; then
            cat > /etc/init.d/${service_name} << EOF
#!/sbin/openrc-run
name="Proxy Server ($protocol)"
command="${openrc_cmd}"
command_args="${openrc_args}"
command_background="yes"
pidfile="/run/${service_name}.pid"
depend() { need net; }
EOF
        else
            cat > /etc/init.d/${service_name} << EOF
#!/sbin/openrc-run
name="Proxy Server ($protocol)"
command="${openrc_cmd}"
command_background="yes"
pidfile="/run/${service_name}.pid"
depend() { need net; }
EOF
        fi
        chmod +x /etc/init.d/${service_name}
        
        # ShadowTLS 需要额外的后端 Shadowsocks 服务 (OpenRC)
        if [[ "$protocol" == "shadowtls" && "$role" == "server" ]]; then
            cat > /etc/init.d/vless-shadowtls-ss << EOF
#!/sbin/openrc-run
name="ShadowTLS Backend Shadowsocks"
command="/usr/local/bin/xray"
command_args="run -c $CFG/shadowtls-ss.json"
command_background="yes"
pidfile="/run/vless-shadowtls-ss.pid"
depend() { need net; before vless-shadowtls; }
EOF
            chmod +x /etc/init.d/vless-shadowtls-ss
        fi

        if [[ "$role" == "client" ]]; then
            # Watchdog (OpenRC)
            cat > /etc/init.d/vless-watchdog << EOF
#!/sbin/openrc-run
name="Proxy Connection Watchdog"
command="/bin/bash"
command_args="$CFG/watchdog.sh"
command_background="yes"
pidfile="/run/vless-watchdog.pid"
depend() { need ${service_name}; }
EOF
            chmod +x /etc/init.d/vless-watchdog

            # Global mode (OpenRC oneshot)
            if [[ "$mode" == "global" ]]; then
                cat > /etc/init.d/vless-global << EOF
#!/sbin/openrc-run
name="VLESS Global Proxy"
depend() { need ${service_name}; }
start() { ebegin "Enable global proxy"; /bin/bash $CFG/global-up.sh; eend \$?; }
stop()  { ebegin "Disable global proxy"; /bin/bash $CFG/global-down.sh; eend \$?; }
EOF
                chmod +x /etc/init.d/vless-global
            fi

            if [[ "$mode" == "tun" ]]; then
                cat > /etc/init.d/vless-tun << EOF
#!/sbin/openrc-run
name="VLESS TUN"
command="/usr/local/bin/tun2socks"
command_args="-device tun0 -proxy socks5://127.0.0.1:10808 -loglevel silent"
command_background="yes"
pidfile="/run/vless-tun.pid"
depend() { need ${service_name}; }
start_pre() { /etc/vless-reality/tun-up.sh; }
stop_post() { /etc/vless-reality/tun-down.sh; }
EOF
                chmod +x /etc/init.d/vless-tun
            fi
        fi
    else
        # 为 Hysteria2 添加端口跳跃支持
        if [[ "$protocol" == "hy2" && "$role" == "server" ]]; then
            cat > /etc/systemd/system/${service_name}.service << EOF
[Unit]
Description=Proxy Server ($protocol)
After=network.target

[Service]
Type=simple
ExecStartPre=-/bin/bash $CFG/hy2-nat.sh
ExecStart=$exec_cmd
Restart=always
RestartSec=3
LimitNOFILE=51200
[Install]
WantedBy=multi-user.target
EOF
        else
            cat > /etc/systemd/system/${service_name}.service << EOF
[Unit]
Description=Proxy Server ($protocol)
After=network.target

[Service]
Type=simple
ExecStart=$exec_cmd
Restart=always
RestartSec=3
LimitNOFILE=51200
[Install]
WantedBy=multi-user.target
EOF
        fi
        
        # ShadowTLS 需要额外的后端 Shadowsocks 服务
        if [[ "$protocol" == "shadowtls" && "$role" == "server" ]]; then
            cat > /etc/systemd/system/vless-shadowtls-ss.service << EOF
[Unit]
Description=ShadowTLS Backend Shadowsocks
After=network.target
Before=vless-shadowtls.service

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -c $CFG/shadowtls-ss.json
Restart=always
RestartSec=3
LimitNOFILE=51200
[Install]
WantedBy=multi-user.target
EOF
        fi
        
        # ShadowTLS 客户端需要额外的 SS 客户端服务
        if [[ "$protocol" == "shadowtls" && "$role" == "client" ]]; then
            # 生成 SS 客户端配置
            local stls_listen_port=$((SOCKS_PORT + 1))  # 10809
            if [[ -f "$CFG/info" ]]; then
                source "$CFG/info"
            fi
            cat > "$CFG/shadowtls-ss-client.json" << EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": $SOCKS_PORT,
    "listen": "127.0.0.1",
    "protocol": "socks",
    "settings": {"udp": true}
  }],
  "outbounds": [{
    "protocol": "shadowsocks",
    "settings": {
      "servers": [{
        "address": "127.0.0.1",
        "port": ${stls_listen_port},
        "method": "${method:-aes-256-gcm}",
        "password": "${password:-}"
      }]
    }
  }]
}
EOF
            cat > /etc/systemd/system/vless-shadowtls-ss.service << EOF
[Unit]
Description=ShadowTLS SS Client
After=vless-shadowtls.service
Requires=vless-shadowtls.service

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -c $CFG/shadowtls-ss-client.json
Restart=always
RestartSec=3
LimitNOFILE=51200
[Install]
WantedBy=multi-user.target
EOF
        fi
        
        if [[ "$role" == "client" ]]; then
            cat > /etc/systemd/system/vless-watchdog.service << EOF
[Unit]
Description=Proxy Connection Watchdog
After=${service_name}.service
[Service]
Type=simple
ExecStart=$CFG/watchdog.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF
            if [[ "$mode" == "tun" ]]; then
                cat > /etc/systemd/system/vless-tun.service << EOF
[Unit]
Description=Proxy TUN
After=${service_name}.service
Requires=${service_name}.service
[Service]
Type=simple
ExecStartPre=$CFG/tun-up.sh
ExecStart=/usr/local/bin/tun2socks -device tun0 -proxy socks5://127.0.0.1:$SOCKS_PORT -loglevel silent
ExecStopPost=$CFG/tun-down.sh
Restart=always
RestartSec=5
LimitNOFILE=51200
[Install]
WantedBy=multi-user.target
EOF
            elif [[ "$mode" == "global" ]]; then
                cat > /etc/systemd/system/vless-global.service << EOF
[Unit]
Description=Proxy Global
After=${service_name}.service
Requires=${service_name}.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$CFG/global-up.sh
ExecStop=$CFG/global-down.sh
[Install]
WantedBy=multi-user.target
EOF
            fi
        fi
        systemctl daemon-reload
    fi
}

svc() {
    local action="$1" name="$2"
    if [[ "$DISTRO" == "alpine" ]]; then
        case "$action" in
            start)   
                if ! rc-service "$name" start 2>/tmp/svc_error.log; then
                    [[ -s /tmp/svc_error.log ]] && { _err "服务启动失败:"; cat /tmp/svc_error.log; }
                    rm -f /tmp/svc_error.log
                    return 1
                fi
                ;;
            stop)    rc-service "$name" stop &>/dev/null ;;
            enable)  rc-update add "$name" default &>/dev/null ;;
            restart) 
                if ! rc-service "$name" restart 2>/tmp/svc_error.log; then
                    [[ -s /tmp/svc_error.log ]] && { _err "服务重启失败:"; cat /tmp/svc_error.log; }
                    rm -f /tmp/svc_error.log
                    return 1
                fi
                ;;
            reload)
                # Alpine/OpenRC：优先 reload，失败则 restart
                if ! rc-service "$name" reload 2>/tmp/svc_error.log; then
                    rm -f /tmp/svc_error.log
                    rc-service "$name" restart &>/dev/null || return 1
                else
                    rm -f /tmp/svc_error.log
                fi
                ;;
            status)
                # OpenRC 的 status 返回值可能不可靠，增加 pidfile 检查作为回退
                if rc-service "$name" status &>/dev/null; then
                    return 0
                else
                    # 回退检查：通过 pidfile 验证进程是否存在
                    local pidfile="/run/${name}.pid"
                    if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile" 2>/dev/null)" 2>/dev/null; then
                        return 0
                    fi
                    return 1
                fi
                ;;
        esac
    else
        case "$action" in
            start)   
                if ! systemctl start "$name" 2>/tmp/svc_error.log; then
                    [[ -s /tmp/svc_error.log ]] && { _err "服务启动失败:"; cat /tmp/svc_error.log; }
                    # 额外显示 systemctl status 信息
                    _err "详细状态信息:"
                    systemctl status "$name" --no-pager -l || true
                    rm -f /tmp/svc_error.log
                    return 1
                fi
                ;;
            stop)    systemctl stop "$name" &>/dev/null ;;
            enable)  systemctl enable "$name" &>/dev/null ;;
            restart) 
                if ! systemctl restart "$name" 2>/tmp/svc_error.log; then
                    [[ -s /tmp/svc_error.log ]] && { _err "服务重启失败:"; cat /tmp/svc_error.log; }
                    _err "详细状态信息:"
                    systemctl status "$name" --no-pager -l || true
                    rm -f /tmp/svc_error.log
                    return 1
                fi
                ;;
            reload)
                # systemd：优先 reload，失败则 restart
                if ! systemctl reload "$name" 2>/tmp/svc_error.log; then
                    rm -f /tmp/svc_error.log
                    systemctl restart "$name" &>/dev/null || return 1
                else
                    rm -f /tmp/svc_error.log
                fi
                ;;
            status)  
                # active 或 activating 都算运行中
                local state=$(systemctl is-active "$name" 2>/dev/null)
                [[ "$state" == "active" || "$state" == "activating" ]]
                ;;
        esac
    fi
}

start_services() {
    local role=$(get_role) mode=$(get_mode)
    local failed_services=()
    rm -f "$CFG/paused"
    
    if [[ "$role" == "server" ]]; then
        # 服务端：启动所有已注册的协议服务
        
        # 启动 Xray 服务（如果有 Xray 协议）
        local xray_protocols=$(get_xray_protocols)
        if [[ -n "$xray_protocols" ]]; then
            # 检查 Xray 服务是否已经在运行
            if svc status vless-reality >/dev/null 2>&1; then
                # 服务已运行，重新生成配置并重启
                _info "更新 Xray 配置..."
                if ! generate_xray_config; then
                    _err "Xray 配置生成失败"
                    failed_services+=("vless-reality")
                else
                    # 重启服务以应用新配置
                    if ! svc restart vless-reality; then
                        _err "Xray 服务重启失败，请检查上述错误信息"
                        failed_services+=("vless-reality")
                    else
                        # 等待并验证进程
                        sleep 2
                        if pgrep -x xray >/dev/null; then
                            local xray_list=$(echo $xray_protocols | tr '\n' ' ')
                            _ok "Xray 服务已更新 (协议: $xray_list)"
                        else
                            _err "Xray 进程未运行"
                            failed_services+=("vless-reality")
                        fi
                    fi
                fi
            else
                # 服务未运行，生成配置并启动
                if ! generate_xray_config; then
                    _err "Xray 配置生成失败"
                    failed_services+=("vless-reality")
                else
                    svc enable vless-reality
                    if ! svc start vless-reality; then
                        _err "Xray 服务启动失败，请检查上述错误信息"
                        failed_services+=("vless-reality")
                    else
                        # 等待并验证进程
                        sleep 2
                        if pgrep -x xray >/dev/null; then
                            local xray_list=$(echo $xray_protocols | tr '\n' ' ')
                            _ok "Xray 服务已启动 (协议: $xray_list)"
                        else
                            _err "Xray 进程未运行"
                            failed_services+=("vless-reality")
                        fi
                    fi
                fi
            fi
        fi
        
        # 启动独立协议服务（即使 Xray 失败也继续）
        local independent_protocols=$(get_independent_protocols)
        local ind_proto
        for ind_proto in $independent_protocols; do
            local service_name="vless-${ind_proto}"
            
            # ShadowTLS 需要先启动后端 SS 服务
            if [[ "$ind_proto" == "shadowtls" ]]; then
                svc enable "vless-shadowtls-ss"
                if ! svc start "vless-shadowtls-ss"; then
                    _err "ShadowTLS 后端 SS 服务启动失败"
                    failed_services+=("vless-shadowtls-ss")
                    continue
                fi
                sleep 1
            fi
            
            svc enable "$service_name"
            
            # 检查服务是否已经在运行
            if svc status "$service_name" >/dev/null 2>&1; then
                _ok "$ind_proto 服务已在运行"
            else
                if ! svc start "$service_name"; then
                    _err "$ind_proto 服务启动失败"
                    failed_services+=("$service_name")
                else
                    sleep 1
                    _ok "$ind_proto 服务已启动"
                fi
            fi
        done
        
        # 报告结果
        if [[ ${#failed_services[@]} -gt 0 ]]; then
            _warn "以下服务启动失败: ${failed_services[*]}"
            return 1
        fi
    else
        # 客户端：根据协议类型启动对应服务
        local protocol=$(cat "$CFG/protocol" 2>/dev/null)
        local service_name
        
        if echo "$XRAY_PROTOCOLS" | grep -qw "$protocol"; then
            service_name="vless-reality"
        else
            service_name="vless-${protocol}"
        fi
        
        svc enable "$service_name"
        if ! svc start "$service_name"; then
            _err "$protocol 服务启动失败"
            # 显示详细错误信息
            _err "详细状态信息:"
            if [[ "$DISTRO" == "alpine" ]]; then
                rc-service "$service_name" status 2>/dev/null || true
            else
                systemctl status "$service_name" --no-pager -l 2>/dev/null || true
            fi
            return 1
        fi
        _ok "$protocol 服务已启动"
        
        # ShadowTLS 客户端需要启动 SS 客户端服务
        if [[ "$protocol" == "shadowtls" ]]; then
            svc enable "vless-shadowtls-ss"
            if ! svc start "vless-shadowtls-ss"; then
                _err "ShadowTLS SS 客户端服务启动失败"
                return 1
            fi
            sleep 1
            _ok "ShadowTLS SS 客户端已启动"
        fi
        
        # 客户端额外服务（Watchdog）
        # Snell/Snell-v5 仅支持 Socks 模式，不启用 watchdog
        if [[ "$protocol" != "snell" && "$protocol" != "snell-v5" ]]; then
            svc enable vless-watchdog
            svc start vless-watchdog
        fi

        case "$mode" in
            tun)
                [[ ! -x "/usr/local/bin/tun2socks" ]] && { _err "tun2socks 未安装"; return 1; }
                svc enable vless-tun
                svc start vless-tun || { _err "TUN 启动失败"; return 1; }
                ;;
            global)
                svc enable vless-global
                svc start vless-global || { _err "全局代理启动失败"; return 1; }
                ;;
            socks)
                echo ""
                _line
                _ok "SOCKS5代理已启动"
                _line
                ;;
        esac
    fi
    
    return 0
}

stop_services() {
    local stopped_services=()
    
    # 定义检查服务状态的函数（兼容 Alpine 和 systemd）
    is_service_active() {
        local svc_name="$1"
        if [[ "$DISTRO" == "alpine" ]]; then
            rc-service "$svc_name" status &>/dev/null
        else
            systemctl is-active --quiet "$svc_name" 2>/dev/null
        fi
    }
    
    # 检查并停止各种服务
    if is_service_active vless-watchdog; then
        svc stop vless-watchdog 2>/dev/null && stopped_services+=("vless-watchdog")
    fi
    
    if is_service_active vless-tun; then
        svc stop vless-tun 2>/dev/null && stopped_services+=("vless-tun")
    fi
    
    if is_service_active vless-global; then
        svc stop vless-global 2>/dev/null && stopped_services+=("vless-global")
    fi
    
    if is_service_active vless-reality; then
        svc stop vless-reality 2>/dev/null && stopped_services+=("vless-reality")
    fi
    
    # 停止所有独立协议服务
    for proto in $INDEPENDENT_PROTOCOLS; do
        local service_name="vless-${proto}"
        if is_service_active "$service_name"; then
            svc stop "$service_name" 2>/dev/null && stopped_services+=("$service_name")
        fi
    done
    
    # 停止 ShadowTLS 后端 SS 服务
    if is_service_active vless-shadowtls-ss; then
        svc stop vless-shadowtls-ss 2>/dev/null && stopped_services+=("vless-shadowtls-ss")
    fi
    
    # 清理 Hysteria2 端口跳跃 NAT 规则
    cleanup_hy2_nat_rules
    
    # 清理网络接口
    if ip link show tun0 &>/dev/null; then
        ip link del tun0 &>/dev/null && stopped_services+=("tun0接口")
    fi
    
    # 显示停止的服务
    if [[ ${#stopped_services[@]} -gt 0 ]]; then
        echo "  ▸ 已停止服务: ${stopped_services[*]}"
    else
        echo "  ▸ 没有运行中的服务需要停止"
    fi
}

# 清理 Hysteria2 端口跳跃 NAT 规则
cleanup_hy2_nat_rules() {
    # 尝试从配置文件读取
    if [[ -f "$CFG/hy2.info" ]]; then
        local hop_start="" hop_end="" port=""
        source "$CFG/hy2.info" 2>/dev/null
        local hs="${hop_start:-20000}"
        local he="${hop_end:-50000}"
        local p="${port:-}"
        
        if [[ -n "$p" ]]; then
            iptables -t nat -D PREROUTING -p udp --dport ${hs}:${he} -j REDIRECT --to-ports ${p} 2>/dev/null
            iptables -t nat -D OUTPUT -p udp --dport ${hs}:${he} -j REDIRECT --to-ports ${p} 2>/dev/null
        fi
    fi
}

create_shortcut() {
    local system_script="/usr/local/bin/vless.sh"
    local current_script="$0"

    # 获取当前脚本的绝对路径
    local real_path
    if [[ "$current_script" == /* ]]; then
        real_path="$current_script"
    elif [[ "$current_script" == "bash" || "$current_script" == "-bash" ]]; then
        # 内存运行模式 (curl | bash)，从网络下载
        real_path=""
    else
        real_path="$(cd "$(dirname "$current_script")" 2>/dev/null && pwd)/$(basename "$current_script")"
    fi

    # 如果系统目录没有脚本，需要创建
    if [[ ! -f "$system_script" ]]; then
        if [[ -n "$real_path" && -f "$real_path" ]]; then
            # 从当前脚本复制（不删除原文件）
            cp -f "$real_path" "$system_script"
        else
            # 内存运行模式，从网络下载
            local raw_url="https://raw.githubusercontent.com/Chil30/vless-all-in-one/main/vless.sh"
            if ! curl -sL --connect-timeout 10 -o "$system_script" "$raw_url"; then
                _warn "无法下载脚本到系统目录"
                return 1
            fi
        fi
    elif [[ -n "$real_path" && -f "$real_path" && "$real_path" != "$system_script" ]]; then
        # 系统目录已有脚本，用当前脚本更新（不删除原文件）
        cp -f "$real_path" "$system_script"
    fi

    chmod +x "$system_script" 2>/dev/null

    # 创建软链接
    ln -sf "$system_script" /usr/local/bin/vless 2>/dev/null
    ln -sf "$system_script" /usr/bin/vless 2>/dev/null
    hash -r 2>/dev/null

    _ok "快捷命令已创建: vless"
}

remove_shortcut() { 
    rm -f /usr/local/bin/vless /usr/local/bin/vless.sh /usr/bin/vless 2>/dev/null
    _ok "快捷命令已移除"
}


#═══════════════════════════════════════════════════════════════════════════════
# 节点管理
#═══════════════════════════════════════════════════════════════════════════════
# 保存节点 (支持所有协议)
# 参数: name protocol [协议特定参数...]
save_node() {
    mkdir -p "$CFG/nodes"
    local name="$1" protocol="$2"
    shift 2
    
    case "$protocol" in
        vless)
            # 参数: ip port uuid pubkey sid sni
            cat > "$CFG/nodes/$name" << EOF
protocol=vless
server_ip=$1
port=$2
uuid=$3
public_key=$4
short_id=$5
sni=$6
EOF
            ;;
        vless-xhttp)
            # 参数: ip port uuid pubkey sid sni path
            cat > "$CFG/nodes/$name" << EOF
protocol=vless-xhttp
server_ip=$1
port=$2
uuid=$3
public_key=$4
short_id=$5
sni=$6
path=$7
EOF
            ;;
        vless-vision)
            # 参数: ip port uuid sni
            cat > "$CFG/nodes/$name" << EOF
protocol=vless-vision
server_ip=$1
port=$2
uuid=$3
sni=$4
EOF
            ;;
        vless-ws)
            # 参数: ip port uuid sni path
            cat > "$CFG/nodes/$name" << EOF
protocol=vless-ws
server_ip=$1
port=$2
uuid=$3
sni=$4
path=$5
EOF
            ;;
        vless-grpc)
            # 参数: ip port uuid sni serviceName
            cat > "$CFG/nodes/$name" << EOF
protocol=vless-grpc
server_ip=$1
port=$2
uuid=$3
sni=$4
service_name=$5
EOF
            ;;
        ss2022)
            # 参数: ip port method password
            cat > "$CFG/nodes/$name" << EOF
protocol=ss2022
server_ip=$1
port=$2
method=$3
password=$4
EOF
            ;;
        trojan)
            # 参数: ip port password sni
            cat > "$CFG/nodes/$name" << EOF
protocol=trojan
server_ip=$1
port=$2
password=$3
sni=$4
EOF
            ;;
        hy2)
            # 参数: ip port password sni
            cat > "$CFG/nodes/$name" << EOF
protocol=hy2
server_ip=$1
port=$2
password=$3
sni=$4
EOF
            ;;
        snell)
            # 参数: ip port psk version
            cat > "$CFG/nodes/$name" << EOF
protocol=snell
server_ip=$1
port=$2
psk=$3
version=$4
EOF
            ;;
        tuic)
            # 参数: ip port uuid password sni [cert_path]
            cat > "$CFG/nodes/$name" << EOF
protocol=tuic
server_ip=$1
port=$2
uuid=$3
password=$4
sni=$5
cert_path=${6:-/etc/vless-reality/certs/server.crt}
EOF
            ;;
    esac
}

list_nodes() {
    [[ ! -d "$CFG/nodes" ]] && return 1
    local current=$(cat "$CFG/current_node" 2>/dev/null) i=1
    for node in "$CFG/nodes"/*; do
        [[ ! -f "$node" ]] && continue
        source "$node"
        local name=$(basename "$node")
        local proto_type="${protocol:-vless}"
        local mark="" latency=$(test_latency "$server_ip" "$port" "$proto_type")
        [[ "$name" == "$current" ]] && mark=" ${G}[当前]${NC}"
        
        local color="${G}"
        [[ "$latency" == "超时" ]] && color="${R}"
        [[ "$latency" == "UDP" ]] && color="${C}"
        [[ "$latency" =~ ^([0-9]+)ms$ && ${BASH_REMATCH[1]} -gt 300 ]] && color="${Y}"
        
        # 显示协议类型
        local proto_short="$proto_type"
        case "$proto_short" in
            vless) proto_short="VLESS" ;;
            vless-xhttp) proto_short="VLESS-XHTTP" ;;
            vless-ws) proto_short="VLESS-WS" ;;
            vless-grpc) proto_short="VLESS-gRPC" ;;
            ss2022) proto_short="SS2022" ;;
            hy2) proto_short="HY2" ;;
            trojan) proto_short="Trojan" ;;
            snell) proto_short="Snell" ;;
            tuic) proto_short="TUIC" ;;
        esac
        
        printf "  ${G}%2d${NC}) %-20s ${D}[%s]${NC} ${D}(%s:%s)${NC} ${color}%s${NC}%b\n" "$i" "$name" "$proto_short" "$server_ip" "$port" "$latency" "$mark"
        ((i++))
    done
    [[ $i -eq 1 ]] && return 1
    return 0
}

switch_node() {
    local node_file="$1"
    [[ ! -f "$node_file" ]] && return 1
    source "$node_file"
    
    _info "切换到节点: $(basename "$node_file")"
    stop_services
    
    # 根据协议调用不同的配置生成
    case "$protocol" in
        vless)
            gen_client_config "vless" "$server_ip" "$port" "$uuid" "$public_key" "$short_id" "$sni"
            ;;
        vless-xhttp)
            gen_client_config "vless-xhttp" "$server_ip" "$port" "$uuid" "$public_key" "$short_id" "$sni" "$path"
            ;;
        vless-vision)
            gen_client_config "vless-vision" "$server_ip" "$port" "$uuid" "$sni"
            ;;
        vless-ws)
            gen_client_config "vless-ws" "$server_ip" "$port" "$uuid" "$sni" "$path"
            ;;
        vless-grpc)
            gen_client_config "vless-grpc" "$server_ip" "$port" "$uuid" "$sni" "$service_name"
            ;;
        ss2022)
            gen_client_config "ss2022" "$server_ip" "$port" "$method" "$password"
            ;;
        trojan)
            gen_client_config "trojan" "$server_ip" "$port" "$password" "$sni"
            ;;
        hy2)
            gen_client_config "hy2" "$server_ip" "$port" "$password" "$sni"
            ;;
        snell)
            gen_client_config "snell" "$server_ip" "$port" "$psk" "$version"
            ;;
        tuic)
            gen_client_config "tuic" "$server_ip" "$port" "$uuid" "$password" "$sni" "$cert_path"
            ;;
        *)
            # 兼容旧格式节点 (默认vless)
            gen_client_config "vless" "$server_ip" "$port" "$uuid" "$public_key" "$short_id" "$sni"
            ;;
    esac
    
    echo "$(basename "$node_file")" > "$CFG/current_node"
    start_services && _ok "节点切换完成"
}

select_node() {
    local prompt="$1"
    SELECTED_NODE=""
    if ! list_nodes; then
        _warn "没有保存的节点"
        return 1
    fi
    _line
    echo ""
    local max=$(ls "$CFG/nodes" 2>/dev/null | wc -l)
    read -rp "  $prompt [1-$max]: " choice
    [[ ! "$choice" =~ ^[0-9]+$ ]] && { _err "无效选择"; return 1; }
    local file=$(ls "$CFG/nodes" 2>/dev/null | sed -n "${choice}p")
    [[ -z "$file" ]] && { _err "节点不存在"; return 1; }
    SELECTED_NODE="$CFG/nodes/$file"
    return 0
}

#═══════════════════════════════════════════════════════════════════════════════
# BBR 网络优化
#═══════════════════════════════════════════════════════════════════════════════

# 检查 BBR 状态
check_bbr_status() {
    local cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    [[ "$cc" == "bbr" && "$qdisc" == "fq" ]]
}

# 一键开启 BBR 优化
enable_bbr() {
    _header
    echo -e "  ${W}BBR 网络优化${NC}"
    _line
    
    # 检查内核版本
    local kernel_ver=$(uname -r | cut -d'-' -f1)
    local kernel_major=$(echo "$kernel_ver" | cut -d'.' -f1)
    local kernel_minor=$(echo "$kernel_ver" | cut -d'.' -f2)
    
    if [[ $kernel_major -lt 4 ]] || [[ $kernel_major -eq 4 && $kernel_minor -lt 9 ]]; then
        _err "内核版本 $(uname -r) 不支持 BBR (需要 4.9+)"
        return 1
    fi
    
    echo -e "  内核版本: ${G}$(uname -r)${NC} ✓"
    
    # 检查当前状态
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    
    echo -e "  当前拥塞控制: ${Y}$current_cc${NC}"
    echo -e "  当前队列调度: ${Y}$current_qdisc${NC}"
    
    if check_bbr_status; then
        _line
        _ok "BBR 已启用，无需重复操作"
        return 0
    fi
    
    _line
    read -rp "  确认开启 BBR 优化? [Y/n]: " confirm
    [[ "$confirm" =~ ^[nN]$ ]] && return
    
    _info "加载 BBR 模块..."
    modprobe tcp_bbr 2>/dev/null || true
    
    # 检查 BBR 是否可用
    if ! sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr; then
        _err "BBR 模块不可用，请检查内核配置"
        return 1
    fi
    
    # 获取系统内存大小
    local mem_mb=$(free -m | awk '/^Mem:/{print $2}')
    
    # 根据内存动态计算参数
    local rmem_max wmem_max tcp_rmem tcp_wmem somaxconn file_max
    if [[ $mem_mb -le 512 ]]; then
        rmem_max=8388608; wmem_max=8388608
        tcp_rmem="4096 65536 8388608"; tcp_wmem="4096 65536 8388608"
        somaxconn=32768; file_max=262144
    elif [[ $mem_mb -le 1024 ]]; then
        rmem_max=16777216; wmem_max=16777216
        tcp_rmem="4096 65536 16777216"; tcp_wmem="4096 65536 16777216"
        somaxconn=49152; file_max=524288
    elif [[ $mem_mb -le 2048 ]]; then
        rmem_max=33554432; wmem_max=33554432
        tcp_rmem="4096 87380 33554432"; tcp_wmem="4096 65536 33554432"
        somaxconn=65535; file_max=1048576
    else
        rmem_max=67108864; wmem_max=67108864
        tcp_rmem="4096 131072 67108864"; tcp_wmem="4096 87380 67108864"
        somaxconn=65535; file_max=2097152
    fi
    
    _info "写入优化配置..."
    
    local conf_file="/etc/sysctl.d/99-bbr-proxy.conf"
    cat > "$conf_file" << EOF
# BBR 网络优化配置 (由 vless 脚本生成)
# 生成时间: $(date)
# 内存: ${mem_mb}MB

# BBR 拥塞控制
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Socket 缓冲区
net.core.rmem_max = $rmem_max
net.core.wmem_max = $wmem_max
net.ipv4.tcp_rmem = $tcp_rmem
net.ipv4.tcp_wmem = $tcp_wmem

# 连接队列
net.core.somaxconn = $somaxconn
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_max_syn_backlog = $somaxconn

# TCP 优化
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 180000
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3

# 文件句柄
fs.file-max = $file_max

# 内存优化
vm.swappiness = 10
EOF
    
    _info "应用配置..."
    if sysctl --system >/dev/null 2>&1; then
        _ok "配置已生效"
    else
        _err "配置应用失败"
        return 1
    fi
    
    # 验证结果
    _line
    local new_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local new_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    
    echo -e "  拥塞控制: ${G}$new_cc${NC}"
    echo -e "  队列调度: ${G}$new_qdisc${NC}"
    
    if [[ "$new_cc" == "bbr" && "$new_qdisc" == "fq" ]]; then
        _ok "BBR 优化已成功启用!"
    else
        _warn "BBR 可能未完全生效，请检查系统日志"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 多协议管理菜单
#═══════════════════════════════════════════════════════════════════════════════

# 显示所有已安装协议的信息（带选择查看详情功能）
show_all_protocols_info() {
    local installed=$(get_installed_protocols)
    [[ -z "$installed" ]] && { _warn "未安装任何协议"; return; }
    
    while true; do
        _header
        echo -e "  ${W}已安装协议配置${NC}"
        _line
        
        local xray_protocols=$(get_xray_protocols)
        local independent_protocols=$(get_independent_protocols)
        local all_protocols=()
        local idx=1
        
        if [[ -n "$xray_protocols" ]]; then
            echo -e "  ${Y}Xray 协议 (共享服务):${NC}"
            for protocol in $xray_protocols; do
                local info_file="$CFG/${protocol}.info"
                if [[ -f "$info_file" ]]; then
                    source "$info_file"
                    echo -e "    ${G}$idx${NC}) $(get_protocol_name $protocol) - 端口: ${G}$port${NC}"
                    all_protocols+=("$protocol")
                    ((idx++))
                fi
            done
            echo ""
        fi
        
        if [[ -n "$independent_protocols" ]]; then
            echo -e "  ${Y}独立协议 (独立服务):${NC}"
            for protocol in $independent_protocols; do
                local info_file="$CFG/${protocol}.info"
                if [[ -f "$info_file" ]]; then
                    source "$info_file"
                    echo -e "    ${G}$idx${NC}) $(get_protocol_name $protocol) - 端口: ${G}$port${NC}"
                    all_protocols+=("$protocol")
                    ((idx++))
                fi
            done
            echo ""
        fi
        
        _line
        echo -e "  ${D}输入序号查看详细配置/链接/二维码${NC}"
        _item "0" "返回主菜单"
        _line
        
        read -rp "  请选择 [0-$((idx-1))]: " choice
        
        if [[ "$choice" == "0" ]]; then
            return
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -lt $idx ]]; then
            local selected_protocol="${all_protocols[$((choice-1))]}"
            show_single_protocol_info "$selected_protocol"
        else
            _err "无效选择"
            sleep 1
        fi
    done
}

# 显示单个协议的详细配置信息（包含链接和二维码）
# 参数: $1=协议名, $2=是否清屏(可选，默认true)
show_single_protocol_info() {
    local protocol="$1"
    local clear_screen="${2:-true}"
    local info_file="$CFG/${protocol}.info"
    [[ ! -f "$info_file" ]] && { _err "协议配置不存在: $info_file"; return; }
    
    # 清除可能残留的变量，避免显示错误的配置
    local uuid="" port="" sni="" short_id="" public_key="" private_key="" path=""
    local password="" username="" method="" psk="" version=""
    local ipv4="" ipv6="" server_ip=""
    
    # 从 info 文件读取配置
    source "$info_file"
    
    # 重新获取 IP（info 文件中的可能是旧的）
    [[ -z "$ipv4" ]] && ipv4=$(get_ipv4)
    [[ -z "$ipv6" ]] && ipv6=$(get_ipv6)
    
    # 检测是否为回落子协议（WS/VMess-WS 在有主协议时使用主协议端口）
    local display_port="$port"
    local is_fallback_protocol=false
    local master_name=""
    if [[ "$protocol" == "vless-ws" || "$protocol" == "vmess-ws" ]]; then
        # 检查是否有主协议 (Vision/Trojan/Reality)
        if [[ -f "$CFG/vless-vision.info" ]]; then
            local master_port=$(grep "^port=" "$CFG/vless-vision.info" | cut -d= -f2)
            if [[ -n "$master_port" ]]; then
                display_port="$master_port"
                is_fallback_protocol=true
                master_name="Vision"
            fi
        elif [[ -f "$CFG/trojan.info" ]]; then
            local master_port=$(grep "^port=" "$CFG/trojan.info" | cut -d= -f2)
            if [[ -n "$master_port" ]]; then
                display_port="$master_port"
                is_fallback_protocol=true
                master_name="Trojan"
            fi
        elif [[ -f "$CFG/vless.info" ]]; then
            local master_port=$(grep "^port=" "$CFG/vless.info" | cut -d= -f2)
            if [[ -n "$master_port" ]]; then
                display_port="$master_port"
                is_fallback_protocol=true
                master_name="Reality"
            fi
        fi
    fi
    
    [[ "$clear_screen" == "true" ]] && _header
    _line
    echo -e "  ${W}$(get_protocol_name $protocol) 配置详情${NC}"
    _line
    
    [[ -n "$ipv4" ]] && echo -e "  IPv4: ${G}$ipv4${NC}"
    [[ -n "$ipv6" ]] && echo -e "  IPv6: ${G}$ipv6${NC}"
    echo -e "  端口: ${G}$display_port${NC}"
    [[ "$is_fallback_protocol" == "true" ]] && echo -e "  ${D}(通过 $master_name 主协议回落，内部端口: $port)${NC}"
    
    case "$protocol" in
        vless)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  公钥: ${G}$public_key${NC}"
            echo -e "  SNI: ${G}$sni${NC}  ShortID: ${G}$short_id${NC}"
            ;;
        vless-xhttp)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  公钥: ${G}$public_key${NC}"
            echo -e "  SNI: ${G}$sni${NC}  ShortID: ${G}$short_id${NC}"
            echo -e "  Path: ${G}$path${NC}"
            ;;
        vless-vision|vless-ws|vless-grpc)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            [[ -n "$path" ]] && echo -e "  Path/ServiceName: ${G}$path${NC}"
            ;;
        ss2022)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  加密: ${G}$method${NC}"
            ;;
        hy2)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            if [[ "$hop_enable" == "1" ]]; then
                echo -e "  端口跳跃: ${G}${hop_start}-${hop_end}${NC}"
            fi
            ;;
        trojan|anytls)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            ;;
        shadowtls)
            echo -e "  SS密码: ${G}$password${NC}"
            echo -e "  加密方法: ${G}$method${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo -e "  TLS密码: ${G}$stls_password${NC}"
            ;;
        snell|snell-v5)
            echo -e "  PSK: ${G}$psk${NC}"
            echo -e "  版本: ${G}v$version${NC}"
            ;;
        tuic)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            ;;
        socks)
            echo -e "  用户名: ${G}$username${NC}"
            echo -e "  密码: ${G}$password${NC}"
            ;;
    esac
    
    _line
    
    # 生成并显示分享链接和二维码
    for ver in v4 v6; do
        local ip_addr
        [[ "$ver" == "v4" ]] && ip_addr="$ipv4" || ip_addr="$ipv6"
        [[ -z "$ip_addr" ]] && continue
        
        # IPv6 需要加方括号
        [[ "$ver" == "v6" ]] && ip_addr="[$ip_addr]"
        
        # 使用 display_port（回落协议使用主协议端口）
        local link_port="$display_port"
        
        local link join_code
        case "$protocol" in
            vless)
                link=$(gen_vless_link "$ip_addr" "$link_port" "$uuid" "$public_key" "$short_id" "$sni")
                join_code=$(echo "REALITY|${ip_addr}|${link_port}|${uuid}|${public_key}|${short_id}|${sni}" | base64 -w 0)
                ;;
            vless-xhttp)
                link=$(gen_vless_xhttp_link "$ip_addr" "$link_port" "$uuid" "$public_key" "$short_id" "$sni" "$path")
                join_code=$(echo "REALITY-XHTTP|${ip_addr}|${link_port}|${uuid}|${public_key}|${short_id}|${sni}|${path}" | base64 -w 0)
                ;;
            vless-vision)
                link=$(gen_vless_vision_link "$ip_addr" "$link_port" "$uuid" "$sni")
                join_code=$(echo "VLESS-VISION|${ip_addr}|${link_port}|${uuid}|${sni}" | base64 -w 0)
                ;;
            vless-ws)
                link=$(gen_vless_ws_link "$ip_addr" "$link_port" "$uuid" "$sni" "$path")
                join_code=$(echo "VLESS-WS|${ip_addr}|${link_port}|${uuid}|${sni}|${path}" | base64 -w 0)
                ;;
            vless-grpc)
                link=$(gen_vless_grpc_link "$ip_addr" "$link_port" "$uuid" "$sni" "$path")
                join_code=$(echo "VLESS-GRPC|${ip_addr}|${link_port}|${uuid}|${sni}|${path}" | base64 -w 0)
                ;;
            vmess-ws)
                link=$(gen_vmess_ws_link "$ip_addr" "$link_port" "$uuid" "$sni" "$path")
                join_code=$(echo "VMESS-WS|${ip_addr}|${link_port}|${uuid}|${sni}|${path}" | base64 -w 0)
                ;;
            ss2022)
                link=$(gen_ss2022_link "$ip_addr" "$link_port" "$method" "$password")
                join_code=$(echo "SS2022|${ip_addr}|${link_port}|${method}|${password}" | base64 -w 0)
                ;;
            hy2)
                link=$(gen_hy2_link "$ip_addr" "$link_port" "$password" "$sni")
                join_code=$(echo "HY2|${ip_addr}|${link_port}|${password}|${sni}" | base64 -w 0)
                ;;
            trojan)
                link=$(gen_trojan_link "$ip_addr" "$link_port" "$password" "$sni")
                join_code=$(echo "TROJAN|${ip_addr}|${link_port}|${password}|${sni}" | base64 -w 0)
                ;;
            snell)
                link=$(gen_snell_link "$ip_addr" "$link_port" "$psk" "$version")
                join_code=$(echo "SNELL|${ip_addr}|${link_port}|${psk}|${version}" | base64 -w 0)
                ;;
            snell-v5)
                link=$(gen_snell_v5_link "$ip_addr" "$link_port" "$psk" "$version")
                join_code=$(echo "SNELL-V5|${ip_addr}|${link_port}|${psk}|${version}" | base64 -w 0)
                ;;
            tuic)
                link=$(gen_tuic_link "$ip_addr" "$link_port" "$uuid" "$password" "$sni")
                join_code=$(echo "TUIC|${ip_addr}|${link_port}|${uuid}|${password}|${sni}" | base64 -w 0)
                ;;
            anytls)
                link=$(gen_anytls_link "$ip_addr" "$link_port" "$password" "$sni")
                join_code=$(echo "ANYTLS|${ip_addr}|${link_port}|${password}|${sni}" | base64 -w 0)
                ;;
            shadowtls)
                link=$(gen_shadowtls_link "$ip_addr" "$link_port" "$password" "$method" "$sni" "$stls_password")
                join_code=$(echo "SHADOWTLS|${ip_addr}|${link_port}|${password}|${method}|${sni}|${stls_password}" | base64 -w 0)
                ;;
            socks)
                link=$(gen_socks_link "$ip_addr" "$link_port" "$username" "$password")
                join_code=$(echo "SOCKS|${ip_addr}|${link_port}|${username}|${password}" | base64 -w 0)
                ;;
        esac
        
        echo ""
        echo -e "  ${Y}═══ IP${ver^^} 连接信息 ═══${NC}"
        echo -e "  ${C}JOIN码:${NC}"
        echo -e "  ${G}$join_code${NC}"
        echo ""
        
        if [[ "$protocol" == "socks" ]]; then
            # SOCKS5 显示两种链接格式
            local socks_link="socks5://${username}:${password}@${ip_addr}:${link_port}#SOCKS5-${ip_addr}"
            echo -e "  ${C}SOCKS5 链接:${NC}"
            echo -e "  ${G}$socks_link${NC}"
            echo ""
            echo -e "  ${C}Telegram 代理链接:${NC}"
            echo -e "  ${G}$link${NC}"
            echo ""
            echo -e "  ${C}二维码 (SOCKS5):${NC}"
            echo -e "  ${G}$(gen_qr "$socks_link")${NC}"
        else
            echo -e "  ${C}分享链接:${NC}"
            echo -e "  ${G}$link${NC}"
            echo ""
            echo -e "  ${C}二维码:${NC}"
            echo -e "  ${G}$(gen_qr "$link")${NC}"
        fi
    done
    
    # Hysteria2 端口跳跃提示
    if [[ "$protocol" == "hy2" && "$hop_enable" == "1" ]]; then
        echo ""
        _line
        echo -e "  ${Y}⚠ 端口跳跃已启用${NC}"
        echo -e "  ${C}客户端请手动将端口改为: ${G}${hop_start}-${hop_end}${NC}"
        _line
    fi
    
    # 生成并显示订阅链接
    echo ""
    echo -e "  ${C}订阅链接:${NC}"
    
    local domain=""
    # 尝试获取域名
    if [[ -f "$CFG/cert_domain" ]]; then
        domain=$(cat "$CFG/cert_domain")
    fi
    
    # 检查Web服务状态
    local web_service_running=false
    local nginx_port=""
    
    # 检查是否有Reality协议（Reality 不需要 Nginx，不提供订阅服务）
    local has_reality=false
    if [[ -f "$CFG/vless.info" || -f "$CFG/vless-xhttp.info" ]]; then
        has_reality=true
        # Reality 协议不启用 Nginx，不设置 nginx_port
    fi
    
    # 检查是否有需要证书的协议（这些协议才需要 Nginx 订阅服务）
    local has_cert_protocol=false
    if [[ -f "$CFG/vless-ws.info" || -f "$CFG/vless-vision.info" || -f "$CFG/trojan.info" ]]; then
        has_cert_protocol=true
        # 从 sub.info 读取实际配置的端口，否则使用默认 8443
        if [[ -f "$CFG/sub.info" ]]; then
            source "$CFG/sub.info"
            nginx_port="${sub_port:-8443}"
        else
            nginx_port="8443"
        fi
    fi
    
    # 判断Web服务是否运行 - 只有证书协议才检查
    if [[ -n "$nginx_port" ]]; then
        if ss -tlnp 2>/dev/null | grep -q ":${nginx_port} "; then
            web_service_running=true
        fi
    fi
    
    # 显示订阅链接提示
    if [[ "$has_cert_protocol" == "true" ]]; then
        # 有证书协议，显示订阅状态
        if [[ "$web_service_running" == "true" && -f "$CFG/sub.info" ]]; then
            source "$CFG/sub.info"
            local sub_protocol="http"
            [[ "$sub_https" == "true" ]] && sub_protocol="https"
            local base_url="${sub_protocol}://${sub_domain:-$ipv4}:${sub_port}/sub/${sub_uuid}"
            echo -e "  ${Y}Clash/Clash Verge:${NC}"
            echo -e "  ${G}$base_url/clash${NC}"
        elif [[ "$web_service_running" == "true" ]]; then
            echo -e "  ${Y}订阅服务未配置，请在主菜单选择「订阅管理」进行配置${NC}"
        else
            echo -e "  ${D}(Web服务未运行，订阅功能不可用)${NC}"
            echo -e "  ${D}提示: 请在主菜单选择「订阅管理」配置订阅服务${NC}"
        fi
    elif [[ "$has_reality" == "true" ]]; then
        # 只有 Reality 协议，不需要订阅服务
        echo -e "  ${D}(Reality 协议无需订阅服务，直接使用分享链接即可)${NC}"
    else
        echo -e "  ${D}(无可用订阅)${NC}"
    fi
    
    _line
    [[ "$clear_screen" == "true" ]] && _pause
}

# 管理协议服务
manage_protocol_services() {
    local installed=$(get_installed_protocols)
    [[ -z "$installed" ]] && { _warn "未安装任何协议"; return; }
    
    while true; do
        _header
        echo -e "  ${W}协议服务管理${NC}"
        _line
        show_protocols_overview  # 使用简洁概览
        
        _item "1" "重启所有服务"
        _item "2" "停止所有服务"
        _item "3" "启动所有服务"
        _item "4" "查看服务状态"
        _item "0" "返回主菜单"
        _line
        
        read -rp "  请选择: " choice
        case $choice in
            1) 
                _info "重启所有服务..."
                stop_services; sleep 2; start_services && _ok "所有服务已重启"
                _pause
                ;;
            2) 
                _info "停止所有服务..."
                stop_services; touch "$CFG/paused"; _ok "所有服务已停止"
                _pause
                ;;
            3) 
                _info "启动所有服务..."
                start_services && _ok "所有服务已启动"
                _pause
                ;;
            4) show_services_status; _pause ;;
            0) return ;;
            *) _err "无效选择"; _pause ;;
        esac
    done
}

# 简洁的协议概览（用于服务管理页面）
show_protocols_overview() {
    local xray_protocols=$(get_xray_protocols)
    local independent_protocols=$(get_independent_protocols)
    
    echo -e "  ${C}已安装协议概览${NC}"
    _line
    
    if [[ -n "$xray_protocols" ]]; then
        echo -e "  ${Y}Xray 协议 (共享服务):${NC}"
        for protocol in $xray_protocols; do
            local info_file="$CFG/${protocol}.info"
            if [[ -f "$info_file" ]]; then
                source "$info_file"
                echo -e "    ${G}●${NC} $(get_protocol_name $protocol) - 端口: ${G}$port${NC}"
            fi
        done
        echo ""
    fi
    
    if [[ -n "$independent_protocols" ]]; then
        echo -e "  ${Y}独立协议 (独立服务):${NC}"
        for protocol in $independent_protocols; do
            local info_file="$CFG/${protocol}.info"
            if [[ -f "$info_file" ]]; then
                source "$info_file"
                echo -e "    ${G}●${NC} $(get_protocol_name $protocol) - 端口: ${G}$port${NC}"
            fi
        done
        echo ""
    fi
    _line
}

# 显示服务状态
show_services_status() {
    _line
    echo -e "  ${C}服务状态${NC}"
    _line
    
    # Xray 服务状态
    local xray_protocols=$(get_xray_protocols)
    if [[ -n "$xray_protocols" ]]; then
        if svc status vless-reality; then
            echo -e "  ${G}●${NC} Xray 服务 - ${G}运行中${NC}"
            # 显示各协议
            for proto in $xray_protocols; do
                echo -e "      ${D}└${NC} $(get_protocol_name $proto)"
            done
        else
            echo -e "  ${R}●${NC} Xray 服务 - ${R}已停止${NC}"
        fi
    fi
    
    # 独立协议服务状态
    local independent_protocols=$(get_independent_protocols)
    for protocol in $independent_protocols; do
        local service_name
        case "$protocol" in
            hy2) service_name="vless-hy2" ;;
            tuic) service_name="vless-tuic" ;;
            snell) service_name="vless-snell" ;;
            snell-v5) service_name="vless-snell-v5" ;;
            anytls) service_name="vless-anytls" ;;
            *) service_name="vless-${protocol}" ;;
        esac
        
        local proto_name=$(get_protocol_name $protocol)
        if svc status "$service_name"; then
            echo -e "  ${G}●${NC} $proto_name - ${G}运行中${NC}"
        else
            echo -e "  ${R}●${NC} $proto_name - ${R}已停止${NC}"
        fi
    done
    _line
}

# 卸载指定协议
uninstall_specific_protocol() {
    local installed=$(get_installed_protocols)
    [[ -z "$installed" ]] && { _warn "未安装任何协议"; return; }
    
    _header
    echo -e "  ${W}卸载指定协议${NC}"
    _line
    
    echo -e "  ${Y}已安装的协议:${NC}"
    local i=1
    for protocol in $installed; do
        echo -e "    ${G}$i${NC}) $(get_protocol_name $protocol)"
        ((i++))
    done
    echo ""
    
    read -rp "  选择要卸载的协议 [1-$((i-1))]: " choice
    [[ ! "$choice" =~ ^[0-9]+$ ]] && { _err "无效选择"; return; }
    
    local selected_protocol=$(echo "$installed" | sed -n "${choice}p")
    [[ -z "$selected_protocol" ]] && { _err "协议不存在"; return; }
    
    echo -e "  将卸载: ${R}$(get_protocol_name $selected_protocol)${NC}"
    read -rp "  确认卸载? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[yY]$ ]] && return
    
    _info "卸载 $selected_protocol..."
    
    # 停止相关服务
    if echo "$XRAY_PROTOCOLS" | grep -qw "$selected_protocol"; then
        # Xray 协议：需要重新生成配置
        unregister_protocol "$selected_protocol"
        rm -f "$CFG/${selected_protocol}.info"
        
        # 检查是否还有其他 Xray 协议
        local remaining_xray=$(get_xray_protocols)
        if [[ -n "$remaining_xray" ]]; then
            _info "重新生成 Xray 配置..."
            # 先停止服务，确保配置能正确重新加载
            svc stop vless-reality 2>/dev/null
            
            # 删除旧配置，强制重新生成
            rm -f "$CFG/config.json"
            
            if generate_xray_config; then
                _ok "Xray 配置已更新"
                svc start vless-reality
            else
                _err "Xray 配置生成失败"
            fi
        else
            # 没有其他 Xray 协议了，完全停止并清理
            _info "没有其他 Xray 协议，停止 Xray 服务..."
            svc stop vless-reality 2>/dev/null
            rm -f "$CFG/config.json"
            _ok "Xray 服务已停止"
        fi
    else
        # 独立协议：直接停止和删除服务
        local service_name="vless-${selected_protocol}"
        
        # Hysteria2: 在删除配置文件前清理 NAT 规则
        if [[ "$selected_protocol" == "hy2" ]]; then
            cleanup_hy2_nat_rules
        fi
        
        svc stop "$service_name" 2>/dev/null
        unregister_protocol "$selected_protocol"
        rm -f "$CFG/${selected_protocol}.info"
        
        # 删除服务文件
        if [[ "$DISTRO" == "alpine" ]]; then
            rc-update del "$service_name" default 2>/dev/null
            rm -f "/etc/init.d/$service_name"
        else
            systemctl disable "$service_name" 2>/dev/null
            rm -f "/etc/systemd/system/${service_name}.service"
            systemctl daemon-reload
        fi
    fi
    
    # 检查是否还有需要订阅服务的协议
    local has_sub_protocol=false
    for proto in vless-ws vless-vision trojan vmess-ws; do
        if is_protocol_installed "$proto"; then
            has_sub_protocol=true
            break
        fi
    done
    
    # 如果没有需要订阅的协议了，清理订阅相关配置
    if [[ "$has_sub_protocol" == "false" ]]; then
        _info "清理订阅服务..."
        # 停止并删除 Nginx 订阅配置
        rm -f /etc/nginx/conf.d/vless-sub.conf
        rm -f /etc/nginx/conf.d/vless-fake.conf
        nginx -s reload 2>/dev/null
        # 清理订阅目录和配置
        rm -rf "$CFG/subscription"
        rm -f "$CFG/sub.info"
        rm -f "$CFG/sub_uuid"
        _ok "订阅服务已清理"
    else
        # 还有其他协议，更新订阅文件
        _info "更新订阅文件..."
        generate_sub_files
    fi
    
    _ok "$selected_protocol 已卸载"
}

#═══════════════════════════════════════════════════════════════════════════════
# 菜单操作 (v3.2: 完整复原所有功能函数)
#═══════════════════════════════════════════════════════════════════════════════
show_server_info() {
    [[ "$(get_role)" != "server" ]] && return
    
    # 多协议模式：显示所有协议的配置
    local installed=$(get_installed_protocols)
    local protocol_count=$(echo "$installed" | wc -w)
    
    if [[ $protocol_count -eq 1 ]]; then
        # 单协议：直接显示详细信息
        show_single_protocol_info "$installed"
    else
        # 多协议：显示协议列表供选择
        show_all_protocols_info
    fi
}

show_client_info() {
    [[ ! -f "$CFG/info" ]] && { _err "未找到节点信息"; return 1; }
    
    # 清除变量避免污染
    local uuid="" port="" sni="" short_id="" public_key="" path=""
    local password="" method="" psk="" version="" server_ip=""
    
    source "$CFG/info"
    local current=$(cat "$CFG/current_node" 2>/dev/null || echo "默认节点")
    local proto=$(get_protocol)
    
    _line
    echo -e "  ${C}当前节点: ${G}$current${NC}"
    echo -e "  ${C}协议: ${G}$(get_protocol_name $proto)${NC}"
    _line
    echo -e "  服务器: ${G}$server_ip:$port${NC}"
    
    case "$proto" in
        vless)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo -e "  ShortID: ${G}$short_id${NC}"
            ;;
        vless-xhttp)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo -e "  ShortID: ${G}$short_id${NC}"
            echo -e "  Path: ${G}$path${NC}"
            ;;
        vless-ws)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo -e "  Path: ${G}$path${NC}"
            ;;
        vless-grpc)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo -e "  ServiceName: ${G}${service_name:-grpc}${NC}"
            ;;
        ss2022)
            echo -e "  加密: ${G}$method${NC}"
            echo -e "  密码: ${G}$password${NC}"
            ;;
        trojan|hy2)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            ;;
        snell)
            echo -e "  PSK: ${G}$psk${NC}"
            echo -e "  版本: ${G}v$version${NC}"
            ;;
        tuic)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            ;;
    esac
    _line
}

do_switch_mode() {
    [[ "$(get_role)" != "client" ]] && { _err "仅客户端支持"; return; }
    local current=$(get_mode)
    local protocol=$(get_protocol)
    
    # Snell 不支持模式切换
    if [[ "$protocol" == "snell" ]]; then
        _warn "Snell 协议仅支持 Surge/Clash 等客户端，不支持模式切换"
        return
    fi
    
    _header
    echo -e "  ${W}切换模式${NC}"
    echo -e "  当前: ${G}$(get_mode_name $current)${NC}"
    _line
    _item "1" "TUN 网卡"
    _item "2" "全局代理"
    _item "3" "SOCKS5代理"
    echo ""
    
    local new_mode
    while true; do
        read -rp "  选择 [1-3]: " choice
        case $choice in
            1) new_mode="tun"; break ;;
            2) new_mode="global"; break ;;
            3) new_mode="socks"; break ;;
            *) _err "无效选择" ;;
        esac
    done
    [[ "$new_mode" == "$current" ]] && { _warn "已是当前模式"; return; }
    
    _info "切换模式..."
    svc stop vless-tun 2>/dev/null
    svc stop vless-global 2>/dev/null
    
    echo "$new_mode" > "$CFG/mode"
    
    # 清除变量避免污染
    local uuid="" port="" sni="" short_id="" public_key="" path=""
    local password="" method="" server_ip=""
    source "$CFG/info"
    
    # 根据协议重新生成配置
    case "$protocol" in
        vless)
            gen_client_config "vless" "$server_ip" "$port" "$uuid" "$public_key" "$short_id" "$sni"
            ;;
        vless-xhttp)
            gen_client_config "vless-xhttp" "$server_ip" "$port" "$uuid" "$public_key" "$short_id" "$sni" "$path"
            ;;
        vless-vision)
            gen_client_config "vless-vision" "$server_ip" "$port" "$uuid" "$sni"
            ;;
        vless-ws)
            gen_client_config "vless-ws" "$server_ip" "$port" "$uuid" "$sni" "$path"
            ;;
        vless-grpc)
            gen_client_config "vless-grpc" "$server_ip" "$port" "$uuid" "$sni" "$service_name"
            ;;
        ss2022)
            gen_client_config "ss2022" "$server_ip" "$port" "$method" "$password"
            ;;
        trojan)
            gen_client_config "trojan" "$server_ip" "$port" "$password" "$sni"
            ;;
        hy2)
            gen_client_config "hy2" "$server_ip" "$port" "$password" "$sni"
            ;;
        tuic)
            gen_client_config "tuic" "$server_ip" "$port" "$uuid" "$password" "$sni"
            ;;
    esac
    
    create_scripts
    create_service "$protocol"
    
    # 根据协议类型重启正确的服务
    local service_name
    if echo " $XRAY_PROTOCOLS " | grep -qw "$protocol"; then
        service_name="vless-reality"
    else
        service_name="vless-$protocol"
    fi
    svc restart "$service_name"
    sleep 1
    
    case "$new_mode" in
        tun)
            [[ ! -x "/usr/local/bin/tun2socks" ]] && { _err "tun2socks 未安装"; return 1; }
            svc enable vless-tun; svc start vless-tun || { _err "TUN 启动失败"; return 1; }
            ;;
        global)
            svc enable vless-global; svc start vless-global || { _err "全局代理启动失败"; return 1; }
            ;;
        socks)
            echo -e "  SOCKS5代理: ${G}socks5://127.0.0.1:$SOCKS_PORT${NC}"
            ;;
    esac
    
    _ok "模式切换完成"
    [[ "$new_mode" != "socks" ]] && { sleep 1; test_connection; }
}

do_add_node() {
    [[ "$(get_role)" != "client" ]] && { _err "仅客户端支持"; return; }
    
    _header
    echo -e "  ${W}添加新节点${NC}"
    _line
    read -rp "  JOIN 码: " join_code
    [[ -z "$join_code" ]] && { _err "JOIN 码不能为空"; return; }

    local decoded=$(echo "$join_code" | base64 -d 2>/dev/null)
    [[ -z "$decoded" ]] && { _err "无效的 JOIN 码"; return; }
    
    # 解析不同协议的JOIN码
    local protocol_type server_ip port
    local uuid pubkey sid sni path password method psk version
    
    if [[ "$decoded" =~ ^REALITY-XHTTP\| ]]; then
        # REALITY-XHTTP|ip|port|uuid|pubkey|sid|sni|path
        IFS='|' read -r _ server_ip port uuid pubkey sid sni path <<< "$decoded"
        protocol_type="vless-xhttp"
    elif [[ "$decoded" =~ ^REALITY\| ]]; then
        # REALITY|ip|port|uuid|pubkey|sid|sni
        IFS='|' read -r _ server_ip port uuid pubkey sid sni <<< "$decoded"
        protocol_type="vless"
    elif [[ "$decoded" =~ ^VLESS-VISION\| ]]; then
        # VLESS-VISION|ip|port|uuid|sni
        IFS='|' read -r _ server_ip port uuid sni <<< "$decoded"
        protocol_type="vless-vision"
    elif [[ "$decoded" =~ ^VLESS-WS\| ]]; then
        # VLESS-WS|ip|port|uuid|sni|path
        IFS='|' read -r _ server_ip port uuid sni path <<< "$decoded"
        protocol_type="vless-ws"
    elif [[ "$decoded" =~ ^VLESS-GRPC\| ]]; then
        # VLESS-GRPC|ip|port|uuid|sni|serviceName
        IFS='|' read -r _ server_ip port uuid sni service_name <<< "$decoded"
        protocol_type="vless-grpc"
    elif [[ "$decoded" =~ ^SS2022\| ]]; then
        # SS2022|ip|port|method|password
        IFS='|' read -r _ server_ip port method password <<< "$decoded"
        protocol_type="ss2022"
    elif [[ "$decoded" =~ ^TROJAN\| ]]; then
        # TROJAN|ip|port|password|sni
        IFS='|' read -r _ server_ip port password sni <<< "$decoded"
        protocol_type="trojan"
    elif [[ "$decoded" =~ ^HY2\| ]]; then
        # HY2|ip|port|password|sni
        IFS='|' read -r _ server_ip port password sni <<< "$decoded"
        protocol_type="hy2"
    elif [[ "$decoded" =~ ^SNELL\| ]]; then
        # SNELL|ip|port|psk|version
        IFS='|' read -r _ server_ip port psk version <<< "$decoded"
        protocol_type="snell"
    elif [[ "$decoded" =~ ^TUIC\| ]]; then
        # TUIC|ip|port|uuid|password|sni
        IFS='|' read -r _ server_ip port uuid password sni <<< "$decoded"
        protocol_type="tuic"
    else
        _err "无效的 JOIN 码格式"; return
    fi
    
    [[ -z "$server_ip" || -z "$port" ]] && { _err "JOIN 码解析失败"; return; }
    
    echo -e "  服务器: ${G}$server_ip:$port${NC}"
    echo -e "  协议: ${G}$(get_protocol_name $protocol_type)${NC}"
    read -rp "  节点名称 (留空自动): " node_name
    [[ -z "$node_name" ]] && node_name="node_${server_ip}_${port}"
    
    # 根据协议保存节点
    case "$protocol_type" in
        vless)
            save_node "$node_name" "vless" "$server_ip" "$port" "$uuid" "$pubkey" "$sid" "$sni"
            ;;
        vless-xhttp)
            save_node "$node_name" "vless-xhttp" "$server_ip" "$port" "$uuid" "$pubkey" "$sid" "$sni" "$path"
            ;;
        vless-vision)
            save_node "$node_name" "vless-vision" "$server_ip" "$port" "$uuid" "$sni"
            ;;
        vless-ws)
            save_node "$node_name" "vless-ws" "$server_ip" "$port" "$uuid" "$sni" "$path"
            ;;
        vless-grpc)
            save_node "$node_name" "vless-grpc" "$server_ip" "$port" "$uuid" "$sni" "$service_name"
            ;;
        ss2022)
            save_node "$node_name" "ss2022" "$server_ip" "$port" "$method" "$password"
            ;;
        trojan)
            save_node "$node_name" "trojan" "$server_ip" "$port" "$password" "$sni"
            ;;
        hy2)
            save_node "$node_name" "hy2" "$server_ip" "$port" "$password" "$sni"
            ;;
        snell)
            save_node "$node_name" "snell" "$server_ip" "$port" "$psk" "$version"
            ;;
        tuic)
            # TUIC 需要证书
            echo ""
            _warn "TUIC v5 要求客户端必须持有服务端证书"
            read -rp "  证书文件路径 (默认 /etc/vless-reality/certs/server.crt): " cert_input
            local cert_path="${cert_input:-/etc/vless-reality/certs/server.crt}"
            if [[ ! -f "$cert_path" ]]; then
                _warn "证书文件不存在，请确保稍后下载证书到: $cert_path"
            fi
            save_node "$node_name" "tuic" "$server_ip" "$port" "$uuid" "$password" "$sni" "$cert_path"
            ;;
    esac
    
    _ok "节点已添加: $node_name"
    
    read -rp "  立即切换? [Y/n]: " sw
    [[ ! "$sw" =~ ^[nN]$ ]] && { switch_node "$CFG/nodes/$node_name"; test_connection; }
}

do_switch_node() {
    [[ "$(get_role)" != "client" ]] && { _err "仅客户端支持"; return; }
    _header
    echo -e "  ${W}切换节点${NC}"
    _line
    
    select_node "选择节点" || return
    switch_node "$SELECTED_NODE"
    sleep 1; test_connection
}

do_delete_node() {
    [[ "$(get_role)" != "client" ]] && { _err "仅客户端支持"; return; }
    _header
    echo -e "  ${W}删除节点${NC}"
    _line
    
    select_node "选择要删除的节点" || return
    local node="$SELECTED_NODE"
    [[ -z "$node" ]] && return
    
    local name=$(basename "$node")
    local current=$(cat "$CFG/current_node" 2>/dev/null)
    [[ "$name" == "$current" ]] && { _err "不能删除当前节点"; return; }
    
    read -rp "  确认删除 $name? [y/N]: " confirm
    [[ "$confirm" =~ ^[yY]$ ]] && { rm -f "$node"; _ok "已删除: $name"; }
}

do_uninstall() {
    check_installed || { _warn "未安装"; return; }
    read -rp "  确认卸载? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[yY]$ ]] && return
    
    _info "停止所有服务..."
    stop_services
    
    # 清理伪装网页服务和订阅文件
    local cleaned_items=()
    
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet fake-web 2>/dev/null; then
        systemctl stop fake-web 2>/dev/null
        systemctl disable fake-web 2>/dev/null
        rm -f /etc/systemd/system/fake-web.service
        systemctl daemon-reload 2>/dev/null
        cleaned_items+=("fake-web服务")
    fi
    
    # 清理Nginx配置
    if [[ -f "/etc/nginx/sites-enabled/vless-fake" ]]; then
        rm -f /etc/nginx/sites-enabled/vless-fake /etc/nginx/sites-available/vless-fake
        # 尝试重载Nginx，忽略错误（兼容 systemd / openrc）
        if nginx -t 2>/dev/null; then
            svc reload nginx 2>/dev/null || svc restart nginx 2>/dev/null
        else
            _warn "Nginx配置有问题，跳过重载"
        fi
        cleaned_items+=("Nginx配置")
    fi
    
    # 显示清理结果
    if [[ ${#cleaned_items[@]} -gt 0 ]]; then
        echo "  ▸ 已清理: ${cleaned_items[*]}"
    fi
    
    # 清理网页文件
    rm -rf /var/www/html/index.html 2>/dev/null
    
    # 强力清理残留进程
    force_cleanup
    
    _info "删除服务文件..."
    if [[ "$DISTRO" == "alpine" ]]; then
        # Alpine: 删除所有 vless 相关的 OpenRC 服务
        for svc_file in /etc/init.d/vless-*; do
            [[ -f "$svc_file" ]] && {
                local svc_name=$(basename "$svc_file")
                rc-update del "$svc_name" default 2>/dev/null
                rm -f "$svc_file"
            }
        done
    else
        # Debian/Ubuntu/CentOS: 删除所有 vless 相关的 systemd 服务
        systemctl stop 'vless-*' 2>/dev/null
        systemctl disable 'vless-*' 2>/dev/null
        rm -f /etc/systemd/system/vless-*.service
        systemctl daemon-reload
    fi
    
    _info "删除配置目录..."
    
    # 保留证书目录和域名记录，避免重复申请
    local cert_backup_dir="/tmp/vless-certs-backup"
    if [[ -d "$CFG/certs" ]]; then
        _info "备份证书文件..."
        mkdir -p "$cert_backup_dir"
        cp -r "$CFG/certs" "$cert_backup_dir/" 2>/dev/null
        [[ -f "$CFG/cert_domain" ]] && cp "$CFG/cert_domain" "$cert_backup_dir/" 2>/dev/null
    fi
    
    # 删除配置目录（但保留证书）
    find "$CFG" -name "*.json" -delete 2>/dev/null
    find "$CFG" -name "*.info" -delete 2>/dev/null
    find "$CFG" -name "*.yaml" -delete 2>/dev/null
    find "$CFG" -name "*.conf" -delete 2>/dev/null
    rm -f "$CFG/installed_protocols" 2>/dev/null
    
    # 如果没有证书，删除整个目录
    if [[ ! -d "$CFG/certs" ]]; then
        rm -rf "$CFG"
    else
        _ok "证书已保留，配置文件已清理，下次安装将自动复用证书"
    fi
    
    _info "删除快捷命令..."
    rm -f /usr/local/bin/vless /usr/local/bin/vless.sh /usr/bin/vless 2>/dev/null
    
    _ok "卸载完成"
    echo ""
    echo -e "  ${Y}已保留的内容:${NC}"
    echo -e "  • 软件包: xray, hysteria, snell-server, tuic-server"
    echo -e "  • 软件包: anytls-server, shadow-tls, tun2socks"
    echo -e "  • ${G}域名证书: 下次安装将自动复用，无需重新申请${NC}"
    echo ""
    echo -e "  ${C}如需完全删除软件包，请执行:${NC}"
    echo -e "  ${G}rm -f /usr/local/bin/{xray,hysteria,snell-server*,tuic-*,anytls-*,shadow-tls,tun2socks}${NC}"
    echo ""
    echo -e "  ${C}如需删除证书，请执行:${NC}"
    echo -e "  ${G}rm -rf /etc/vless-reality/certs /etc/vless-reality/cert_domain${NC}"
}

#═══════════════════════════════════════════════════════════════════════════════
# 安装流程
#═══════════════════════════════════════════════════════════════════════════════

# 协议选择菜单
select_protocol() {
    echo ""
    _line
    echo -e "  ${W}选择代理协议${NC}"
    _line
    _item "1" "VLESS + Reality ${D}(推荐, 抗封锁)${NC}"
    _item "2" "VLESS + Reality + XHTTP ${D}(多路复用)${NC}"
    _item "3" "VLESS + WS + TLS ${D}(CDN友好, 可作回落)${NC}"
    _item "4" "VLESS + gRPC + TLS ${D}(CDN友好, 多路复用)${NC}"
    _item "5" "VMess + WS ${D}(回落分流/免流)${NC}"
    _item "6" "VLESS-XTLS-Vision ${D}(TLS主协议, 支持回落)${NC}"
    _item "7" "SOCKS5 ${D}(经典代理)${NC}"
    _item "8" "Shadowsocks 2022 ${D}(新版加密)${NC}"
    _item "9" "Hysteria2 ${D}(UDP加速, 高速)${NC}"
    _item "10" "Trojan ${D}(TLS主协议, 支持回落)${NC}"
    _item "11" "Snell v4 ${D}(Surge专用)${NC}"
    _item "12" "Snell v5 ${D}(Surge 5.0新版)${NC}"
    _item "13" "AnyTLS ${D}(多协议TLS代理)${NC}"
    _item "14" "ShadowTLS ${D}(TLS流量伪装)${NC}"
    _item "15" "TUIC v5 ${D}(QUIC协议)${NC}"
    echo ""
    echo -e "  ${D}提示: 先装主协议(6/10)占用443，再装WS(3/5)可共用端口${NC}"
    echo ""
    
    while true; do
        read -rp "  选择协议 [1-15]: " choice
        case $choice in
            1) SELECTED_PROTOCOL="vless"; break ;;
            2) SELECTED_PROTOCOL="vless-xhttp"; break ;;
            3) SELECTED_PROTOCOL="vless-ws"; break ;;
            4) SELECTED_PROTOCOL="vless-grpc"; break ;;
            5) SELECTED_PROTOCOL="vmess-ws"; break ;;
            6) SELECTED_PROTOCOL="vless-vision"; break ;;
            7) SELECTED_PROTOCOL="socks"; break ;;
            8) SELECTED_PROTOCOL="ss2022"; break ;;
            9) SELECTED_PROTOCOL="hy2"; break ;;
            10) SELECTED_PROTOCOL="trojan"; break ;;
            11) SELECTED_PROTOCOL="snell"; break ;;
            12) SELECTED_PROTOCOL="snell-v5"; break ;;
            13) SELECTED_PROTOCOL="anytls"; break ;;
            14) SELECTED_PROTOCOL="shadowtls"; break ;;
            15) SELECTED_PROTOCOL="tuic"; break ;;
            *) _err "无效选择" ;;
        esac
    done
}

do_install_server() {
    # check_installed && { _warn "已安装，请先卸载"; return; }
    _header
    echo -e "  ${W}服务端安装向导${NC}"
    echo -e "  系统: ${C}$DISTRO${NC}"
    
    # 选择协议
    select_protocol
    local protocol="$SELECTED_PROTOCOL"
    
    # 检查该协议是否已安装
    if is_protocol_installed "$protocol"; then
        _warn "协议 $(get_protocol_name $protocol) 已安装"
        read -rp "  是否重新安装? [y/N]: " reinstall
        if [[ "$reinstall" =~ ^[yY]$ ]]; then
            _info "卸载现有 $protocol 协议..."
            unregister_protocol "$protocol"
            rm -f "$CFG/${protocol}.info"
            
            # 如果是 Xray 协议，需要重新生成配置释放端口
            if echo "$XRAY_PROTOCOLS" | grep -qw "$protocol"; then
                local remaining_xray=$(get_xray_protocols)
                if [[ -n "$remaining_xray" ]]; then
                    # 还有其他 Xray 协议，重新生成配置
                    svc stop vless-reality 2>/dev/null
                    rm -f "$CFG/config.json"
                    generate_xray_config
                    svc start vless-reality 2>/dev/null
                else
                    # 没有其他 Xray 协议，停止服务并删除配置
                    svc stop vless-reality 2>/dev/null
                    rm -f "$CFG/config.json"
                fi
            fi
        else
            return
        fi
    fi
    
    # 只在必要时清理环境（避免影响现有协议）
    sync_time

    _info "检测网络环境..."
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    echo -e "  IPv4: ${ipv4:-${R}无${NC}}"
    echo -e "  IPv6: ${ipv6:-${R}无${NC}}"
    [[ -z "$ipv4" && -z "$ipv6" ]] && { _err "无法获取公网IP"; return 1; }
    echo ""

    # === 主协议冲突检测 ===
    # Vision 和 Trojan 都是 443 端口主协议，不能同时安装
    local master_protocols="vless-vision trojan"
    if echo "$master_protocols" | grep -qw "$protocol"; then
        local existing_master=""
        local existing_master_name=""
        
        if [[ "$protocol" == "vless-vision" && -f "$CFG/trojan.info" ]]; then
            existing_master="trojan"
            existing_master_name="Trojan"
        elif [[ "$protocol" == "trojan" && -f "$CFG/vless-vision.info" ]]; then
            existing_master="vless-vision"
            existing_master_name="VLESS-XTLS-Vision"
        fi
        
        if [[ -n "$existing_master" ]]; then
            echo ""
            _warn "检测到已安装 $existing_master_name (443端口主协议)"
            echo ""
            echo -e "  ${Y}$existing_master_name 和 $(get_protocol_name $protocol) 都需要 443 端口${NC}"
            echo -e "  ${Y}它们不能同时作为主协议运行${NC}"
            echo ""
            echo -e "  ${W}选项：${NC}"
            echo -e "  1) 卸载 $existing_master_name，安装 $(get_protocol_name $protocol)"
            echo -e "  2) 使用其他端口安装 $(get_protocol_name $protocol) (非标准端口)"
            echo -e "  3) 取消安装"
            echo ""
            
            while true; do
                read -rp "  请选择 [1-3]: " master_choice
                case "$master_choice" in
                    1)
                        _info "卸载 $existing_master_name..."
                        unregister_protocol "$existing_master"
                        rm -f "$CFG/${existing_master}.info"
                        # 重新生成 Xray 配置
                        local remaining_xray=$(get_xray_protocols)
                        if [[ -n "$remaining_xray" ]]; then
                            svc stop vless-reality 2>/dev/null
                            rm -f "$CFG/config.json"
                            generate_xray_config
                            svc start vless-reality 2>/dev/null
                        else
                            svc stop vless-reality 2>/dev/null
                            rm -f "$CFG/config.json"
                        fi
                        _ok "$existing_master_name 已卸载"
                        break
                        ;;
                    2)
                        _warn "将使用非 443 端口，可能影响伪装效果"
                        break
                        ;;
                    3)
                        _info "已取消安装"
                        return
                        ;;
                    *)
                        _err "无效选择"
                        ;;
                esac
            done
        fi
    fi

    install_deps || return
    
    # 根据协议安装对应软件
    case "$protocol" in
        vless|vless-xhttp|vless-ws|vless-grpc|vless-vision|ss2022|trojan)
            install_xray || return
            ;;
        hy2)
            install_hysteria || return
            ;;
        snell)
            install_snell || return
            ;;
        snell-v5)
            install_snell_v5 || return
            ;;
        tuic)
            install_tuic "server" || return
            ;;
        anytls)
            install_anytls || return
            ;;
        shadowtls)
            install_shadowtls || return
            install_xray || return  # ShadowTLS 后端需要 Xray 的 Shadowsocks
            ;;
    esac

    _info "生成配置参数..."
    
    # 使用新的智能端口选择
    local port=$(ask_port "$protocol")
    
    case "$protocol" in
        vless)
            local uuid=$(gen_uuid) sid=$(gen_sid)
            local keys=$(xray x25519 2>/dev/null)
            [[ -z "$keys" ]] && { _err "密钥生成失败"; return 1; }
            local privkey=$(echo "$keys" | grep "PrivateKey:" | awk '{print $2}')
            local pubkey=$(echo "$keys" | grep "Password:" | awk '{print $2}')
            [[ -z "$privkey" || -z "$pubkey" ]] && { _err "密钥提取失败"; return 1; }
            
            # Reality协议不需要证书，直接选择SNI
            echo "" >&2
            echo -e "  ${Y}Reality协议无需本地证书，直接配置SNI...${NC}" >&2
            local final_sni=$(ask_sni_config "$(gen_sni)" "")
            
            echo ""
            _line
            echo -e "  ${C}VLESS+Reality 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}  ShortID: ${G}$sid${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_server_config "$uuid" "$port" "$privkey" "$pubkey" "$sid" "$final_sni"
            ;;
        vless-xhttp)
            local uuid=$(gen_uuid) sid=$(gen_sid) path="$(gen_xhttp_path)"
            local keys=$(xray x25519 2>/dev/null)
            [[ -z "$keys" ]] && { _err "密钥生成失败"; return 1; }
            local privkey=$(echo "$keys" | grep "PrivateKey:" | awk '{print $2}')
            local pubkey=$(echo "$keys" | grep "Password:" | awk '{print $2}')
            [[ -z "$privkey" || -z "$pubkey" ]] && { _err "密钥提取失败"; return 1; }
            
            # Reality+XHTTP协议不需要证书，直接选择SNI
            echo "" >&2
            echo -e "  ${Y}Reality+XHTTP协议无需本地证书，直接配置SNI...${NC}" >&2
            local final_sni=$(ask_sni_config "$(gen_sni)" "")
            
            echo ""
            _line
            echo -e "  ${C}VLESS+Reality+XHTTP 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}  ShortID: ${G}$sid${NC}"
            echo -e "  Path: ${G}$path${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_vless_xhttp_server_config "$uuid" "$port" "$privkey" "$pubkey" "$sid" "$final_sni" "$path"
            ;;
        vless-ws)
            local uuid=$(gen_uuid) path="/vless"
            
            # 检查是否有主协议（用于回落）
            local master_domain=""
            local master_protocol=""
            if [[ -f "$CFG/vless-vision.info" ]]; then
                master_domain=$(grep "^sni=" "$CFG/vless-vision.info" | cut -d= -f2)
                master_protocol="vless-vision"
            elif [[ -f "$CFG/trojan.info" ]]; then
                master_domain=$(grep "^sni=" "$CFG/trojan.info" | cut -d= -f2)
                master_protocol="trojan"
            fi
            
            # 检查证书域名
            local cert_domain=""
            if [[ -f "$CFG/cert_domain" ]]; then
                cert_domain=$(cat "$CFG/cert_domain")
            fi
            
            local final_sni=""
            # 如果是回落子协议，强制使用证书域名（必须和 TLS 证书匹配）
            if [[ -n "$master_protocol" ]]; then
                if [[ -n "$cert_domain" ]]; then
                    final_sni="$cert_domain"
                    echo ""
                    _warn "作为回落子协议，SNI 必须与主协议证书域名一致"
                    _ok "自动使用证书域名: $cert_domain"
                elif [[ -n "$master_domain" ]]; then
                    final_sni="$master_domain"
                    _ok "自动使用主协议 SNI: $master_domain"
                else
                    # 使用统一的证书和 Nginx 配置函数
                    setup_cert_and_nginx "vless-ws"
                    cert_domain="$CERT_DOMAIN"
                    final_sni=$(ask_sni_config "$(gen_sni)" "$cert_domain")
                fi
            else
                # 独立安装，使用统一的证书和 Nginx 配置函数
                setup_cert_and_nginx "vless-ws"
                cert_domain="$CERT_DOMAIN"
                final_sni=$(ask_sni_config "$(gen_sni)" "$cert_domain")
            fi
            
            read -rp "  WS Path [回车默认 $path]: " _p
            [[ -n "$_p" ]] && path="$_p"
            [[ "$path" != /* ]] && path="/$path"
            
            echo ""
            _line
            echo -e "  ${C}VLESS+WS+TLS 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}  Path: ${G}$path${NC}"
            [[ -n "$cert_domain" ]] && echo -e "  订阅端口: ${G}${NGINX_PORT:-8443}${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_vless_ws_server_config "$uuid" "$port" "$final_sni" "$path"
            ;;
        vless-grpc)
            local uuid=$(gen_uuid) service_name="grpc"
            
            # 使用统一的证书和 Nginx 配置函数
            setup_cert_and_nginx "vless-grpc"
            local cert_domain="$CERT_DOMAIN"
            
            # 询问SNI配置
            local final_sni=$(ask_sni_config "$(gen_sni)" "$cert_domain")
            
            # 询问 gRPC serviceName
            read -rp "  gRPC ServiceName [回车默认 $service_name]: " _sn
            [[ -n "$_sn" ]] && service_name="$_sn"
            
            echo ""
            _line
            echo -e "  ${C}VLESS+gRPC+TLS 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}  ServiceName: ${G}$service_name${NC}"
            [[ -n "$CERT_DOMAIN" ]] && echo -e "  订阅端口: ${G}$NGINX_PORT${NC}"
            echo ""
            echo -e "  ${Y}提示: gRPC 支持 CDN (如 Cloudflare)，需开启 gRPC 支持${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_vless_grpc_server_config "$uuid" "$port" "$final_sni" "$service_name"
            ;;
        vmess-ws)
            local uuid=$(gen_uuid)

            # 检查是否有主协议（用于回落）
            local master_domain=""
            local master_protocol=""
            if [[ -f "$CFG/vless-vision.info" ]]; then
                master_domain=$(grep "^sni=" "$CFG/vless-vision.info" | cut -d= -f2)
                master_protocol="vless-vision"
            elif [[ -f "$CFG/trojan.info" ]]; then
                master_domain=$(grep "^sni=" "$CFG/trojan.info" | cut -d= -f2)
                master_protocol="trojan"
            fi
            
            # 检查证书域名
            local cert_domain=""
            if [[ -f "$CFG/cert_domain" ]]; then
                cert_domain=$(cat "$CFG/cert_domain")
            fi
            
            local final_sni=""
            # 如果是回落子协议，强制使用主协议的 SNI（必须和证书匹配）
            if [[ -n "$master_protocol" ]]; then
                if [[ -n "$cert_domain" ]]; then
                    final_sni="$cert_domain"
                    echo ""
                    _warn "作为回落子协议，SNI 必须与主协议证书域名一致"
                    _ok "自动使用证书域名: $cert_domain"
                elif [[ -n "$master_domain" ]]; then
                    final_sni="$master_domain"
                    _ok "自动使用主协议 SNI: $master_domain"
                else
                    final_sni=$(ask_sni_config "$(gen_sni)" "")
                fi
            else
                # 独立安装，询问 SNI
                final_sni=$(ask_sni_config "$(gen_sni)" "$cert_domain")
            fi

            local path="/vmess"
            read -rp "  WS Path [回车默认 $path]: " _p
            [[ -n "$_p" ]] && path="$_p"
            [[ "$path" != /* ]] && path="/$path"

            # 避免和 vless-ws path 撞车（简单提示）
            if [[ -f "$CFG/vless-ws.info" ]]; then
                local used_path=$(grep "^path=" "$CFG/vless-ws.info" | cut -d= -f2)
                if [[ -n "$used_path" && "$used_path" == "$path" ]]; then
                    _warn "该 Path 已被 vless-ws 使用：$used_path（回落会冲突），建议换一个"
                fi
            fi

            echo ""
            _line
            echo -e "  ${C}VMess + WS 配置${NC}"
            _line
            echo -e "  内部端口: ${G}$port${NC} (若启用 443 回落复用，会走 ${master_protocol:-主协议} 的 443 对外)"
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI/Host: ${G}$final_sni${NC}"
            echo -e "  WS Path: ${G}$path${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return

            _info "生成配置..."
            gen_vmess_ws_server_config "$uuid" "$port" "$final_sni" "$path"
            ;;
        vless-vision)
            local uuid=$(gen_uuid)
            
            # 使用统一的证书和 Nginx 配置函数
            setup_cert_and_nginx "vless-vision"
            local cert_domain="$CERT_DOMAIN"
            
            # 询问SNI配置
            local final_sni=$(ask_sni_config "$(gen_sni)" "$cert_domain")
            
            echo ""
            _line
            echo -e "  ${C}VLESS-XTLS-Vision 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}"
            [[ -n "$CERT_DOMAIN" ]] && echo -e "  订阅端口: ${G}$NGINX_PORT${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_vless_vision_server_config "$uuid" "$port" "$final_sni"
            ;;
        socks)
            local username=$(gen_password 8) password=$(gen_password)
            
            echo ""
            _line
            echo -e "  ${C}SOCKS5 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  用户名: ${G}$username${NC}"
            echo -e "  密码: ${G}$password${NC}"
            _line
            echo ""
            
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_socks_server_config "$username" "$password" "$port"
            ;;
        ss2022)
            # SS2022 加密方式选择
            echo ""
            _line
            echo -e "  ${W}选择 SS2022 加密方式${NC}"
            _line
            _item "1" "2022-blake3-aes-128-gcm ${D}(推荐, 16字节密钥)${NC}"
            _item "2" "2022-blake3-aes-256-gcm ${D}(更强, 32字节密钥)${NC}"
            _item "3" "2022-blake3-chacha20-poly1305 ${D}(ARM优化, 32字节密钥)${NC}"
            echo ""
            
            local method key_len
            while true; do
                read -rp "  选择加密 [1-3]: " enc_choice
                case $enc_choice in
                    1) method="2022-blake3-aes-128-gcm"; key_len=16; break ;;
                    2) method="2022-blake3-aes-256-gcm"; key_len=32; break ;;
                    3) method="2022-blake3-chacha20-poly1305"; key_len=32; break ;;
                    *) _err "无效选择" ;;
                esac
            done
            
            local password=$(head -c $key_len /dev/urandom 2>/dev/null | base64 -w 0)
            
            echo ""
            _line
            echo -e "  ${C}Shadowsocks 2022 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  加密: ${G}$method${NC}"
            echo -e "  密钥: ${G}$password${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_ss2022_server_config "$password" "$port" "$method"
            ;;
        hy2)
            local password=$(gen_password)
            local cert_domain=$(ask_cert_config "$(gen_sni)")
            
            # 询问SNI配置（在证书申请完成后）
            local final_sni=$(ask_sni_config "$(gen_sni)" "$cert_domain")
            
            # ===== 新增：端口跳跃开关 + 范围（默认不启用）=====
            local hop_enable=0
            local hop_start=20000
            local hop_end=50000

            echo ""
            _line
            echo -e "  ${C}Hysteria2 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC} (UDP)"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  伪装: ${G}$final_sni${NC}"
            echo ""

            echo -e "  ${W}端口跳跃(Port Hopping)${NC}"
            echo -e "  ${D}说明：会将一段 UDP 端口范围重定向到 ${G}$port${NC}；高位随机端口有暴露风险，默认关闭。${NC}"
            read -rp "  是否启用端口跳跃? [y/N]: " hop_ans
            if [[ "$hop_ans" =~ ^[yY]$ ]]; then
                hop_enable=1

                read -rp "  起始端口 [回车默认 $hop_start]: " _hs
                [[ -n "$_hs" ]] && hop_start="$_hs"
                read -rp "  结束端口 [回车默认 $hop_end]: " _he
                [[ -n "$_he" ]] && hop_end="$_he"

                # 基础校验：数字 + 范围 + start<end
                if ! [[ "$hop_start" =~ ^[0-9]+$ && "$hop_end" =~ ^[0-9]+$ ]] \
                   || [[ "$hop_start" -lt 1 || "$hop_start" -gt 65535 ]] \
                   || [[ "$hop_end" -lt 1 || "$hop_end" -gt 65535 ]] \
                   || [[ "$hop_start" -ge "$hop_end" ]]; then
                    _warn "端口范围无效，已自动关闭端口跳跃"
                    hop_enable=0
                    hop_start=20000
                    hop_end=50000
                else
                    echo -e "  ${C}将启用：${G}${hop_start}-${hop_end}${NC} → 转发至 ${G}$port${NC}"
                fi
            else
                echo -e "  ${D}已选择：不启用端口跳跃${NC}"
            fi

            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return

            _info "生成配置..."
            # ★改：把 hop 参数传进去
            gen_hy2_server_config "$password" "$port" "$final_sni" "$hop_enable" "$hop_start" "$hop_end"
            ;;
        trojan)
            local password=$(gen_password)
            
            # 使用统一的证书和 Nginx 配置函数
            setup_cert_and_nginx "trojan"
            local cert_domain="$CERT_DOMAIN"
            
            # 询问SNI配置
            local final_sni=$(ask_sni_config "$(gen_sni)" "$cert_domain")
            
            echo ""
            _line
            echo -e "  ${C}Trojan 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}"
            [[ -n "$CERT_DOMAIN" ]] && echo -e "  订阅端口: ${G}$NGINX_PORT${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_trojan_server_config "$password" "$port" "$final_sni"
            ;;
        snell)
            # Snell PSK 需要随机生成
            local psk=$(head -c 16 /dev/urandom 2>/dev/null | base64 -w 0 | tr -d '/+=' | head -c 22)
            local version="4"
            
            echo ""
            _line
            echo -e "  ${C}Snell v4 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  PSK: ${G}$psk${NC}"
            echo -e "  版本: ${G}v$version${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_snell_server_config "$psk" "$port" "$version"
            ;;
        tuic)
            local uuid=$(gen_uuid) password=$(gen_password)
            
            # TUIC不需要证书申请，直接询问SNI配置
            local final_sni=$(ask_sni_config "$(gen_sni)" "")
            
            echo ""
            _line
            echo -e "  ${C}TUIC v5 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC} (UDP/QUIC)"
            echo -e "  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_tuic_server_config "$uuid" "$password" "$port" "$final_sni"
            ;;
        anytls)
            local password=$(gen_password)
            
            # AnyTLS不需要证书申请，直接询问SNI配置
            local final_sni=$(ask_sni_config "$(gen_sni)" "")
            
            echo ""
            _line
            echo -e "  ${C}AnyTLS 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_anytls_server_config "$password" "$port" "$final_sni"
            ;;
        shadowtls)
            local password=$(gen_password) method="aes-256-gcm" stls_password=$(gen_password)
            
            # ShadowTLS不需要证书申请，直接询问SNI配置（使用随机SNI）
            local final_sni=$(ask_sni_config "$(gen_sni)" "")
            
            echo ""
            _line
            echo -e "  ${C}ShadowTLS 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  SS密码: ${G}$password${NC}"
            echo -e "  加密方法: ${G}$method${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}"
            echo -e "  TLS密码: ${G}$stls_password${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_shadowtls_server_config "$password" "$port" "$method" "$final_sni" "$stls_password"
            ;;
        snell-v5)
            local psk=$(gen_password) version="5"
            
            echo ""
            _line
            echo -e "  ${C}Snell v5 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  PSK: ${G}$psk${NC}"
            echo -e "  版本: ${G}$version${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_snell_v5_server_config "$psk" "$port" "$version"
            ;;
    esac
    
    _info "创建服务..."
    create_scripts  # 生成辅助脚本（包括 hy2-nat.sh）
    create_service "$protocol"
    _info "启动服务..."
    
    # 保存当前安装的协议名（防止被后续函数中的循环变量覆盖）
    local current_protocol="$protocol"
    
    if start_services; then
        create_shortcut   # 安装成功才创建快捷命令
        
        # 更新订阅文件（此时 info 文件已生成，订阅内容才会正确）
        if [[ -f "$CFG/sub.info" ]]; then
            generate_sub_files
        fi
        
        # 对于HTTPS协议，测试连接（跳过回落子协议）
        if [[ "$current_protocol" == "vless-vision" || "$current_protocol" == "trojan" ]]; then
            # 只测试主协议，vless-ws/vmess-ws 作为回落子协议不需要测试
            if [[ -f "$CFG/${current_protocol}.info" ]]; then
                # 清除变量避免污染
                local port="" sni="" uuid="" password=""
                source "$CFG/${current_protocol}.info"
                if [[ -f "$CFG/certs/server.crt" && "$sni" != "bing.com" ]]; then
                    _info "测试HTTPS服务..."
                    if timeout 3 curl -k -s "https://$sni:$port" >/dev/null 2>&1; then
                        _ok "HTTPS服务测试成功"
                    else
                        _warn "HTTPS服务测试失败，请检查防火墙和DNS解析"
                    fi
                fi
            fi
        fi
        
        _dline
        _ok "服务端安装完成! 快捷命令: vless"
        _ok "协议: $(get_protocol_name $current_protocol)"
        _dline
        
        # UDP协议提示开放防火墙
        if [[ "$current_protocol" == "hy2" || "$current_protocol" == "tuic" ]]; then
            # 清除变量避免污染
            local port="" password="" sni="" uuid=""
            source "$CFG/${current_protocol}.info" 2>/dev/null
            echo ""
            _warn "重要: 请确保防火墙开放 UDP 端口 $port"
            echo -e "  ${D}# iptables 示例:${NC}"
            echo -e "  ${C}iptables -A INPUT -p udp --dport $port -j ACCEPT${NC}"
            echo -e "  ${D}# 或使用 ufw:${NC}"
            echo -e "  ${C}ufw allow $port/udp${NC}"
            echo ""
        fi
        
        # TUIC 协议需要客户端持有证书
        if [[ "$current_protocol" == "tuic" ]]; then
            echo ""
            _warn "TUIC v5 要求客户端必须持有服务端证书!"
            _line
            echo -e "  ${C}请在客户端执行以下命令下载证书:${NC}"
            echo ""
            echo -e "  ${G}mkdir -p /etc/vless-reality/certs${NC}"
            echo -e "  ${G}scp root@$(get_ipv4):$CFG/certs/server.crt /etc/vless-reality/certs/${NC}"
            echo ""
            echo -e "  ${D}或手动复制证书内容到客户端 /etc/vless-reality/certs/server.crt${NC}"
            _line
        fi
        
        # 清理临时文件
        rm -f "$CFG/.nginx_port_tmp" 2>/dev/null
        
        # 显示刚安装的协议配置（不清屏）
        show_single_protocol_info "$current_protocol" false
    else
        _err "安装失败"
    fi
}


do_install_client() {
    # 检查是否有残留但无有效安装
    if check_installed; then
        local installed=$(get_installed_protocols)
        if [[ -z "$installed" ]]; then
            # 有残留文件但没有有效协议，自动清理
            _info "检测到残留文件，自动清理..."
            stop_services 2>/dev/null
            rm -rf "$CFG" 2>/dev/null
            if [[ "$DISTRO" == "alpine" ]]; then
                rc-update del vless-reality default 2>/dev/null
                rc-update del vless-tun default 2>/dev/null
                rc-update del vless-global default 2>/dev/null
                rc-update del vless-watchdog default 2>/dev/null
                rm -f /etc/init.d/vless-reality /etc/init.d/vless-tun /etc/init.d/vless-global /etc/init.d/vless-watchdog 2>/dev/null
            else
                systemctl disable vless-reality vless-tun vless-global vless-watchdog 2>/dev/null
                rm -f /etc/systemd/system/vless-*.service 2>/dev/null
                systemctl daemon-reload 2>/dev/null
            fi
        else
            _warn "已安装，请先卸载"
            return
        fi
    fi
    _header
    echo -e "  ${W}客户端安装向导${NC}"
    _line
    echo ""
    read -rp "  JOIN 码: " join_code
    [[ -z "$join_code" ]] && { _err "JOIN 码不能为空"; return; }

    local decoded=$(echo "$join_code" | base64 -d 2>/dev/null)
    [[ -z "$decoded" ]] && { _err "无效的 JOIN 码"; return; }

    # 解析不同协议的JOIN码
    local protocol_type server_ip port
    local uuid pubkey sid sni path password method psk version
    
    if [[ "$decoded" =~ ^REALITY-XHTTP\| ]]; then
        # REALITY-XHTTP|ip|port|uuid|pubkey|sid|sni|path
        IFS='|' read -r _ server_ip port uuid pubkey sid sni path <<< "$decoded"
        protocol_type="vless-xhttp"
    elif [[ "$decoded" =~ ^REALITY\| ]]; then
        # REALITY|ip|port|uuid|pubkey|sid|sni
        IFS='|' read -r _ server_ip port uuid pubkey sid sni <<< "$decoded"
        protocol_type="vless"
    elif [[ "$decoded" =~ ^VLESS-VISION\| ]]; then
        # VLESS-VISION|ip|port|uuid|sni
        IFS='|' read -r _ server_ip port uuid sni <<< "$decoded"
        protocol_type="vless-vision"
    elif [[ "$decoded" =~ ^VLESS-WS\| ]]; then
        # VLESS-WS|ip|port|uuid|sni|path
        IFS='|' read -r _ server_ip port uuid sni path <<< "$decoded"
        protocol_type="vless-ws"
    elif [[ "$decoded" =~ ^VLESS-GRPC\| ]]; then
        # VLESS-GRPC|ip|port|uuid|sni|serviceName
        IFS='|' read -r _ server_ip port uuid sni service_name <<< "$decoded"
        protocol_type="vless-grpc"
    elif [[ "$decoded" =~ ^SS2022\| ]]; then
        # SS2022|ip|port|method|password
        IFS='|' read -r _ server_ip port method password <<< "$decoded"
        protocol_type="ss2022"
    elif [[ "$decoded" =~ ^TROJAN\| ]]; then
        # TROJAN|ip|port|password|sni
        IFS='|' read -r _ server_ip port password sni <<< "$decoded"
        protocol_type="trojan"
    elif [[ "$decoded" =~ ^HY2\| ]]; then
        # HY2|ip|port|password|sni
        IFS='|' read -r _ server_ip port password sni <<< "$decoded"
        protocol_type="hy2"
    elif [[ "$decoded" =~ ^SNELL\| ]]; then
        # SNELL|ip|port|psk|version
        IFS='|' read -r _ server_ip port psk version <<< "$decoded"
        protocol_type="snell"
    elif [[ "$decoded" =~ ^TUIC\| ]]; then
        # TUIC|ip|port|uuid|password|sni
        IFS='|' read -r _ server_ip port uuid password sni <<< "$decoded"
        protocol_type="tuic"
    elif [[ "$decoded" =~ ^ANYTLS\| ]]; then
        # ANYTLS|ip|port|password|sni
        IFS='|' read -r _ server_ip port password sni <<< "$decoded"
        protocol_type="anytls"
    elif [[ "$decoded" =~ ^SHADOWTLS\| ]]; then
        # SHADOWTLS|ip|port|password|method|sni|stls_password
        IFS='|' read -r _ server_ip port password method sni stls_password <<< "$decoded"
        protocol_type="shadowtls"
    elif [[ "$decoded" =~ ^SNELL-V5\| ]]; then
        # SNELL-V5|ip|port|psk|version
        IFS='|' read -r _ server_ip port psk version <<< "$decoded"
        protocol_type="snell-v5"
    else
        _err "无效的 JOIN 码格式"; return
    fi
    
    [[ -z "$server_ip" || -z "$port" ]] && { _err "JOIN 码解析失败"; return; }

    echo ""
    _line
    echo -e "  服务器: ${G}$server_ip:$port${NC}"
    echo -e "  协议: ${G}$(get_protocol_name $protocol_type)${NC}"
    _line
    
    _info "清理旧环境..."
    force_cleanup
    sync_time

    _info "检测网络环境..."
    local client_ipv4=$(get_ipv4) client_ipv6=$(get_ipv6)
    echo -e "  IPv4: ${client_ipv4:-${R}无${NC}}  IPv6: ${client_ipv6:-${R}无${NC}}"
    
    _info "测试服务器连通性..."
    local clean_ip=$(echo "$server_ip" | tr -d '[]')
    local conn_ok=false
    
    # UDP协议(hy2/tuic)无法用TCP测试，跳过或用ping测试
    if [[ "$protocol_type" == "hy2" || "$protocol_type" == "tuic" ]]; then
        _warn "UDP协议，跳过TCP端口测试"
        # 尝试ping测试基本连通性
        if ping -c 1 -W 3 "$clean_ip" &>/dev/null; then
            _ok "服务器可达 (ICMP)"
            conn_ok=true
        else
            _warn "ICMP不通，但UDP可能正常"
            conn_ok=true  # UDP协议继续安装
        fi
    else
        if timeout 5 bash -c "echo >/dev/tcp/$clean_ip/$port" 2>/dev/null; then
            _ok "连接成功"
            conn_ok=true
        else
            _err "连接失败"
            read -rp "  是否继续安装? [y/N]: " force
            [[ "$force" =~ ^[yY]$ ]] && conn_ok=true
        fi
    fi
    [[ "$conn_ok" != "true" ]] && return
    
    if [[ "$warp_enabled" == "true" ]]; then
        echo ""
        _warn "检测到WARP"
        echo -e "  ${G}1.${NC} 保留WARP (推荐)  ${G}2.${NC} 关闭WARP"
        read -rp "  请选择 [1-2]: " warp_choice
        if [[ "$warp_choice" == "2" ]]; then
            _info "关闭WARP..."
            command -v warp-cli &>/dev/null && { warp-cli disconnect &>/dev/null; warp-cli disable-always-on &>/dev/null; }
            systemctl stop warp-svc &>/dev/null; systemctl disable warp-svc &>/dev/null
            ip link del warp &>/dev/null || true
            warp_enabled=false
            _ok "WARP已关闭"
        fi
    fi
    
    # Snell 客户端不支持 TUN/全局模式
    local mode
    if [[ "$protocol_type" == "snell" || "$protocol_type" == "snell-v5" ]]; then
        _warn "Snell 协议仅支持 Surge/Clash 等客户端"
        mode="socks"
    else
        echo ""
        _line
        _item "1" "TUN 网卡"
        _item "2" "全局代理 (iptables)"
        _item "3" "SOCKS5代理"
        echo ""
        while true; do
            read -rp "  选择模式 [1-3]: " choice
            case $choice in
                1) mode="tun"; break ;;
                2) mode="global"; break ;;
                3) mode="socks"; break ;;
                *) _err "无效选择" ;;
            esac
        done
    fi

    echo ""
    install_deps || return
    
    # 根据协议安装对应软件
    case "$protocol_type" in
        vless|vless-xhttp|vless-ws|vless-grpc|vless-vision|ss2022|trojan)
            install_xray || return
            ;;
        hy2)
            install_hysteria || return
            ;;
        snell)
            _warn "Snell 客户端需要手动安装 Surge/Clash"
            ;;
        snell-v5)
            _warn "Snell v5 客户端需要手动安装 Surge/Clash"
            ;;
        tuic)
            install_tuic "client" || return
            ;;
        anytls)
            install_anytls || return
            ;;
        shadowtls)
            install_shadowtls || return
            install_xray || return  # ShadowTLS 客户端需要 Xray 的 SS 客户端
            ;;
    esac
    
    # TUN模式需要安装tun2socks
    if [[ "$mode" == "tun" && "$protocol_type" != "snell" && "$protocol_type" != "snell-v5" ]]; then
        install_tun2socks || { _err "tun2socks 安装失败，无法使用TUN模式"; return 1; }
    fi
    
    mkdir -p "$CFG"
    echo "$mode" > "$CFG/mode"
    
    _info "生成配置..."
    # 根据协议生成客户端配置
    case "$protocol_type" in
        vless)
            gen_client_config "vless" "$server_ip" "$port" "$uuid" "$pubkey" "$sid" "$sni"
            save_node "默认_${server_ip}_${port}" "vless" "$server_ip" "$port" "$uuid" "$pubkey" "$sid" "$sni"
            ;;
        vless-xhttp)
            gen_client_config "vless-xhttp" "$server_ip" "$port" "$uuid" "$pubkey" "$sid" "$sni" "$path"
            save_node "默认_${server_ip}_${port}" "vless-xhttp" "$server_ip" "$port" "$uuid" "$pubkey" "$sid" "$sni" "$path"
            ;;
        vless-vision)
            gen_client_config "vless-vision" "$server_ip" "$port" "$uuid" "$sni"
            save_node "默认_${server_ip}_${port}" "vless-vision" "$server_ip" "$port" "$uuid" "$sni"
            ;;
        vless-ws)
            gen_client_config "vless-ws" "$server_ip" "$port" "$uuid" "$sni" "$path"
            save_node "默认_${server_ip}_${port}" "vless-ws" "$server_ip" "$port" "$uuid" "$sni" "$path"
            ;;
        vless-grpc)
            gen_client_config "vless-grpc" "$server_ip" "$port" "$uuid" "$sni" "$service_name"
            save_node "默认_${server_ip}_${port}" "vless-grpc" "$server_ip" "$port" "$uuid" "$sni" "$service_name"
            ;;
        ss2022)
            gen_client_config "ss2022" "$server_ip" "$port" "$method" "$password"
            save_node "默认_${server_ip}_${port}" "ss2022" "$server_ip" "$port" "$method" "$password"
            ;;
        trojan)
            gen_client_config "trojan" "$server_ip" "$port" "$password" "$sni"
            save_node "默认_${server_ip}_${port}" "trojan" "$server_ip" "$port" "$password" "$sni"
            ;;
        hy2)
            gen_client_config "hy2" "$server_ip" "$port" "$password" "$sni"
            save_node "默认_${server_ip}_${port}" "hy2" "$server_ip" "$port" "$password" "$sni"
            ;;
        snell)
            gen_client_config "snell" "$server_ip" "$port" "$psk" "$version"
            save_node "默认_${server_ip}_${port}" "snell" "$server_ip" "$port" "$psk" "$version"
            ;;
        tuic)
            # TUIC v5 需要客户端持有服务端证书
            echo ""
            _warn "TUIC v5 要求客户端必须持有服务端证书"
            _line
            echo -e "  ${D}请确保已从服务端下载证书到本机${NC}"
            echo -e "  ${D}默认路径: /etc/vless-reality/certs/server.crt${NC}"
            echo ""
            read -rp "  证书文件路径 (直接回车使用默认): " cert_path
            [[ -z "$cert_path" ]] && cert_path="/etc/vless-reality/certs/server.crt"
            
            # 检查证书文件是否存在
            if [[ ! -f "$cert_path" ]]; then
                _err "证书文件不存在: $cert_path"
                echo ""
                echo -e "  ${C}请先从服务端下载证书:${NC}"
                echo -e "  ${G}mkdir -p /etc/vless-reality/certs${NC}"
                echo -e "  ${G}scp root@服务端IP:/etc/vless-reality/certs/server.crt /etc/vless-reality/certs/${NC}"
                echo ""
                return 1
            fi
            _ok "证书文件已找到: $cert_path"
            
            gen_client_config "tuic" "$server_ip" "$port" "$uuid" "$password" "$sni" "$cert_path"
            save_node "默认_${server_ip}_${port}" "tuic" "$server_ip" "$port" "$uuid" "$password" "$sni" "$cert_path"
            ;;
        anytls)
            gen_client_config "anytls" "$server_ip" "$port" "$password" "$sni"
            save_node "默认_${server_ip}_${port}" "anytls" "$server_ip" "$port" "$password" "$sni"
            ;;
        shadowtls)
            gen_client_config "shadowtls" "$server_ip" "$port" "$password" "$method" "$sni" "$stls_password"
            save_node "默认_${server_ip}_${port}" "shadowtls" "$server_ip" "$port" "$password" "$method" "$sni" "$stls_password"
            ;;
        snell-v5)
            gen_client_config "snell-v5" "$server_ip" "$port" "$psk" "$version"
            save_node "默认_${server_ip}_${port}" "snell-v5" "$server_ip" "$port" "$psk" "$version"
            ;;
    esac
    
    local node_name="默认_${server_ip}_${port}"
    echo "$node_name" > "$CFG/current_node"
    
    create_scripts
    create_service "$protocol_type"
    
    _info "启动服务..."
    if start_services; then
        create_shortcut   # 安装成功才创建快捷命令
        _dline
        echo -e "  ${G}✓${NC} 客户端安装完成!"
        echo -e "  快捷命令: ${G}vless${NC}  模式: ${G}$(get_mode_name $mode)${NC}"
        echo -e "  协议: ${G}$(get_protocol_name $protocol_type)${NC}"
        [[ "$protocol_type" != "snell" ]] && echo -e "  守护进程: ${G}Watchdog 已激活${NC}"
        _dline
        
        # SOCKS5 模式使用提示
        if [[ "$mode" == "socks" ]]; then
            echo ""
            _info "SOCKS5 代理使用方法:"
            echo -e "  ${C}代理地址: ${G}127.0.0.1:${SOCKS_PORT}${NC}"
            echo ""
            echo -e "  ${W}# 设置全局代理 (当前终端)${NC}"
            echo -e "  ${G}export http_proxy=socks5://127.0.0.1:${SOCKS_PORT}${NC}"
            echo -e "  ${G}export https_proxy=socks5://127.0.0.1:${SOCKS_PORT}${NC}"
            echo -e "  ${G}export all_proxy=socks5://127.0.0.1:${SOCKS_PORT}${NC}"
            echo ""
            echo -e "  ${W}# curl 使用代理${NC}"
            echo -e "  ${G}curl -x socks5://127.0.0.1:${SOCKS_PORT} https://ip.sb${NC}"
            echo ""
            echo -e "  ${W}# 取消代理${NC}"
            echo -e "  ${G}unset http_proxy https_proxy all_proxy${NC}"
            echo ""
        fi
        
        # UDP协议额外提示
        if [[ "$protocol_type" == "hy2" || "$protocol_type" == "tuic" ]]; then
            echo ""
            _warn "UDP协议注意事项:"
            echo -e "  ${D}1. 确保服务端防火墙已开放 UDP 端口${NC}"
            echo -e "  ${D}2. 云服务商安全组需允许 UDP 入站${NC}"
            echo -e "  ${D}3. 如连接失败，可尝试 SOCKS5 模式测试${NC}"
            echo ""
        fi
        
        [[ "$mode" != "socks" && "$protocol_type" != "snell" && "$protocol_type" != "snell-v5" ]] && { sleep 2; test_connection; }
    else
        _err "安装失败"
        # 清理残留文件
        _info "清理残留..."
        stop_services 2>/dev/null
        rm -rf "$CFG" 2>/dev/null
        if [[ "$DISTRO" == "alpine" ]]; then
            rc-update del vless-reality default 2>/dev/null
            rc-update del vless-tun default 2>/dev/null
            rc-update del vless-global default 2>/dev/null
            rc-update del vless-watchdog default 2>/dev/null
            rm -f /etc/init.d/vless-reality /etc/init.d/vless-tun /etc/init.d/vless-global /etc/init.d/vless-watchdog 2>/dev/null
        else
            systemctl disable vless-reality vless-tun vless-global vless-watchdog 2>/dev/null
            rm -f /etc/systemd/system/vless-*.service 2>/dev/null
            systemctl daemon-reload 2>/dev/null
        fi
    fi
}

show_status() {
    local installed=$(get_installed_protocols)
    if [[ -n "$installed" ]]; then
        local role=$(get_role) mode=$(get_mode)
        local status_icon status_text
        
        # 统计协议数量
        local protocol_count=$(echo "$installed" | wc -l)
        local xray_protocols=$(get_xray_protocols)
        local independent_protocols=$(get_independent_protocols)
        
        # 检查服务运行状态
        local xray_running=false
        local independent_running=0 independent_total=0
        
        # 检查 Xray 服务状态
        if [[ -n "$xray_protocols" ]]; then
            if svc status vless-reality; then
                xray_running=true
            fi
        fi
        
        # 检查独立协议服务状态
        local ind_proto
        for ind_proto in $independent_protocols; do
            ((independent_total++))
            if svc status "vless-${ind_proto}"; then
                ((independent_running++))
            fi
        done
        
        # 确定整体状态
        local xray_count=0
        [[ -n "$xray_protocols" ]] && xray_count=$(echo "$xray_protocols" | wc -l)
        local running_protocols=0
        
        if [[ "$xray_running" == "true" ]]; then
            running_protocols=$xray_count
        fi
        running_protocols=$((running_protocols + independent_running))
        
        if is_paused; then
            status_icon="${Y}⏸${NC}"; status_text="${Y}已暂停${NC}"
        elif [[ $running_protocols -eq $protocol_count ]]; then
            status_icon="${G}●${NC}"; status_text="${G}运行中${NC}"
        elif [[ $running_protocols -gt 0 ]]; then
            status_icon="${Y}●${NC}"; status_text="${Y}部分运行${NC} (${running_protocols}/${protocol_count})"
        else
            status_icon="${R}●${NC}"; status_text="${R}已停止${NC}"
        fi
        
        echo -e "  状态: $status_icon $status_text"
        echo -e "  角色: ${C}$([ "$role" == "server" ] && echo "服务端" || echo "客户端")${NC}"
        
        # 显示协议概要
        if [[ $protocol_count -eq 1 ]]; then
            # 清除变量避免污染
            local port=""
            source "$CFG/${installed}.info" 2>/dev/null
            echo -e "  协议: ${C}$(get_protocol_name $installed)${NC}"
            echo -e "  端口: ${C}$port${NC}"
        else
            echo -e "  协议: ${C}多协议 (${protocol_count}个)${NC}"
            # 显示每个协议和端口
            for proto in $installed; do
                local proto_port=""
                local port=""
                if [[ -f "$CFG/${proto}.info" ]]; then
                    source "$CFG/${proto}.info"
                    proto_port="$port"
                fi
                echo -e "    ${G}•${NC} $(get_protocol_name $proto) ${D}- 端口: ${proto_port}${NC}"
            done
        fi
        if [[ "$role" == "client" ]]; then
            echo -e "  模式: ${C}$(get_mode_name $mode)${NC}"
            local server_ip="" port=""
            source "$CFG/info" 2>/dev/null
            echo -e "  服务器: ${C}$server_ip:$port${NC}"
            if svc status vless-watchdog 2>/dev/null; then
                echo -e "  守护: ${G}Watchdog 运行中${NC}"
            fi
        fi
    else
        echo -e "  状态: ${D}○ 未安装${NC}"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 订阅服务管理
#═══════════════════════════════════════════════════════════════════════════════

# 安装 Nginx
install_nginx() {
    if check_cmd nginx; then
        _ok "Nginx 已安装"
        return 0
    fi
    
    _info "安装 Nginx..."
    case "$DISTRO" in
        alpine) apk add --no-cache nginx ;;
        centos) yum install -y nginx ;;
        *) apt-get install -y -qq nginx ;;
    esac
    
    if check_cmd nginx; then
        _ok "Nginx 安装完成"
        return 0
    else
        _err "Nginx 安装失败"
        return 1
    fi
}

# 获取或生成订阅 UUID
get_sub_uuid() {
    local uuid_file="$CFG/sub_uuid"
    if [[ -f "$uuid_file" ]]; then
        cat "$uuid_file"
    else
        local new_uuid=$(gen_uuid)
        echo "$new_uuid" > "$uuid_file"
        chmod 600 "$uuid_file"
        echo "$new_uuid"
    fi
}

# 重置订阅 UUID（生成新的）
reset_sub_uuid() {
    local uuid_file="$CFG/sub_uuid"
    local new_uuid=$(gen_uuid)
    echo "$new_uuid" > "$uuid_file"
    chmod 600 "$uuid_file"
    echo "$new_uuid"
}

# 生成 V2Ray/通用 Base64 订阅内容
gen_v2ray_sub() {
    local installed=$(get_installed_protocols)
    local links=""
    local ipv4=$(get_ipv4)
    local ipv6=$(get_ipv6)
    
    # 检查是否有主协议（用于判断 WS 协议是否为回落子协议）
    local master_port=""
    if [[ -f "$CFG/vless-vision.info" ]]; then
        master_port=$(grep "^port=" "$CFG/vless-vision.info" | cut -d= -f2)
    elif [[ -f "$CFG/trojan.info" ]]; then
        master_port=$(grep "^port=" "$CFG/trojan.info" | cut -d= -f2)
    elif [[ -f "$CFG/vless.info" ]]; then
        master_port=$(grep "^port=" "$CFG/vless.info" | cut -d= -f2)
    fi
    
    for protocol in $installed; do
        local info_file="$CFG/${protocol}.info"
        [[ ! -f "$info_file" ]] && continue
        
        # 清除变量
        local uuid="" port="" sni="" short_id="" public_key="" path=""
        local password="" username="" method="" psk=""
        source "$info_file"
        
        # 对于回落子协议，使用主协议端口
        local actual_port="$port"
        if [[ -n "$master_port" && ("$protocol" == "vless-ws" || "$protocol" == "vmess-ws") ]]; then
            actual_port="$master_port"
        fi
        
        local link=""
        case "$protocol" in
            vless)
                [[ -n "$ipv4" ]] && link=$(gen_vless_link "$ipv4" "$actual_port" "$uuid" "$public_key" "$short_id" "$sni")
                ;;
            vless-xhttp)
                [[ -n "$ipv4" ]] && link=$(gen_vless_xhttp_link "$ipv4" "$actual_port" "$uuid" "$public_key" "$short_id" "$sni" "$path")
                ;;
            vless-ws)
                [[ -n "$ipv4" ]] && link=$(gen_vless_ws_link "$ipv4" "$actual_port" "$uuid" "$sni" "$path")
                ;;
            vless-grpc)
                [[ -n "$ipv4" ]] && link=$(gen_vless_grpc_link "$ipv4" "$actual_port" "$uuid" "$sni" "$path")
                ;;
            vless-vision)
                [[ -n "$ipv4" ]] && link=$(gen_vless_vision_link "$ipv4" "$actual_port" "$uuid" "$sni")
                ;;
            vmess-ws)
                [[ -n "$ipv4" ]] && link=$(gen_vmess_ws_link "$ipv4" "$actual_port" "$uuid" "$sni" "$path")
                ;;
            trojan)
                [[ -n "$ipv4" ]] && link=$(gen_trojan_link "$ipv4" "$actual_port" "$password" "$sni")
                ;;
            ss2022)
                [[ -n "$ipv4" ]] && link=$(gen_ss2022_link "$ipv4" "$actual_port" "$method" "$password")
                ;;
            hy2)
                [[ -n "$ipv4" ]] && link=$(gen_hy2_link "$ipv4" "$actual_port" "$password" "$sni")
                ;;
            tuic)
                [[ -n "$ipv4" ]] && link=$(gen_tuic_link "$ipv4" "$actual_port" "$uuid" "$password" "$sni")
                ;;
        esac
        
        [[ -n "$link" ]] && links+="$link"$'\n'
    done
    
    # Base64 编码
    printf '%s' "$links" | base64 -w 0 2>/dev/null || printf '%s' "$links" | base64
}

# 生成 Clash 订阅内容
gen_clash_sub() {
    local installed=$(get_installed_protocols)
    local ipv4=$(get_ipv4)
    local ipv6=$(get_ipv6)
    local proxies=""
    local proxy_names=""
    
    # 检查是否有主协议（用于判断 WS 协议是否为回落子协议）
    local master_port=""
    if [[ -f "$CFG/vless-vision.info" ]]; then
        master_port=$(grep "^port=" "$CFG/vless-vision.info" | cut -d= -f2)
    elif [[ -f "$CFG/trojan.info" ]]; then
        master_port=$(grep "^port=" "$CFG/trojan.info" | cut -d= -f2)
    elif [[ -f "$CFG/vless.info" ]]; then
        master_port=$(grep "^port=" "$CFG/vless.info" | cut -d= -f2)
    fi
    
    for protocol in $installed; do
        local info_file="$CFG/${protocol}.info"
        [[ ! -f "$info_file" ]] && continue
        
        # 清除变量
        local uuid="" port="" sni="" short_id="" public_key="" path=""
        local password="" username="" method="" psk=""
        source "$info_file"
        
        # 对于回落子协议，使用主协议端口
        local actual_port="$port"
        if [[ -n "$master_port" && ("$protocol" == "vless-ws" || "$protocol" == "vmess-ws") ]]; then
            actual_port="$master_port"
        fi
        
        local name="$(get_protocol_name $protocol)"
        local proxy=""
        
        case "$protocol" in
            vless)
                [[ -n "$ipv4" ]] && proxy="  - name: \"$name\"
    type: vless
    server: $ipv4
    port: $actual_port
    uuid: $uuid
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: $sni
    reality-opts:
      public-key: $public_key
      short-id: $short_id
    client-fingerprint: chrome"
                ;;
            vless-xhttp)
                [[ -n "$ipv4" ]] && proxy="  - name: \"$name\"
    type: vless
    server: $ipv4
    port: $actual_port
    uuid: $uuid
    network: xhttp
    tls: true
    udp: true
    servername: $sni
    xhttp-opts:
      path: $path
      mode: auto
    reality-opts:
      public-key: $public_key
      short-id: $short_id
    client-fingerprint: chrome"
                ;;
            vless-ws)
                [[ -n "$ipv4" ]] && proxy="  - name: \"$name\"
    type: vless
    server: $ipv4
    port: $actual_port
    uuid: $uuid
    network: ws
    tls: true
    udp: true
    skip-cert-verify: true
    servername: $sni
    ws-opts:
      path: $path
      headers:
        Host: $sni"
                ;;
            vless-grpc)
                [[ -n "$ipv4" ]] && proxy="  - name: \"$name\"
    type: vless
    server: $ipv4
    port: $actual_port
    uuid: $uuid
    network: grpc
    tls: true
    udp: true
    skip-cert-verify: true
    servername: $sni
    grpc-opts:
      grpc-service-name: $path"
                ;;
            vless-vision)
                [[ -n "$ipv4" ]] && proxy="  - name: \"$name\"
    type: vless
    server: $ipv4
    port: $actual_port
    uuid: $uuid
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    skip-cert-verify: true
    servername: $sni
    client-fingerprint: chrome"
                ;;
            vmess-ws)
                [[ -n "$ipv4" ]] && proxy="  - name: \"$name\"
    type: vmess
    server: $ipv4
    port: $actual_port
    uuid: $uuid
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    skip-cert-verify: true
    servername: $sni
    ws-opts:
      path: $path
      headers:
        Host: $sni"
                ;;
            trojan)
                [[ -n "$ipv4" ]] && proxy="  - name: \"$name\"
    type: trojan
    server: $ipv4
    port: $actual_port
    password: $password
    udp: true
    skip-cert-verify: true
    sni: $sni"
                ;;
            ss2022)
                [[ -n "$ipv4" ]] && proxy="  - name: \"$name\"
    type: ss
    server: $ipv4
    port: $port
    cipher: $method
    password: $password
    udp: true"
                ;;
            hy2)
                [[ -n "$ipv4" ]] && proxy="  - name: \"$name\"
    type: hysteria2
    server: $ipv4
    port: $port
    password: $password
    sni: $sni
    skip-cert-verify: true"
                ;;
            tuic)
                [[ -n "$ipv4" ]] && proxy="  - name: \"$name\"
    type: tuic
    server: $ipv4
    port: $port
    uuid: $uuid
    password: $password
    alpn: [h3]
    udp-relay-mode: native
    congestion-controller: bbr
    sni: $sni
    skip-cert-verify: true"
                ;;
        esac
        
        if [[ -n "$proxy" ]]; then
            proxies+="$proxy"$'\n'
            proxy_names+="      - \"$name\""$'\n'
        fi
    done
    
    # 生成完整 Clash 配置
    cat << EOF
mixed-port: 7897
allow-lan: false
mode: rule
log-level: info

proxies:
$proxies
proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
$proxy_names
rules:
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
EOF
}

# 生成 Surge 订阅内容
gen_surge_sub() {
    local installed=$(get_installed_protocols)
    local ipv4=$(get_ipv4)
    local proxies=""
    local proxy_names=""
    
    for protocol in $installed; do
        local info_file="$CFG/${protocol}.info"
        [[ ! -f "$info_file" ]] && continue
        
        local uuid="" port="" sni="" short_id="" public_key="" path=""
        local password="" username="" method="" psk=""
        source "$info_file"
        
        local name="$(get_protocol_name $protocol)"
        local proxy=""
        
        case "$protocol" in
            trojan)
                [[ -n "$ipv4" ]] && proxy="$name = trojan, $ipv4, $port, password=$password, sni=$sni, skip-cert-verify=true"
                ;;
            ss2022)
                [[ -n "$ipv4" ]] && proxy="$name = ss, $ipv4, $port, encrypt-method=$method, password=$password"
                ;;
            hy2)
                [[ -n "$ipv4" ]] && proxy="$name = hysteria2, $ipv4, $port, password=$password, sni=$sni, skip-cert-verify=true"
                ;;
            snell|snell-v5)
                [[ -n "$ipv4" ]] && proxy="$name = snell, $ipv4, $port, psk=$psk, version=${version:-4}"
                ;;
        esac
        
        if [[ -n "$proxy" ]]; then
            proxies+="$proxy"$'\n'
            [[ -n "$proxy_names" ]] && proxy_names+=", "
            proxy_names+="$name"
        fi
    done
    
    cat << EOF
[General]
loglevel = notify

[Proxy]
$proxies
[Proxy Group]
Proxy = select, $proxy_names

[Rule]
GEOIP,CN,DIRECT
FINAL,Proxy
EOF
}

# 生成订阅文件
generate_sub_files() {
    local sub_uuid=$(get_sub_uuid)
    local sub_dir="$CFG/subscription/$sub_uuid"
    mkdir -p "$sub_dir"
    
    _info "生成订阅文件..."
    
    # V2Ray/通用订阅
    gen_v2ray_sub > "$sub_dir/base64"
    
    # Clash 订阅
    gen_clash_sub > "$sub_dir/clash.yaml"
    
    # Surge 订阅
    gen_surge_sub > "$sub_dir/surge.conf"
    
    chmod -R 644 "$sub_dir"/*
    _ok "订阅文件已生成"
}

# 配置 Nginx 订阅服务
setup_nginx_sub() {
    local sub_uuid=$(get_sub_uuid)
    local sub_port="${1:-8443}"
    local domain="${2:-}"
    local use_https="${3:-true}"
    
    # 确保订阅文件存在
    generate_sub_files
    
    local sub_dir="$CFG/subscription/$sub_uuid"
    local fake_conf="/etc/nginx/conf.d/vless-fake.conf"
    
    # 检查 vless-fake.conf 是否已经配置了订阅端口
    if [[ -f "$fake_conf" ]] && grep -q "listen.*$sub_port" "$fake_conf" 2>/dev/null; then
        # 检查是否有正确的订阅路由配置 (使用 alias 而不是 try_files)
        if grep -q "location.*sub.*alias.*subscription" "$fake_conf" 2>/dev/null; then
            # 保存订阅配置
            cat > "$CFG/sub.info" << EOF
sub_uuid=$sub_uuid
sub_port=$sub_port
sub_domain=$domain
sub_https=$use_https
EOF
            # 重载 Nginx 确保配置生效
            nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null
            _ok "订阅服务已配置 (复用现有 Nginx 配置)"
            return 0
        else
            # 旧配置没有正确的订阅路由，需要重新生成
            _warn "检测到旧版 Nginx 配置，正在更新订阅路由..."
            rm -f "$fake_conf"
            # 重新调用 create_fake_website 生成正确的配置
            create_fake_website "$domain" "vless-vision" "$sub_port"
        fi
    fi
    
    # 检查证书
    local cert_file="$CFG/certs/server.crt"
    local key_file="$CFG/certs/server.key"
    local nginx_conf="/etc/nginx/conf.d/vless-sub.conf"
    
    # 先删除可能存在的旧配置，避免冲突
    rm -f "$nginx_conf" 2>/dev/null
    
    if [[ "$use_https" == "true" && ( ! -f "$cert_file" || ! -f "$key_file" ) ]]; then
        _warn "证书不存在，生成自签名证书..."
        gen_self_cert "${domain:-localhost}"
    fi
    
    # 再次检查证书是否存在
    if [[ "$use_https" == "true" && ( ! -f "$cert_file" || ! -f "$key_file" ) ]]; then
        _err "证书文件不存在，无法配置 HTTPS"
        _warn "切换到 HTTP 模式..."
        use_https="false"
    fi
    
    _info "配置 Nginx..."
    
    mkdir -p /etc/nginx/conf.d
    
    if [[ "$use_https" == "true" ]]; then
        cat > "$nginx_conf" << EOF
server {
    listen $sub_port ssl http2;
    listen [::]:$sub_port ssl http2;
    server_name ${domain:-_};
    
    ssl_certificate $cert_file;
    ssl_certificate_key $key_file;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # 订阅路径
    location /sub/$sub_uuid/ {
        alias $sub_dir/;
        default_type text/plain;
        add_header Content-Type 'text/plain; charset=utf-8';
    }
    
    # Clash 订阅
    location /sub/$sub_uuid/clash {
        alias $sub_dir/clash.yaml;
        default_type text/yaml;
        add_header Content-Disposition 'attachment; filename="clash.yaml"';
    }
    
    # Surge 订阅
    location /sub/$sub_uuid/surge {
        alias $sub_dir/surge.conf;
        default_type text/plain;
        add_header Content-Disposition 'attachment; filename="surge.conf"';
    }
    
    # 通用订阅 (Base64)
    location /sub/$sub_uuid/v2ray {
        alias $sub_dir/base64;
        default_type text/plain;
    }
    
    # 伪装网页
    root /var/www/html;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # 隐藏 Nginx 版本
    server_tokens off;
}
EOF
    else
        cat > "$nginx_conf" << EOF
server {
    listen $sub_port;
    listen [::]:$sub_port;
    server_name ${domain:-_};
    
    location /sub/$sub_uuid/ {
        alias $sub_dir/;
        default_type text/plain;
        add_header Content-Type 'text/plain; charset=utf-8';
    }
    
    location /sub/$sub_uuid/clash {
        alias $sub_dir/clash.yaml;
        default_type text/yaml;
        add_header Content-Disposition 'attachment; filename="clash.yaml"';
    }
    
    location /sub/$sub_uuid/surge {
        alias $sub_dir/surge.conf;
        default_type text/plain;
        add_header Content-Disposition 'attachment; filename="surge.conf"';
    }
    
    location /sub/$sub_uuid/v2ray {
        alias $sub_dir/base64;
        default_type text/plain;
    }
    
    # 伪装网页
    root /var/www/html;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # 隐藏 Nginx 版本
    server_tokens off;
}
EOF
    fi
    
    # 确保伪装网页存在
    if [[ ! -f "/var/www/html/index.html" ]]; then
        mkdir -p /var/www/html
        cat > /var/www/html/index.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        p { color: #666; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Our Website</h1>
        <p>This is a simple website hosted on our server.</p>
    </div>
</body>
</html>
HTMLEOF
    fi
    
    # 清理旧的订阅目录
    find "$CFG/subscription" -mindepth 1 -maxdepth 1 -type d ! -name "$sub_uuid" -exec rm -rf {} \; 2>/dev/null
    
    # 保存订阅配置
    cat > "$CFG/sub.info" << EOF
sub_uuid=$sub_uuid
sub_port=$sub_port
sub_domain=$domain
sub_https=$use_https
EOF
    
    # 测试并重载 Nginx
    if nginx -t 2>/dev/null; then
        if [[ "$DISTRO" == "alpine" ]]; then
            rc-service nginx restart 2>/dev/null || nginx -s reload
        else
            systemctl reload nginx 2>/dev/null || nginx -s reload
        fi
        _ok "Nginx 配置完成"
        return 0
    else
        _err "Nginx 配置错误"
        rm -f "$nginx_conf"
        return 1
    fi
}

# 显示订阅链接
show_sub_links() {
    [[ ! -f "$CFG/sub.info" ]] && { _warn "订阅服务未配置"; return; }
    
    # 清除变量避免污染
    local sub_uuid="" sub_port="" sub_domain="" sub_https=""
    source "$CFG/sub.info"
    local ipv4=$(get_ipv4)
    local protocol="http"
    [[ "$sub_https" == "true" ]] && protocol="https"
    
    local base_url="${protocol}://${sub_domain:-$ipv4}:${sub_port}/sub/${sub_uuid}"
    
    _line
    echo -e "  ${W}订阅链接${NC}"
    _line
    echo -e "  ${Y}Clash/Clash Verge (推荐):${NC}"
    echo -e "  ${G}${base_url}/clash${NC}"
    echo ""
    echo -e "  ${Y}Surge:${NC}"
    echo -e "  ${G}${base_url}/surge${NC}"
    echo ""
    echo -e "  ${Y}V2Ray/通用:${NC}"
    echo -e "  ${G}${base_url}/v2ray${NC}"
    _line
    echo -e "  ${D}订阅路径包含随机UUID，请妥善保管${NC}"
}

# 订阅服务管理菜单
manage_subscription() {
    while true; do
        _header
        echo -e "  ${W}订阅服务管理${NC}"
        _line
        
        if [[ -f "$CFG/sub.info" ]]; then
            # 清除变量避免污染
            local sub_uuid="" sub_port="" sub_domain="" sub_https=""
            source "$CFG/sub.info"
            echo -e "  状态: ${G}已配置${NC}"
            echo -e "  端口: ${G}$sub_port${NC}"
            [[ -n "$sub_domain" ]] && echo -e "  域名: ${G}$sub_domain${NC}"
            echo -e "  HTTPS: ${G}$sub_https${NC}"
            echo ""
            _item "1" "查看订阅链接"
            _item "2" "更新订阅内容"
            _item "3" "重新配置"
            _item "4" "停用订阅服务"
        else
            echo -e "  状态: ${D}未配置${NC}"
            echo ""
            _item "1" "启用订阅服务"
        fi
        _item "0" "返回"
        _line
        
        read -rp "  请选择: " choice
        
        if [[ -f "$CFG/sub.info" ]]; then
            case $choice in
                1) show_sub_links; _pause ;;
                2) generate_sub_files; _ok "订阅内容已更新"; _pause ;;
                3) setup_subscription_interactive ;;
                4) 
                    rm -f /etc/nginx/conf.d/vless-sub.conf "$CFG/sub.info"
                    rm -rf "$CFG/subscription"
                    nginx -s reload 2>/dev/null
                    _ok "订阅服务已停用"
                    _pause
                    ;;
                0) return ;;
            esac
        else
            case $choice in
                1) setup_subscription_interactive ;;
                0) return ;;
            esac
        fi
    done
}

# 交互式配置订阅
setup_subscription_interactive() {
    _header
    echo -e "  ${W}配置订阅服务${NC}"
    _line
    
    # 询问是否重新生成 UUID
    if [[ -f "$CFG/sub_uuid" ]]; then
        echo -e "  ${Y}检测到已有订阅 UUID${NC}"
        read -rp "  是否重新生成 UUID? [y/N]: " regen_uuid
        if [[ "$regen_uuid" =~ ^[yY]$ ]]; then
            local old_uuid=$(cat "$CFG/sub_uuid")
            reset_sub_uuid
            local new_uuid=$(cat "$CFG/sub_uuid")
            _ok "UUID 已更新: ${old_uuid:0:8}... → ${new_uuid:0:8}..."
            # 清理旧的订阅目录
            rm -rf "$CFG/subscription/$old_uuid" 2>/dev/null
        fi
        echo ""
    fi
    
    # 安装 Nginx
    if ! check_cmd nginx; then
        _info "需要安装 Nginx..."
        install_nginx || { _err "Nginx 安装失败"; _pause; return; }
    fi
    
    # 端口
    local default_port=8443
    read -rp "  订阅端口 [$default_port]: " sub_port
    sub_port="${sub_port:-$default_port}"
    
    # 域名
    echo -e "  ${D}留空使用服务器IP${NC}"
    read -rp "  域名 (可选): " sub_domain
    
    # HTTPS
    local use_https="true"
    read -rp "  启用 HTTPS? [Y/n]: " https_choice
    [[ "$https_choice" =~ ^[nN]$ ]] && use_https="false"
    
    # 配置
    if setup_nginx_sub "$sub_port" "$sub_domain" "$use_https"; then
        # 启动 Nginx
        if [[ "$DISTRO" == "alpine" ]]; then
            rc-update add nginx default 2>/dev/null
            rc-service nginx start 2>/dev/null
        else
            systemctl enable nginx 2>/dev/null
            systemctl start nginx 2>/dev/null
        fi
        
        echo ""
        show_sub_links
    fi
    _pause
}

#═══════════════════════════════════════════════════════════════════════════════
# 脚本更新
#═══════════════════════════════════════════════════════════════════════════════

do_update() {
    _header
    echo -e "  ${W}脚本更新${NC}"
    _line
    
    echo -e "  当前版本: ${G}v${VERSION}${NC}"
    _info "检查最新版本..."
    
    local raw_url="https://raw.githubusercontent.com/Chil30/vless-all-in-one/main/vless.sh"
    local tmp_file=$(mktemp)
    
    # 下载最新脚本
    if ! curl -sL --connect-timeout 10 -o "$tmp_file" "$raw_url"; then
        rm -f "$tmp_file"
        _err "下载失败，请检查网络连接"
        return 1
    fi
    
    # 获取远程版本号
    local remote_ver=$(grep -m1 '^readonly VERSION=' "$tmp_file" 2>/dev/null | cut -d'"' -f2)
    if [[ -z "$remote_ver" ]]; then
        rm -f "$tmp_file"
        _err "无法获取远程版本信息"
        return 1
    fi
    
    echo -e "  最新版本: ${C}v${remote_ver}${NC}"
    
    # 比较版本
    if [[ "$VERSION" == "$remote_ver" ]]; then
        rm -f "$tmp_file"
        _ok "已是最新版本"
        return 0
    fi
    
    _line
    read -rp "  发现新版本，是否更新? [Y/n]: " confirm
    if [[ "$confirm" =~ ^[nN]$ ]]; then
        rm -f "$tmp_file"
        return 0
    fi
    
    _info "更新中..."
    
    # 获取当前脚本路径
    local script_path=$(readlink -f "$0")
    local script_dir=$(dirname "$script_path")
    local script_name=$(basename "$script_path")
    
    # 备份当前脚本
    cp "$script_path" "${script_path}.bak" 2>/dev/null
    
    # 替换脚本
    if mv "$tmp_file" "$script_path" && chmod +x "$script_path"; then
        _ok "更新成功! v${VERSION} -> v${remote_ver}"
        echo ""
        echo -e "  ${C}请重新运行脚本以使用新版本${NC}"
        echo -e "  ${D}备份文件: ${script_path}.bak${NC}"
        _line
        exit 0
    else
        # 恢复备份
        [[ -f "${script_path}.bak" ]] && mv "${script_path}.bak" "$script_path"
        rm -f "$tmp_file"
        _err "更新失败"
        return 1
    fi
}

main_menu() {
    check_root
    clean_corrupted_info_files  # 清理被污染的配置文件
    
    while true; do
        _header
        echo ""
        show_status
        echo ""
        _line
        
        local installed=$(get_installed_protocols)
        if [[ -n "$installed" ]]; then
            local role=$(get_role)
            if [[ "$role" == "server" ]]; then
                # 多协议服务端菜单
                _item "1" "安装新协议 (多协议共存)"
                _item "2" "查看所有协议配置"
                _item "3" "订阅服务管理"
                _item "4" "管理协议服务"
                _item "5" "BBR 网络优化"
                _item "6" "卸载指定协议"
                _item "7" "完全卸载"
            else
                # 客户端菜单
                _item "1" "查看节点信息"
                _item "2" "切换代理模式"
                _item "3" "测试连接"
                _item "4" "添加节点"
                _item "5" "切换节点"
                _item "6" "删除节点"
                is_paused && _item "7" "恢复服务" || _item "7" "暂停服务"
                _item "8" "重启服务"
                _item "9" "卸载"
            fi
        else
            _item "1" "安装服务端"
            _item "2" "安装客户端 (JOIN码)"
        fi
        _item "u" "检查更新"
        _item "0" "退出"
        _line
        
        read -rp "  请选择: " choice || exit 0
        
        if [[ -n "$installed" ]]; then
            local role=$(get_role)
            if [[ "$role" == "server" ]]; then
                case $choice in
                    1) do_install_server ;;
                    2) show_all_protocols_info ;;
                    3) manage_subscription ;;
                    4) manage_protocol_services ;;
                    5) enable_bbr ;;
                    6) uninstall_specific_protocol ;;
                    7) do_uninstall ;;
                    u|U) do_update ;;
                    0) exit 0 ;;
                    *) _err "无效选择" ;;
                esac
            else
                case $choice in
                    1) show_client_info ;;
                    2) do_switch_mode ;;
                    3) test_connection ;;
                    4) do_add_node ;;
                    5) do_switch_node ;;
                    6) do_delete_node ;;
                    7) is_paused && { _info "恢复服务..."; start_services && _ok "已恢复"; } || { _info "暂停服务..."; stop_services; touch "$CFG/paused"; _ok "已暂停"; } ;;
                    8) _info "重启服务..."; stop_services; sleep 1; start_services && _ok "重启完成" ;;
                    9) do_uninstall ;;
                    u|U) do_update ;;
                    0) exit 0 ;;
                    *) _err "无效选择" ;;
                esac
            fi
        else
            case $choice in
                1) do_install_server ;;
                2) do_install_client ;;
                u|U) do_update ;;
                0) exit 0 ;;
                *) _err "无效选择" ;;
            esac
        fi
        _pause
    done
}

# 启动主菜单
main_menu