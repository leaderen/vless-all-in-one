#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
#  多协议代理一键部署脚本 v3.0.2 [服务端]
#  支持协议: VLESS+Reality / VLESS+Reality+XHTTP / VLESS+WS / VMess+WS / 
#           VLESS-XTLS-Vision / SOCKS5 / SS2022 / HY2 / Trojan / 
#           Snell v4 / Snell v5 / AnyTLS / TUIC (共13种)
#  插件支持: Snell v4/v5 和 SS2022 可选启用 ShadowTLS
#  适配: Alpine/Debian/Ubuntu/CentOS
#  
#  作者: Chil30
#  项目地址: https://github.com/Chil30/vless-all-in-one
#═══════════════════════════════════════════════════════════════════════════════

readonly VERSION="3.0.2"
readonly AUTHOR="Chil30"
readonly REPO_URL="https://github.com/Chil30/vless-all-in-one"
readonly CFG="/etc/vless-reality"

#═══════════════════════════════════════════════════════════════════════════════
#  用户配置区 - 可根据需要修改以下设置
#═══════════════════════════════════════════════════════════════════════════════
# JOIN 码显示开关 (on=显示, off=隐藏)
# 如果只需要服务端功能，不需要客户端 JOIN 码，可设置为 off
SHOW_JOIN_CODE="off"
#═══════════════════════════════════════════════════════════════════════════════

# 颜色
R='\e[31m'; G='\e[32m'; Y='\e[33m'; C='\e[36m'; W='\e[97m'; D='\e[2m'; NC='\e[0m'
set -o pipefail

# 日志文件
LOG_FILE="/var/log/vless-server.log"

# 统一日志函数 - 同时输出到终端和日志文件
_log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    # 写入日志文件（无颜色）
    echo "[$timestamp] [$level] $msg" >> "$LOG_FILE" 2>/dev/null
}

# 初始化日志文件
init_log() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
    # 日志轮转：超过 5MB 时截断保留最后 1000 行
    if [[ -f "$LOG_FILE" ]]; then
        local size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        if [[ $size -gt 5242880 ]]; then
            tail -n 1000 "$LOG_FILE" > "$LOG_FILE.tmp" 2>/dev/null && mv "$LOG_FILE.tmp" "$LOG_FILE" 2>/dev/null
        fi
    fi
    _log "INFO" "========== 脚本启动 v${VERSION} =========="
}

# timeout 兼容函数（某些精简系统可能没有 timeout 命令）
if ! command -v timeout &>/dev/null; then
    timeout() {
        local duration="$1"
        shift
        # 使用后台进程实现简单的超时
        "$@" &
        local pid=$!
        ( sleep "$duration" 2>/dev/null; kill -9 $pid 2>/dev/null ) &
        local killer=$!
        wait $pid 2>/dev/null
        local ret=$?
        kill $killer 2>/dev/null
        wait $killer 2>/dev/null
        return $ret
    }
fi

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
XRAY_PROTOCOLS="vless vless-xhttp vless-ws vmess-ws vless-vision trojan socks ss2022"
INDEPENDENT_PROTOCOLS="hy2 tuic snell snell-v5 snell-shadowtls snell-v5-shadowtls ss2022-shadowtls anytls"

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
        local temp_inbound=$(mktemp)
        local backup_config=""
        
        # 备份原配置（用于失败时恢复）
        if [[ -f "$CFG/config.json" ]]; then
            backup_config=$(mktemp)
            cp "$CFG/config.json" "$backup_config"
        fi
        
        if ! echo "$inbound_json" | jq -c '.' > "$temp_inbound" 2>/dev/null; then
            _err "生成的 $protocol inbound JSON 格式错误"
            _log "ERROR" "JSON 内容: $inbound_json"
            rm -f "$temp_inbound" "$temp_config" "$backup_config"
            return 1
        fi
        if ! jq '.inbounds += [input]' "$CFG/config.json" "$temp_inbound" > "$temp_config" 2>/dev/null; then
            _err "合并 $protocol 配置到 Xray 配置文件失败"
            # 恢复原配置
            [[ -n "$backup_config" && -f "$backup_config" ]] && mv "$backup_config" "$CFG/config.json"
            rm -f "$temp_inbound" "$temp_config"
            return 1
        fi
        mv "$temp_config" "$CFG/config.json"
        rm -f "$temp_inbound" "$backup_config"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 基础工具函数
#═══════════════════════════════════════════════════════════════════════════════
_line()  { echo -e "${D}─────────────────────────────────────────────${NC}"; }
_dline() { echo -e "${C}═════════════════════════════════════════════${NC}"; }
_info()  { echo -e "  ${C}▸${NC} $1"; }
_ok()    { echo -e "  ${G}✓${NC} $1"; _log "OK" "$1"; }
_err()   { echo -e "  ${R}✗${NC} $1"; _log "ERROR" "$1"; }
_warn()  { echo -e "  ${Y}!${NC} $1"; _log "WARN" "$1"; }
_item()  { echo -e "  ${G}$1${NC}) $2"; }
_pause() { echo ""; read -rp "  按回车继续..."; }

_header() {
    clear; echo ""
    _dline
    echo -e "      ${W}多协议代理${NC} ${D}一键部署${NC} ${C}v${VERSION}${NC} ${Y}[服务端]${NC}"
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
        vmess-ws) echo "VMess+WS" ;;
        ss2022) echo "Shadowsocks 2022" ;;
        hy2) echo "Hysteria2" ;;
        trojan) echo "Trojan" ;;
        snell) echo "Snell v4" ;;
        snell-v5) echo "Snell v5" ;;
        snell-shadowtls) echo "Snell v4+ShadowTLS" ;;
        snell-v5-shadowtls) echo "Snell v5+ShadowTLS" ;;
        ss2022-shadowtls) echo "SS2022+ShadowTLS" ;;
        tuic) echo "TUIC v5" ;;
        socks) echo "SOCKS5" ;;
        anytls) echo "AnyTLS" ;;
        *) echo "未知" ;;
    esac
}

check_root()      { [[ $EUID -ne 0 ]] && { _err "请使用 root 权限运行"; exit 1; }; }
check_cmd()       { command -v "$1" &>/dev/null; }
check_installed() { [[ -d "$CFG" && ( -f "$CFG/config.json" || -f "$CFG/config.yaml" || -f "$CFG/config.conf" || -f "$CFG/info" ) ]]; }
get_role()        { [[ -f "$CFG/role" ]] && cat "$CFG/role" || echo ""; }
is_paused()       { [[ -f "$CFG/paused" ]]; }

# 配置 DNS64 (纯 IPv6 环境)
configure_dns64() {
    # 检测 IPv4 网络是否可用
    if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        return 0  # IPv4 正常，无需配置
    fi
    
    _warn "检测到纯 IPv6 环境，正在配置 DNS64..."
    
    # 备份原有配置
    if [[ -f /etc/resolv.conf ]] && [[ ! -f /etc/resolv.conf.bak ]]; then
        cp /etc/resolv.conf /etc/resolv.conf.bak
    fi
    
    # 写入 DNS64 服务器
    cat > /etc/resolv.conf << 'EOF'
nameserver 2a00:1098:2b::1
nameserver 2001:4860:4860::6464
nameserver 2a00:1098:2c::1
EOF
    
    _ok "DNS64 配置完成 (Kasper Sky + Google DNS64 + Trex)"
}

# 检测并安装基础依赖
check_dependencies() {
    # 先配置 DNS64 (如果是纯 IPv6 环境)
    configure_dns64
    
    local missing_deps=()
    local need_install=false
    
    # 必需的基础命令
    local required_cmds="curl jq openssl"
    
    for cmd in $required_cmds; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
            need_install=true
        fi
    done
    
    if [[ "$need_install" == "true" ]]; then
        _info "安装缺失的依赖: ${missing_deps[*]}..."
        
        case "$DISTRO" in
            alpine)
                apk update >/dev/null 2>&1
                apk add --no-cache curl jq openssl coreutils >/dev/null 2>&1
                ;;
            centos)
                yum install -y curl jq openssl >/dev/null 2>&1
                ;;
            debian|ubuntu)
                apt-get update >/dev/null 2>&1
                DEBIAN_FRONTEND=noninteractive apt-get install -y curl jq openssl >/dev/null 2>&1
                ;;
        esac
        
        # 再次检查
        for cmd in $required_cmds; do
            if ! command -v "$cmd" &>/dev/null; then
                _err "依赖安装失败: $cmd"
                _warn "请手动安装: $cmd"
                return 1
            fi
        done
        _ok "依赖安装完成"
    fi
    return 0
}

#═══════════════════════════════════════════════════════════════════════════════
# 核心功能：强力清理 & 时间同步
#═══════════════════════════════════════════════════════════════════════════════
force_cleanup() {
    svc stop vless-watchdog 2>/dev/null
    svc stop vless-reality 2>/dev/null
    svc stop vless-hy2 2>/dev/null
    svc stop vless-tuic 2>/dev/null
    svc stop vless-snell 2>/dev/null
    svc stop vless-snell-v5 2>/dev/null
    svc stop vless-anytls 2>/dev/null
    svc stop vless-snell-shadowtls 2>/dev/null
    svc stop vless-snell-v5-shadowtls 2>/dev/null
    svc stop vless-ss2022-shadowtls 2>/dev/null
    svc stop vless-snell-shadowtls-backend 2>/dev/null
    svc stop vless-snell-v5-shadowtls-backend 2>/dev/null
    svc stop vless-ss2022-shadowtls-backend 2>/dev/null
    killall xray hysteria snell-server snell-server-v5 tuic-server anytls-server shadow-tls 2>/dev/null
    
    # 清理 Hysteria2 端口跳跃 NAT 规则
    if [[ -f "$CFG/hy2.info" ]]; then
        local hop_enable="" hop_start="" hop_end="" port=""
        source "$CFG/hy2.info" 2>/dev/null
        if [[ -n "$port" ]]; then
            local hs="${hop_start:-20000}"
            local he="${hop_end:-50000}"
            iptables -t nat -D PREROUTING -p udp --dport ${hs}:${he} -j REDIRECT --to-ports ${port} 2>/dev/null
            iptables -t nat -D OUTPUT -p udp --dport ${hs}:${he} -j REDIRECT --to-ports ${port} 2>/dev/null
        fi
    fi
    
    # 兜底清理 REDIRECT 规则
    iptables -t nat -S PREROUTING 2>/dev/null | grep -E "REDIRECT.*--to-ports" | while read -r rule; do
        local del_rule=$(echo "$rule" | sed 's/^-A/-D/')
        eval "iptables -t nat $del_rule" 2>/dev/null || true
    done
    
    iptables -t nat -S OUTPUT 2>/dev/null | grep -E "REDIRECT.*--to-ports" | while read -r rule; do
        local del_rule=$(echo "$rule" | sed 's/^-A/-D/')
        eval "iptables -t nat $del_rule" 2>/dev/null || true
    done
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
# 网络工具
#═══════════════════════════════════════════════════════════════════════════════
get_ipv4() { curl -4 -sf --connect-timeout 5 ip.sb 2>/dev/null || curl -4 -sf --connect-timeout 5 ifconfig.me 2>/dev/null; }
get_ipv6() { curl -6 -sf --connect-timeout 5 ip.sb 2>/dev/null || curl -6 -sf --connect-timeout 5 ifconfig.me 2>/dev/null; }

# 获取 IP 地理位置代码 (如 HK, JP, US, SG)
get_ip_country() {
    local ip="${1:-}"
    local country=""
    
    # 方法1: ip-api.com (免费，无需 key)
    if [[ -n "$ip" ]]; then
        country=$(curl -sf --connect-timeout 3 "http://ip-api.com/line/${ip}?fields=countryCode" 2>/dev/null)
    else
        country=$(curl -sf --connect-timeout 3 "http://ip-api.com/line/?fields=countryCode" 2>/dev/null)
    fi
    
    # 方法2: 回退到 ipinfo.io
    if [[ -z "$country" || "$country" == "fail" ]]; then
        if [[ -n "$ip" ]]; then
            country=$(curl -sf --connect-timeout 3 "https://ipinfo.io/${ip}/country" 2>/dev/null)
        else
            country=$(curl -sf --connect-timeout 3 "https://ipinfo.io/country" 2>/dev/null)
        fi
    fi
    
    # 清理结果（去除空白字符）
    country=$(echo "$country" | tr -d '[:space:]')
    
    # 默认返回 XX
    echo "${country:-XX}"
}

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

#═══════════════════════════════════════════════════════════════════════════════
# 端口管理
#═══════════════════════════════════════════════════════════════════════════════

# 检查脚本内部记录的端口占用
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
        vless|vless-xhttp|vless-vision|trojan|anytls|snell-shadowtls|snell-v5-shadowtls|ss2022-shadowtls)
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

#═══════════════════════════════════════════════════════════════════════════════
# 密钥与凭证生成
#═══════════════════════════════════════════════════════════════════════════════

# 生成 UUID
gen_uuid() { cat /proc/sys/kernel/random/uuid 2>/dev/null || printf '%04x%04x-%04x-%04x-%04x-%04x%04x%04x\n' $RANDOM $RANDOM $RANDOM $(($RANDOM&0x0fff|0x4000)) $(($RANDOM&0x3fff|0x8000)) $RANDOM $RANDOM $RANDOM; }

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
        
        # 保存订阅配置信息（关键！确保订阅链接显示正确）
        local sub_uuid=$(get_sub_uuid)
        local use_https="false"
        [[ "$protocol" == "vless-vision" || "$protocol" == "vless-ws" || "$protocol" == "vmess-ws" || "$protocol" == "trojan" ]] && use_https="true"
        
        cat > "$CFG/sub.info" << EOF
sub_uuid=$sub_uuid
sub_port=$nginx_port
sub_domain=$domain
sub_https=$use_https
EOF
        _log "INFO" "订阅配置已保存: UUID=${sub_uuid:0:8}..., 端口=$nginx_port, 域名=$domain"
    fi
    
}

gen_sni() { 
    # 稳定的 SNI 列表（国内可访问、大厂子域名、不易被封）
    local s=(
        # 科技巨头与云服务（最稳）
        "www.microsoft.com"
        "learn.microsoft.com"
        "azure.microsoft.com"
        "www.apple.com"
        "www.amazon.com"
        "aws.amazon.com"
        "www.icloud.com"
        "itunes.apple.com"
        # 硬件与芯片厂商（流量特征正常）
        "www.nvidia.com"
        "www.amd.com"
        "www.intel.com"
        "www.samsung.com"
        "www.dell.com"
        # 企业软件与网络安全（企业级白名单常客）
        "www.cisco.com"
        "www.oracle.com"
        "www.ibm.com"
        "www.adobe.com"
        "www.autodesk.com"
        "www.sap.com"
        "www.vmware.com"
    )
    # 使用 /dev/urandom 生成更好的随机数
    local idx=$(od -An -tu4 -N4 /dev/urandom 2>/dev/null | tr -d ' ')
    [[ -z "$idx" ]] && idx=$RANDOM
    echo "${s[$((idx % ${#s[@]}))]}"
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

# 提取 IP 地址后缀（IPv4 取最后一段，IPv6 直接返回 "v6"）
get_ip_suffix() {
    local ip="$1"
    # 移除方括号
    ip="${ip#[}"
    ip="${ip%]}"
    
    if [[ "$ip" == *:* ]]; then
        # IPv6: 直接返回 "v6"
        echo "v6"
    else
        # IPv4: 取最后一个点后面的数字
        echo "${ip##*.}"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 分享链接生成
#═══════════════════════════════════════════════════════════════════════════════

gen_vless_link() {
    local ip="$1" port="$2" uuid="$3" pbk="$4" sid="$5" sni="$6" country="${7:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}VLESS+Reality${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=reality&type=tcp&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&flow=xtls-rprx-vision#${name}"
}

gen_vless_xhttp_link() {
    local ip="$1" port="$2" uuid="$3" pbk="$4" sid="$5" sni="$6" path="${7:-/}" country="${8:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}VLESS-XHTTP${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=reality&type=xhttp&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&path=$(urlencode "$path")&mode=auto#${name}"
}

gen_vmess_ws_link() {
    local ip="$1" port="$2" uuid="$3" sni="$4" path="$5" country="${6:-}"
    local clean_ip="${ip#[}"
    clean_ip="${clean_ip%]}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}VMess-WS${ip_suffix:+-${ip_suffix}}"

    # VMess ws 链接：vmess://base64(json)
    # 注意：allowInsecure 必须是字符串 "true"，不是布尔值
    local json
    json=$(cat <<EOF
{"v":"2","ps":"${name}","add":"${clean_ip}","port":"${port}","id":"${uuid}","aid":"0","scy":"auto","net":"ws","type":"none","host":"${sni}","path":"${path}","tls":"tls","sni":"${sni}","allowInsecure":"true"}
EOF
)
    printf 'vmess://%s\n' "$(echo -n "$json" | base64 -w 0 2>/dev/null || echo -n "$json" | base64 | tr -d '\n')"
}

gen_qr() { printf '%s\n' "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=$(urlencode "$1")"; }



# 生成各协议分享链接
gen_hy2_link() {
    local ip="$1" port="$2" password="$3" sni="$4" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}Hysteria2${ip_suffix:+-${ip_suffix}}"
    # 链接始终使用实际端口，端口跳跃需要客户端手动配置
    printf '%s\n' "hysteria2://${password}@${ip}:${port}?sni=${sni}&insecure=1#${name}"
}

gen_trojan_link() {
    local ip="$1" port="$2" password="$3" sni="$4" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}Trojan${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "trojan://${password}@${ip}:${port}?security=tls&sni=${sni}&type=tcp&allowInsecure=1#${name}"
}

gen_vless_ws_link() {
    local ip="$1" port="$2" uuid="$3" sni="$4" path="${5:-/}" country="${6:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}VLESS-WS${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=tls&sni=${sni}&type=ws&host=${sni}&path=$(urlencode "$path")&allowInsecure=1#${name}"
}

gen_vless_vision_link() {
    local ip="$1" port="$2" uuid="$3" sni="$4" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}VLESS-Vision${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=tls&sni=${sni}&type=tcp&flow=xtls-rprx-vision&allowInsecure=1#${name}"
}

gen_ss2022_link() {
    local ip="$1" port="$2" method="$3" password="$4" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}SS2022${ip_suffix:+-${ip_suffix}}"
    local userinfo=$(printf '%s:%s' "$method" "$password" | base64 -w 0 2>/dev/null || printf '%s:%s' "$method" "$password" | base64)
    printf '%s\n' "ss://${userinfo}@${ip}:${port}#${name}"
}

gen_snell_link() {
    local ip="$1" port="$2" psk="$3" version="${4:-4}" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}Snell-v${version}${ip_suffix:+-${ip_suffix}}"
    # Snell 没有标准URI格式，使用自定义格式
    printf '%s\n' "snell://${psk}@${ip}:${port}?version=${version}#${name}"
}

gen_tuic_link() {
    local ip="$1" port="$2" uuid="$3" password="$4" sni="$5" country="${6:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}TUIC${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "tuic://${uuid}:${password}@${ip}:${port}?congestion_control=bbr&alpn=h3&sni=${sni}&udp_relay_mode=native&allow_insecure=1#${name}"
}

gen_anytls_link() {
    local ip="$1" port="$2" password="$3" sni="$4" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}AnyTLS${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "anytls://${password}@${ip}:${port}?sni=${sni}&allowInsecure=1#${name}"
}

gen_shadowtls_link() {
    local ip="$1" port="$2" password="$3" method="$4" sni="$5" stls_password="$6" country="${7:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}ShadowTLS${ip_suffix:+-${ip_suffix}}"
    # ShadowTLS链接格式：ss://method:password@server:port#name + ShadowTLS参数
    local ss_link=$(echo -n "${method}:${password}" | base64 -w 0)
    printf '%s\n' "ss://${ss_link}@${ip}:${port}?plugin=shadow-tls;host=${sni};password=${stls_password}#${name}"
}

gen_snell_v5_link() {
    local ip="$1" port="$2" psk="$3" version="${4:-5}" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}Snell-v5${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "snell://${psk}@${ip}:${port}?version=${version}#${name}"
}

gen_socks_link() {
    local ip="$1" port="$2" username="$3" password="$4" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}SOCKS5${ip_suffix:+-${ip_suffix}}"
    if [[ -n "$username" && -n "$password" ]]; then
        printf '%s\n' "https://t.me/socks?server=${ip}&port=${port}&user=${username}&pass=${password}"
    else
        printf '%s\n' "socks5://${ip}:${port}#${name}"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 连接测试
#═══════════════════════════════════════════════════════════════════════════════

test_connection() {
    # 服务端：检查所有已安装协议的端口
    local installed=$(get_installed_protocols)
    for proto in $installed; do
        if [[ -f "$CFG/${proto}.info" ]]; then
            local port="" uuid="" password="" sni="" psk=""
            source "$CFG/${proto}.info"
            if ss -tlnp 2>/dev/null | grep -q ":$port " || ss -ulnp 2>/dev/null | grep -q ":$port "; then
                _ok "$(get_protocol_name $proto) 端口 $port 已监听"
            else
                _err "$(get_protocol_name $proto) 端口 $port 未监听"
            fi
        fi
    done
}

test_latency() {
    local ip="$1" port="$2" proto="${3:-tcp}" start end
    start=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
    
    if [[ "$proto" == "hy2" || "$proto" == "tuic" ]]; then
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
# 软件安装
#═══════════════════════════════════════════════════════════════════════════════

# 安装系统依赖
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
# 证书管理
#═══════════════════════════════════════════════════════════════════════════════

# 安装 acme.sh
install_acme_tool() {
    # 检查多个可能的安装位置
    local acme_paths=(
        "$HOME/.acme.sh/acme.sh"
        "/root/.acme.sh/acme.sh"
        "/usr/local/bin/acme.sh"
    )
    
    for acme_path in "${acme_paths[@]}"; do
        if [[ -f "$acme_path" ]]; then
            _ok "acme.sh 已安装 ($acme_path)"
            return 0
        fi
    done
    
    _info "安装 acme.sh 证书申请工具..."
    
    # 方法1: 官方安装脚本
    if curl -sL https://get.acme.sh | sh -s email=admin@example.com 2>&1 | grep -qE "Install success|already installed"; then
        source "$HOME/.acme.sh/acme.sh.env" 2>/dev/null || true
        if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
            _ok "acme.sh 安装成功"
            return 0
        fi
    fi
    
    # 方法2: 使用 git clone
    if command -v git &>/dev/null; then
        _info "尝试使用 git 安装..."
        if git clone --depth 1 https://github.com/acmesh-official/acme.sh.git /tmp/acme.sh 2>/dev/null; then
            cd /tmp/acme.sh && ./acme.sh --install -m admin@example.com 2>/dev/null
            cd - >/dev/null
            rm -rf /tmp/acme.sh
            if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
                _ok "acme.sh 安装成功 (git)"
                return 0
            fi
        fi
    fi
    
    # 方法3: 直接下载脚本
    _info "尝试直接下载..."
    mkdir -p "$HOME/.acme.sh"
    if curl -sL -o "$HOME/.acme.sh/acme.sh" "https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh" 2>/dev/null; then
        chmod +x "$HOME/.acme.sh/acme.sh"
        if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
            _ok "acme.sh 安装成功 (直接下载)"
            return 0
        fi
    fi
    
    _err "acme.sh 安装失败，请检查网络连接"
    _warn "你可以手动安装: curl https://get.acme.sh | sh"
    return 1
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
    
    # 直接执行 acme.sh，不使用 timeout（避免某些系统兼容性问题）
    if "$acme_sh" --issue -d "$domain" --standalone --httpport 80 --force 2>&1 | tee "$acme_log" | grep -E "^\[|Verify finished|Cert success|error|Error" | sed 's/^/  /'; then
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
            
            # 检查是否是自签名证书
            local is_self_signed=true
            local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
            if [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"R11"* ]] || [[ "$issuer" == *"E1"* ]] || [[ "$issuer" == *"ZeroSSL"* ]] || [[ "$issuer" == *"Buypass"* ]]; then
                is_self_signed=false
            fi
            
            # 如果是自签名证书，询问用户是否申请真实证书
            if [[ "$is_self_signed" == "true" && "$is_fallback_mode" == "false" ]]; then
                echo ""
                _warn "检测到自签名证书 (域名: $CERT_DOMAIN)"
                echo -e "  ${G}1)${NC} 申请真实证书 (推荐 - 订阅功能可用)"
                echo -e "  ${G}2)${NC} 继续使用自签名证书 (订阅功能不可用)"
                echo ""
                read -rp "  请选择 [1]: " self_cert_choice
                
                if [[ "$self_cert_choice" != "2" ]]; then
                    # 用户选择申请真实证书，清除旧证书，走正常申请流程
                    rm -f "$CFG/certs/server.crt" "$CFG/certs/server.key" "$CFG/cert_domain"
                    CERT_DOMAIN=""
                    # 继续往下走到证书申请流程
                else
                    # 继续使用自签名证书，跳过 Nginx 配置
                    _ok "继续使用自签名证书: $CERT_DOMAIN"
                    return 0
                fi
            else
                # 真实证书，正常处理
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
                    generate_sub_files
                    create_fake_website "$CERT_DOMAIN" "$protocol" "$NGINX_PORT"
                else
                    # 检查 Nginx 配置是否有正确的订阅路由 (使用 alias 指向 subscription 目录)
                    local nginx_conf_valid=false
                    if grep -q "alias.*subscription" "/etc/nginx/conf.d/vless-fake.conf" 2>/dev/null; then
                        nginx_conf_valid=true
                    fi
                    
                    if [[ "$nginx_conf_valid" == "false" ]]; then
                        _warn "检测到旧版 Nginx 配置，正在更新..."
                        generate_sub_files
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
                        generate_sub_files
                        create_fake_website "$CERT_DOMAIN" "$protocol" "$NGINX_PORT"
                    fi
                fi
                
                return 0
            fi
        fi
    fi
    
    # 没有证书或用户选择申请新证书，询问用户
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
            
            # 确保配置目录存在
            mkdir -p "$CFG" 2>/dev/null
            
            # 保存端口到临时文件，供 create_fake_website 使用
            echo "$NGINX_PORT" > "$CFG/.nginx_port_tmp" 2>/dev/null
            
            # 申请证书（内部会调用 create_fake_website，会自动保存 sub.info）
            if get_acme_cert "$CERT_DOMAIN" "$protocol"; then
                echo "$CERT_DOMAIN" > "$CFG/cert_domain"
                # 确保订阅文件存在
                generate_sub_files
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
    
    # 如果有证书域名，检查是否是真实证书
    if [[ -n "$cert_domain" && -f "$CFG/certs/server.crt" ]]; then
        local is_real_cert=false
        local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
        if [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"R11"* ]] || [[ "$issuer" == *"E1"* ]] || [[ "$issuer" == *"ZeroSSL"* ]] || [[ "$issuer" == *"Buypass"* ]]; then
            is_real_cert=true
        fi
        
        # 真实证书：直接使用证书域名，不询问
        if [[ "$is_real_cert" == "true" ]]; then
            _ok "使用证书域名: $cert_domain" >&2
            echo "$cert_domain"
            return 0
        fi
    fi
    
    echo "" >&2
    _line >&2
    echo -e "  ${W}SNI 配置${NC}" >&2
    
    # 生成一个真正的随机 SNI（用于"更隐蔽"选项）
    local random_sni=$(gen_sni)
    
    # 如果有证书域名（自签名证书），询问是否使用
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
    
    # 智能证书选择
    local cert_file="" key_file=""
    local hy2_cert_dir="$CFG/certs/hy2"
    mkdir -p "$hy2_cert_dir"
    
    # 检查是否有真实域名的 ACME 证书
    local has_acme_cert=false
    if [[ -f "$CFG/cert_domain" && -f "$CFG/certs/server.crt" ]]; then
        local cert_domain=$(cat "$CFG/cert_domain")
        local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
        if [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"R11"* ]]; then
            # 有 ACME 证书，检查 SNI 是否匹配
            if [[ "$sni" == "$cert_domain" ]]; then
                has_acme_cert=true
                cert_file="$CFG/certs/server.crt"
                key_file="$CFG/certs/server.key"
                _ok "复用现有 ACME 证书 (域名: $sni)"
            fi
        fi
    fi
    
    # 如果没有匹配的 ACME 证书，使用独立自签证书
    if [[ "$has_acme_cert" == "false" ]]; then
        cert_file="$hy2_cert_dir/server.crt"
        key_file="$hy2_cert_dir/server.key"
        
        # 检查是否需要重新生成（SNI 变更或证书不存在）
        local need_regen=false
        if [[ ! -f "$cert_file" ]]; then
            need_regen=true
        else
            # 检查现有证书的 CN 是否匹配
            local cert_cn=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed 's/.*CN *= *//')
            if [[ "$cert_cn" != "$sni" ]]; then
                need_regen=true
            fi
        fi
        
        if [[ "$need_regen" == "true" ]]; then
            _info "为 Hysteria2 生成自签证书 (SNI: $sni)..."
            openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
                -keyout "$key_file" -out "$cert_file" \
                -subj "/CN=$sni" -days 36500 2>/dev/null
            chmod 600 "$key_file"
            _ok "Hysteria2 自签证书生成完成"
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
    local uuid="$1" port="$2" sni="${3:-bing.com}" path="${4:-/vless}" force_new_cert="${5:-false}"
    mkdir -p "$CFG"
    
    # 如果存在主协议（Vision/Trojan），则 VLESS WS 用作回落子协议
    local outer_port="$port"
    local has_master=false
    if [[ -f "$CFG/vless-vision.info" ]]; then
        outer_port=$(grep "^port=" "$CFG/vless-vision.info" | cut -d= -f2)
        has_master=true
    elif [[ -f "$CFG/trojan.info" ]]; then
        outer_port=$(grep "^port=" "$CFG/trojan.info" | cut -d= -f2)
        has_master=true
    fi

    # 独立安装时处理证书
    if [[ "$has_master" == "false" ]]; then
        if [[ "$force_new_cert" == "true" ]]; then
            # 检查现有证书是否是 CA 签发的真实证书
            local is_real_cert=false
            if [[ -f "$CFG/certs/server.crt" ]]; then
                local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
                if [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"R11"* ]] || [[ "$issuer" == *"E1"* ]] || [[ "$issuer" == *"ZeroSSL"* ]] || [[ "$issuer" == *"Buypass"* ]]; then
                    is_real_cert=true
                fi
            fi
            
            if [[ "$is_real_cert" == "true" ]]; then
                _warn "检测到 CA 签发的真实证书，不会覆盖"
            else
                # 只覆盖自签名证书
                rm -f "$CFG/certs/server.crt" "$CFG/certs/server.key" "$CFG/cert_domain"
                gen_self_cert "$sni"
                echo "$sni" > "$CFG/cert_domain"
            fi
        elif [[ ! -f "$CFG/certs/server.crt" ]]; then
            # 没有证书，生成新的
            gen_self_cert "$sni"
            echo "$sni" > "$CFG/cert_domain"
        fi
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
    local uuid="$1" port="$2" sni="$3" path="$4" force_new_cert="${5:-false}"

    # 如果存在主协议（Vision/Trojan），则 VMess WS 用作回落子协议：监听 127.0.0.1 内部端口
    local outer_port="$port"
    local has_master=false
    if [[ -f "$CFG/vless-vision.info" ]]; then
        outer_port=$(grep "^port=" "$CFG/vless-vision.info" | cut -d= -f2)
        has_master=true
    elif [[ -f "$CFG/trojan.info" ]]; then
        outer_port=$(grep "^port=" "$CFG/trojan.info" | cut -d= -f2)
        has_master=true
    fi

    # 独立安装时处理证书
    if [[ "$has_master" == "false" ]]; then
        if [[ "$force_new_cert" == "true" ]]; then
            # 检查现有证书是否是 CA 签发的真实证书
            local is_real_cert=false
            if [[ -f "$CFG/certs/server.crt" ]]; then
                local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
                if [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"R11"* ]] || [[ "$issuer" == *"E1"* ]] || [[ "$issuer" == *"ZeroSSL"* ]] || [[ "$issuer" == *"Buypass"* ]]; then
                    is_real_cert=true
                fi
            fi
            
            if [[ "$is_real_cert" == "true" ]]; then
                _warn "检测到 CA 签发的真实证书，不会覆盖"
                _warn "SNI 将使用证书域名，否则连接会失败"
                # 不覆盖真实证书，但 sni 参数已经传入，info 文件会记录用户选择的 sni
            else
                # 只覆盖自签名证书
                rm -f "$CFG/certs/server.crt" "$CFG/certs/server.key" "$CFG/cert_domain"
                gen_self_cert "$sni"
                echo "$sni" > "$CFG/cert_domain"
            fi
        elif [[ ! -f "$CFG/certs/server.crt" ]]; then
            # 没有证书，生成新的
            gen_self_cert "$sni"
            echo "$sni" > "$CFG/cert_domain"
        fi
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
    local common_snis="www.microsoft.com learn.microsoft.com azure.microsoft.com www.apple.com www.amazon.com aws.amazon.com www.icloud.com itunes.apple.com www.nvidia.com www.amd.com www.intel.com www.samsung.com www.dell.com www.cisco.com www.oracle.com www.ibm.com www.adobe.com www.autodesk.com www.sap.com www.vmware.com"
    
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

# Snell + ShadowTLS 服务端配置 (v4/v5)
gen_snell_shadowtls_server_config() {
    local psk="$1" port="$2" sni="${3:-www.microsoft.com}" stls_password="$4" version="${5:-4}" custom_backend_port="${6:-}"
    mkdir -p "$CFG"
    
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    local protocol_name="snell-shadowtls"
    local snell_bin="snell-server"
    local snell_conf="snell-shadowtls.conf"
    
    if [[ "$version" == "5" ]]; then
        protocol_name="snell-v5-shadowtls"
        snell_bin="snell-server-v5"
        snell_conf="snell-v5-shadowtls.conf"
    fi
    
    # Snell 后端端口 (内部监听) - 支持自定义或自动计算
    local snell_backend_port
    if [[ -n "$custom_backend_port" ]]; then
        snell_backend_port="$custom_backend_port"
    else
        snell_backend_port=$((port + 10000))
        if [[ $snell_backend_port -gt 65535 ]]; then
            snell_backend_port=$((port - 10000))
        fi
    fi
    
    # 生成 Snell 配置 (监听本地)
    cat > "$CFG/$snell_conf" << EOF
[snell-server]
listen = 127.0.0.1:$snell_backend_port
psk = $psk
ipv6 = false
obfs = off
EOF
    
    # 保存到独立的 info 文件
    cat > "$CFG/${protocol_name}.info" << EOF
protocol=$protocol_name
psk=$psk
port=$port
sni=$sni
stls_password=$stls_password
snell_backend_port=$snell_backend_port
version=$version
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "$protocol_name"
    echo "server" > "$CFG/role"
}

# SS2022 + ShadowTLS 服务端配置
gen_ss2022_shadowtls_server_config() {
    local password="$1" port="$2" method="${3:-2022-blake3-aes-256-gcm}" sni="${4:-www.microsoft.com}" stls_password="$5" custom_backend_port="${6:-}"
    mkdir -p "$CFG"
    
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # SS2022 后端端口 (内部监听) - 支持自定义或自动计算
    local ss_backend_port
    if [[ -n "$custom_backend_port" ]]; then
        ss_backend_port="$custom_backend_port"
    else
        ss_backend_port=$((port + 10000))
        if [[ $ss_backend_port -gt 65535 ]]; then
            ss_backend_port=$((port - 10000))
        fi
    fi
    
    # 生成后端 SS2022 配置 (使用 Xray)
    cat > "$CFG/ss2022-shadowtls-backend.json" << EOF
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
    
    # 保存到独立的 info 文件
    cat > "$CFG/ss2022-shadowtls.info" << EOF
protocol=ss2022-shadowtls
password=$password
port=$port
method=$method
sni=$sni
stls_password=$stls_password
ss_backend_port=$ss_backend_port
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "ss2022-shadowtls"
    echo "server" > "$CFG/role"
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
# 服务端辅助脚本生成
#═══════════════════════════════════════════════════════════════════════════════
create_server_scripts() {
    # Watchdog 脚本 - 服务端监控进程（带重启次数限制）
    cat > "$CFG/watchdog.sh" << 'EOFSCRIPT'
#!/bin/bash
CFG="/etc/vless-reality"
LOG_FILE="/var/log/vless-watchdog.log"
MAX_RESTARTS=5           # 冷却期内最大重启次数
COOLDOWN_PERIOD=300      # 冷却期（秒）
declare -A restart_counts
declare -A first_restart_time

log() { 
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    # 日志轮转：超过 2MB 时截断
    local size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
    if [[ $size -gt 2097152 ]]; then
        tail -n 500 "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
    fi
}

restart_service() {
    local svc="$1"
    local now=$(date +%s)
    local first_time=${first_restart_time[$svc]:-0}
    local count=${restart_counts[$svc]:-0}
    
    # 检查是否在冷却期内
    if [[ $((now - first_time)) -gt $COOLDOWN_PERIOD ]]; then
        # 冷却期已过，重置计数
        restart_counts[$svc]=1
        first_restart_time[$svc]=$now
    else
        # 仍在冷却期内
        ((count++))
        restart_counts[$svc]=$count
        
        if [[ $count -gt $MAX_RESTARTS ]]; then
            log "ERROR: $svc 在 ${COOLDOWN_PERIOD}s 内重启次数超过 $MAX_RESTARTS 次，暂停监控该服务"
            return 1
        fi
    fi
    
    log "INFO: 正在重启 $svc (第 ${restart_counts[$svc]} 次)"
    
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl restart "$svc" 2>&1; then
            log "OK: $svc 重启成功"
            return 0
        else
            log "ERROR: $svc 重启失败"
            return 1
        fi
    elif command -v rc-service >/dev/null 2>&1; then
        if rc-service "$svc" restart 2>&1; then
            log "OK: $svc 重启成功"
            return 0
        else
            log "ERROR: $svc 重启失败"
            return 1
        fi
    else
        log "ERROR: 无法找到服务管理命令"
        return 1
    fi
}

# 获取所有需要监控的服务 (支持多协议)
get_all_services() {
    local services=""
    
    if [[ -f "$CFG/installed_protocols" ]]; then
        local xray_protos="vless vless-xhttp vless-ws vmess-ws vless-vision trojan socks ss2022"
        local has_xray=false
        
        for proto in $xray_protos; do
            if grep -q "^$proto$" "$CFG/installed_protocols" 2>/dev/null; then
                has_xray=true
                break
            fi
        done
        
        [[ "$has_xray" == "true" ]] && services+="vless-reality:xray "
        
        grep -q "^hy2$" "$CFG/installed_protocols" 2>/dev/null && services+="vless-hy2:hysteria "
        grep -q "^tuic$" "$CFG/installed_protocols" 2>/dev/null && services+="vless-tuic:tuic-server "
        grep -q "^snell$" "$CFG/installed_protocols" 2>/dev/null && services+="vless-snell:snell-server "
        grep -q "^snell-v5$" "$CFG/installed_protocols" 2>/dev/null && services+="vless-snell-v5:snell-server-v5 "
        grep -q "^anytls$" "$CFG/installed_protocols" 2>/dev/null && services+="vless-anytls:anytls-server "
        grep -q "^snell-shadowtls$" "$CFG/installed_protocols" 2>/dev/null && services+="vless-snell-shadowtls:shadow-tls "
        grep -q "^snell-v5-shadowtls$" "$CFG/installed_protocols" 2>/dev/null && services+="vless-snell-v5-shadowtls:shadow-tls "
        grep -q "^ss2022-shadowtls$" "$CFG/installed_protocols" 2>/dev/null && services+="vless-ss2022-shadowtls:shadow-tls "
    fi
    
    echo "$services"
}

log "INFO: Watchdog 启动"

while true; do
    for svc_info in $(get_all_services); do
        IFS=':' read -r svc_name proc_name <<< "$svc_info"
        # 多种方式检测进程
        if ! pgrep -x "$proc_name" > /dev/null 2>&1 && ! pgrep -f "$proc_name" > /dev/null 2>&1; then
            log "CRITICAL: $proc_name 进程不存在，尝试重启 $svc_name..."
            restart_service "$svc_name"
            sleep 5
        fi
    done
    sleep 60
done
EOFSCRIPT

    # Hysteria2 端口跳跃规则脚本 (服务端)
    if grep -q "^hy2$" "$CFG/installed_protocols" 2>/dev/null; then
        cat > "$CFG/hy2-nat.sh" << 'EOFSCRIPT'
#!/bin/bash
CFG=/etc/vless-reality

[[ ! -f "$CFG/hy2.info" ]] && exit 0
source "$CFG/hy2.info" 2>/dev/null

hop_start="${hop_start:-20000}"
hop_end="${hop_end:-50000}"

if ! [[ "$hop_start" =~ ^[0-9]+$ && "$hop_end" =~ ^[0-9]+$ ]] || [[ "$hop_start" -ge "$hop_end" ]]; then
  exit 0
fi

iptables -t nat -D PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null
iptables -t nat -D OUTPUT -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null

[[ "${hop_enable:-0}" != "1" ]] && exit 0

iptables -t nat -C PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null \
  || iptables -t nat -A PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port

iptables -t nat -C OUTPUT -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null \
  || iptables -t nat -A OUTPUT -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port
EOFSCRIPT
    fi

    chmod +x "$CFG"/*.sh 2>/dev/null
}

#═══════════════════════════════════════════════════════════════════════════════
# 服务管理
#═══════════════════════════════════════════════════════════════════════════════
create_service() {
    # 支持传入协议参数，否则使用 get_protocol 获取
    local protocol="${1:-$(get_protocol)}"
    
    # 清除可能残留的变量
    local port="" password="" sni="" stls_password="" ss_backend_port=""
    
    # 根据协议确定启动命令 (服务端)
    local exec_cmd exec_name
    case "$protocol" in
        vless|vless-xhttp|vless-ws|vmess-ws|vless-vision|trojan|socks|ss2022)
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
        snell-shadowtls)
            if [[ ! -f "$CFG/snell-shadowtls.info" ]]; then
                _err "Snell+ShadowTLS 配置文件不存在"
                return 1
            fi
            source "$CFG/snell-shadowtls.info"
            exec_cmd="/usr/local/bin/shadow-tls --v3 server --listen 0.0.0.0:${port} --server 127.0.0.1:${snell_backend_port} --tls ${sni}:443 --password ${stls_password}"
            exec_name="shadow-tls"
            ;;
        snell-v5-shadowtls)
            if [[ ! -f "$CFG/snell-v5-shadowtls.info" ]]; then
                _err "Snell v5+ShadowTLS 配置文件不存在"
                return 1
            fi
            source "$CFG/snell-v5-shadowtls.info"
            exec_cmd="/usr/local/bin/shadow-tls --v3 server --listen 0.0.0.0:${port} --server 127.0.0.1:${snell_backend_port} --tls ${sni}:443 --password ${stls_password}"
            exec_name="shadow-tls"
            ;;
        ss2022-shadowtls)
            if [[ ! -f "$CFG/ss2022-shadowtls.info" ]]; then
                _err "SS2022+ShadowTLS 配置文件不存在"
                return 1
            fi
            source "$CFG/ss2022-shadowtls.info"
            exec_cmd="/usr/local/bin/shadow-tls --v3 server --listen 0.0.0.0:${port} --server 127.0.0.1:${ss_backend_port} --tls ${sni}:443 --password ${stls_password}"
            exec_name="shadow-tls"
            ;;
        tuic)
            exec_cmd="/usr/local/bin/tuic-server -c $CFG/tuic.json"
            exec_name="tuic-server"
            ;;
        anytls)
            if [[ ! -f "$CFG/anytls.info" ]]; then
                _err "AnyTLS 配置文件不存在"
                return 1
            fi
            source "$CFG/anytls.info"
            exec_cmd="/usr/local/bin/anytls-server -l 0.0.0.0:${port} -p ${password}"
            exec_name="anytls-server"
            ;;
    esac
    
    # 确定服务名
    local service_name
    if echo "$XRAY_PROTOCOLS" | grep -q "$protocol"; then
        service_name="vless-reality"
    else
        service_name="vless-${protocol}"
    fi
    
    if [[ "$DISTRO" == "alpine" ]]; then
        local openrc_cmd="${exec_cmd%% *}"
        local openrc_args=""
        [[ "$exec_cmd" == *" "* ]] && openrc_args="${exec_cmd#* }"

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
        
        # Snell+ShadowTLS 需要额外的后端 Snell 服务
        if [[ "$protocol" == "snell-shadowtls" ]]; then
            cat > /etc/init.d/vless-snell-shadowtls-backend << EOF
#!/sbin/openrc-run
name="Snell Backend for ShadowTLS"
command="/usr/local/bin/snell-server"
command_args="-c $CFG/snell-shadowtls.conf"
command_background="yes"
pidfile="/run/vless-snell-shadowtls-backend.pid"
depend() { need net; before vless-snell-shadowtls; }
EOF
            chmod +x /etc/init.d/vless-snell-shadowtls-backend
        fi
        
        # Snell v5+ShadowTLS 需要额外的后端 Snell v5 服务
        if [[ "$protocol" == "snell-v5-shadowtls" ]]; then
            cat > /etc/init.d/vless-snell-v5-shadowtls-backend << EOF
#!/sbin/openrc-run
name="Snell v5 Backend for ShadowTLS"
command="/usr/local/bin/snell-server-v5"
command_args="-c $CFG/snell-v5-shadowtls.conf"
command_background="yes"
pidfile="/run/vless-snell-v5-shadowtls-backend.pid"
depend() { need net; before vless-snell-v5-shadowtls; }
EOF
            chmod +x /etc/init.d/vless-snell-v5-shadowtls-backend
        fi
        
        # SS2022+ShadowTLS 需要额外的后端 SS2022 服务
        if [[ "$protocol" == "ss2022-shadowtls" ]]; then
            cat > /etc/init.d/vless-ss2022-shadowtls-backend << EOF
#!/sbin/openrc-run
name="SS2022 Backend for ShadowTLS"
command="/usr/local/bin/xray"
command_args="run -c $CFG/ss2022-shadowtls-backend.json"
command_background="yes"
pidfile="/run/vless-ss2022-shadowtls-backend.pid"
depend() { need net; before vless-ss2022-shadowtls; }
EOF
            chmod +x /etc/init.d/vless-ss2022-shadowtls-backend
        fi
        
        # Watchdog 服务
        cat > /etc/init.d/vless-watchdog << EOF
#!/sbin/openrc-run
name="Proxy Watchdog"
command="/bin/bash"
command_args="$CFG/watchdog.sh"
command_background="yes"
pidfile="/run/vless-watchdog.pid"
depend() { need ${service_name}; }
EOF
        chmod +x /etc/init.d/vless-watchdog
    else
        # Hysteria2 添加端口跳跃支持
        if [[ "$protocol" == "hy2" ]]; then
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
        
        # Snell+ShadowTLS 需要额外的后端 Snell 服务
        if [[ "$protocol" == "snell-shadowtls" ]]; then
            cat > /etc/systemd/system/vless-snell-shadowtls-backend.service << EOF
[Unit]
Description=Snell Backend for ShadowTLS
After=network.target
Before=vless-snell-shadowtls.service

[Service]
Type=simple
ExecStart=/usr/local/bin/snell-server -c $CFG/snell-shadowtls.conf
Restart=always
RestartSec=3
LimitNOFILE=51200
[Install]
WantedBy=multi-user.target
EOF
        fi
        
        # Snell v5+ShadowTLS 需要额外的后端 Snell v5 服务
        if [[ "$protocol" == "snell-v5-shadowtls" ]]; then
            cat > /etc/systemd/system/vless-snell-v5-shadowtls-backend.service << EOF
[Unit]
Description=Snell v5 Backend for ShadowTLS
After=network.target
Before=vless-snell-v5-shadowtls.service

[Service]
Type=simple
ExecStart=/usr/local/bin/snell-server-v5 -c $CFG/snell-v5-shadowtls.conf
Restart=always
RestartSec=3
LimitNOFILE=51200
[Install]
WantedBy=multi-user.target
EOF
        fi
        
        # SS2022+ShadowTLS 需要额外的后端 SS2022 服务
        if [[ "$protocol" == "ss2022-shadowtls" ]]; then
            cat > /etc/systemd/system/vless-ss2022-shadowtls-backend.service << EOF
[Unit]
Description=SS2022 Backend for ShadowTLS
After=network.target
Before=vless-ss2022-shadowtls.service

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -c $CFG/ss2022-shadowtls-backend.json
Restart=always
RestartSec=3
LimitNOFILE=51200
[Install]
WantedBy=multi-user.target
EOF
        fi
        
        # Watchdog 服务
        cat > /etc/systemd/system/vless-watchdog.service << EOF
[Unit]
Description=Proxy Watchdog
After=${service_name}.service
[Service]
Type=simple
ExecStart=$CFG/watchdog.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF
        
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
                # OpenRC 的 status 返回值可能不可靠，使用多种方式检测
                if rc-service "$name" status &>/dev/null; then
                    return 0
                fi
                
                # 回退检查1：通过 pidfile 验证进程是否存在
                local pidfile="/run/${name}.pid"
                if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile" 2>/dev/null)" 2>/dev/null; then
                    return 0
                fi
                
                # 回退检查2：直接检测进程名
                local proc_name=""
                case "$name" in
                    vless-reality) proc_name="xray" ;;
                    vless-hy2) proc_name="hysteria" ;;
                    vless-snell) proc_name="snell-server" ;;
                    vless-snell-v5) proc_name="snell-server-v5" ;;
                    vless-tuic) proc_name="tuic-server" ;;
                    vless-anytls) proc_name="anytls-server" ;;
                    vless-snell-shadowtls|vless-snell-v5-shadowtls|vless-ss2022-shadowtls) proc_name="shadow-tls" ;;
                    nginx) proc_name="nginx" ;;
                esac
                if [[ -n "$proc_name" ]] && pgrep -x "$proc_name" >/dev/null 2>&1; then
                    return 0
                fi
                
                return 1
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
    local failed_services=()
    rm -f "$CFG/paused"
    
    # 服务端：启动所有已注册的协议服务
    
    # 启动 Xray 服务（如果有 Xray 协议）
    local xray_protocols=$(get_xray_protocols)
    if [[ -n "$xray_protocols" ]]; then
        if svc status vless-reality >/dev/null 2>&1; then
            _info "更新 Xray 配置..."
            if ! generate_xray_config; then
                _err "Xray 配置生成失败"
                failed_services+=("vless-reality")
            else
                if ! svc restart vless-reality; then
                    _err "Xray 服务重启失败"
                    failed_services+=("vless-reality")
                else
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
            if ! generate_xray_config; then
                _err "Xray 配置生成失败"
                failed_services+=("vless-reality")
            else
                svc enable vless-reality
                if ! svc start vless-reality; then
                    _err "Xray 服务启动失败"
                    failed_services+=("vless-reality")
                else
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
    
    # 启动独立协议服务
    local independent_protocols=$(get_independent_protocols)
    local ind_proto
    for ind_proto in $independent_protocols; do
        local service_name="vless-${ind_proto}"
        
        # ShadowTLS 组合协议需要先启动/重启后端服务
        if [[ "$ind_proto" == "snell-shadowtls" ]]; then
            svc enable "vless-snell-shadowtls-backend"
            if svc status "vless-snell-shadowtls-backend" >/dev/null 2>&1; then
                svc restart "vless-snell-shadowtls-backend" || true
            else
                if ! svc start "vless-snell-shadowtls-backend"; then
                    _err "Snell+ShadowTLS 后端服务启动失败"
                    failed_services+=("vless-snell-shadowtls-backend")
                    continue
                fi
            fi
            sleep 1
        elif [[ "$ind_proto" == "snell-v5-shadowtls" ]]; then
            svc enable "vless-snell-v5-shadowtls-backend"
            if svc status "vless-snell-v5-shadowtls-backend" >/dev/null 2>&1; then
                svc restart "vless-snell-v5-shadowtls-backend" || true
            else
                if ! svc start "vless-snell-v5-shadowtls-backend"; then
                    _err "Snell v5+ShadowTLS 后端服务启动失败"
                    failed_services+=("vless-snell-v5-shadowtls-backend")
                    continue
                fi
            fi
            sleep 1
        elif [[ "$ind_proto" == "ss2022-shadowtls" ]]; then
            svc enable "vless-ss2022-shadowtls-backend"
            if svc status "vless-ss2022-shadowtls-backend" >/dev/null 2>&1; then
                svc restart "vless-ss2022-shadowtls-backend" || true
            else
                if ! svc start "vless-ss2022-shadowtls-backend"; then
                    _err "SS2022+ShadowTLS 后端服务启动失败"
                    failed_services+=("vless-ss2022-shadowtls-backend")
                    continue
                fi
            fi
            sleep 1
        fi
        
        svc enable "$service_name"
        
        if svc status "$service_name" >/dev/null 2>&1; then
            # 服务已在运行，需要重启以加载新配置
            _info "重启 $ind_proto 服务以加载新配置..."
            if ! svc restart "$service_name"; then
                _err "$ind_proto 服务重启失败"
                failed_services+=("$service_name")
            else
                sleep 1
                _ok "$ind_proto 服务已重启"
            fi
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
    
    # 启动 Watchdog
    svc enable vless-watchdog 2>/dev/null
    svc start vless-watchdog 2>/dev/null
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        _warn "以下服务启动失败: ${failed_services[*]}"
        return 1
    fi
    
    return 0
}

stop_services() {
    local stopped_services=()
    
    is_service_active() {
        local svc_name="$1"
        if [[ "$DISTRO" == "alpine" ]]; then
            rc-service "$svc_name" status &>/dev/null
        else
            systemctl is-active --quiet "$svc_name" 2>/dev/null
        fi
    }
    
    # 停止 Watchdog
    if is_service_active vless-watchdog; then
        svc stop vless-watchdog 2>/dev/null && stopped_services+=("vless-watchdog")
    fi
    
    # 停止 Xray 服务
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
    
    # 停止 ShadowTLS 组合协议的后端服务
    for backend_svc in vless-snell-shadowtls-backend vless-snell-v5-shadowtls-backend vless-ss2022-shadowtls-backend; do
        if is_service_active "$backend_svc"; then
            svc stop "$backend_svc" 2>/dev/null && stopped_services+=("$backend_svc")
        fi
    done
    
    # 清理 Hysteria2 端口跳跃 NAT 规则
    cleanup_hy2_nat_rules
    
    if [[ ${#stopped_services[@]} -gt 0 ]]; then
        echo "  ▸ 已停止服务: ${stopped_services[*]}"
    else
        echo "  ▸ 没有运行中的服务需要停止"
    fi
}

# 清理 Hysteria2 端口跳跃 NAT 规则
cleanup_hy2_nat_rules() {
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
    local system_script="/usr/local/bin/vless-server.sh"
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
            local raw_url="https://raw.githubusercontent.com/Chil30/vless-all-in-one/main/vless-server.sh"
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
    rm -f /usr/local/bin/vless /usr/local/bin/vless-server.sh /usr/bin/vless 2>/dev/null
    _ok "快捷命令已移除"
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
    
    # 获取地区代码（只获取一次，用于所有显示）
    local country_code=$(get_ip_country "$ipv4")
    [[ -z "$country_code" ]] && country_code=$(get_ip_country "$ipv6")
    
    # 确定用于配置显示的 IP 地址：优先 IPv4，纯 IPv6 环境使用 IPv6（带方括号）
    local config_ip="$ipv4"
    [[ -z "$config_ip" ]] && config_ip="[$ipv6]"
    
    case "$protocol" in
        vless)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  公钥: ${G}$public_key${NC}"
            echo -e "  SNI: ${G}$sni${NC}  ShortID: ${G}$short_id${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-Vless-Reality = VLESS, ${config_ip}, ${display_port}, \"${uuid}\", transport=tcp, flow=xtls-rprx-vision, public-key=\"${public_key}\", short-id=${short_id}, udp=true, over-tls=true, sni=${sni}${NC}"
            ;;
        vless-xhttp)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  公钥: ${G}$public_key${NC}"
            echo -e "  SNI: ${G}$sni${NC}  ShortID: ${G}$short_id${NC}"
            echo -e "  Path: ${G}$path${NC}"
            echo ""
            echo -e "  ${D}注: Loon/Surge 暂不支持 XHTTP 传输，请使用分享链接导入 Shadowrocket${NC}"
            ;;
        vless-vision)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            [[ -n "$path" ]] && echo -e "  Path/ServiceName: ${G}$path${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-Vless-Vision = VLESS, ${config_ip}, ${display_port}, \"${uuid}\", transport=tcp, flow=xtls-rprx-vision, udp=true, over-tls=true, sni=${sni}, skip-cert-verify=true${NC}"
            ;;
        vless-ws)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            [[ -n "$path" ]] && echo -e "  Path/ServiceName: ${G}$path${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-Vless-WS = VLESS, ${config_ip}, ${display_port}, \"${uuid}\", transport=ws, path=${path}, host=${sni}, udp=true, over-tls=true, sni=${sni}, skip-cert-verify=true${NC}"
            ;;
        vmess-ws)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            [[ -n "$path" ]] && echo -e "  Path: ${G}$path${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-VMess-WS = vmess, ${config_ip}, ${display_port}, ${uuid}, tls=true, ws=true, ws-path=${path}, sni=${sni}, skip-cert-verify=true${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-VMess-WS = VMess, ${config_ip}, ${display_port}, aes-128-gcm, \"${uuid}\", transport=ws, path=${path}, host=${sni}, udp=true, over-tls=true, sni=${sni}, skip-cert-verify=true${NC}"
            ;;
        ss2022)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  加密: ${G}$method${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-SS2022 = ss, ${config_ip}, ${display_port}, encrypt-method=${method}, password=${password}${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-SS2022 = Shadowsocks, ${config_ip}, ${display_port}, ${method}, \"${password}\", udp=true${NC}"
            ;;
        hy2)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            if [[ "$hop_enable" == "1" ]]; then
                echo -e "  端口跳跃: ${G}${hop_start}-${hop_end}${NC}"
            fi
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-Hysteria2 = hysteria2, ${config_ip}, ${display_port}, password=${password}, sni=${sni}, skip-cert-verify=true${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-Hysteria2 = Hysteria2, ${config_ip}, ${display_port}, \"${password}\", udp=true, sni=${sni}, skip-cert-verify=true${NC}"
            ;;
        trojan)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-Trojan = trojan, ${config_ip}, ${display_port}, password=${password}, sni=${sni}, skip-cert-verify=true${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-Trojan = trojan, ${config_ip}, ${display_port}, \"${password}\", udp=true, over-tls=true, sni=${sni}${NC}"
            ;;
        anytls)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-AnyTLS = anytls, ${config_ip}, ${display_port}, password=${password}, sni=${sni}, skip-cert-verify=true${NC}"
            ;;
        snell-shadowtls)
            echo -e "  PSK: ${G}$psk${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo -e "  版本: ${G}v${version:-4}${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-Snell-ShadowTLS = snell, ${config_ip}, ${display_port}, psk=${psk}, version=${version:-4}, reuse=true, tfo=true, shadow-tls-password=${stls_password}, shadow-tls-sni=${sni}, shadow-tls-version=3${NC}"
            ;;
        snell-v5-shadowtls)
            echo -e "  PSK: ${G}$psk${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo -e "  版本: ${G}v${version:-5}${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-Snell5-ShadowTLS = snell, ${config_ip}, ${display_port}, psk=${psk}, version=${version:-5}, reuse=true, tfo=true, shadow-tls-password=${stls_password}, shadow-tls-sni=${sni}, shadow-tls-version=3${NC}"
            ;;
        ss2022-shadowtls)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  加密: ${G}$method${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-SS2022-ShadowTLS = ss, ${config_ip}, ${display_port}, encrypt-method=${method}, password=${password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${sni}, shadow-tls-version=3${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-SS2022-ShadowTLS = Shadowsocks, ${config_ip}, ${display_port}, ${method}, \"${password}\", udp=true, shadow-tls-password=${stls_password}, shadow-tls-sni=${sni}, shadow-tls-version=3${NC}"
            ;;
        snell|snell-v5)
            echo -e "  PSK: ${G}$psk${NC}"
            echo -e "  版本: ${G}v$version${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置 (Snell 为 Surge 专属协议):${NC}"
            echo -e "  ${C}${country_code}-Snell = snell, ${config_ip}, ${display_port}, psk=${psk}, version=${version}, reuse=true, tfo=true${NC}"
            ;;
        tuic)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-TUIC = tuic-v5, ${config_ip}, ${display_port}, password=${password}, uuid=${uuid}, sni=${sni}, skip-cert-verify=true, alpn=h3${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-TUIC = TUIC, ${config_ip}, ${display_port}, \"${password}\", \"${uuid}\", udp=true, sni=${sni}, skip-cert-verify=true, alpn=h3${NC}"
            ;;
        socks)
            echo -e "  用户名: ${G}$username${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-SOCKS5 = socks5, ${config_ip}, ${display_port}, ${username}, ${password}${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-SOCKS5 = socks5, ${config_ip}, ${display_port}, ${username}, \"${password}\", udp=true${NC}"
            ;;
    esac
    
    _line
    
    # 获取地区代码（只获取一次，用于所有链接）
    local country_code=$(get_ip_country "$ipv4")
    [[ -z "$country_code" ]] && country_code=$(get_ip_country "$ipv6")
    
    # 确定使用的 IP 地址：优先 IPv4，纯 IPv6 环境使用 IPv6
    local ip_addr=""
    if [[ -n "$ipv4" ]]; then
        ip_addr="$ipv4"
    elif [[ -n "$ipv6" ]]; then
        ip_addr="[$ipv6]"  # IPv6 需要用方括号包裹
    fi
    
    # 显示分享链接和二维码
    if [[ -n "$ip_addr" ]]; then
        local link_port="$display_port"
        
        local link join_code
        case "$protocol" in
            vless)
                link=$(gen_vless_link "$ip_addr" "$link_port" "$uuid" "$public_key" "$short_id" "$sni" "$country_code")
                join_code=$(echo "REALITY|${ip_addr}|${link_port}|${uuid}|${public_key}|${short_id}|${sni}" | base64 -w 0)
                ;;
            vless-xhttp)
                link=$(gen_vless_xhttp_link "$ip_addr" "$link_port" "$uuid" "$public_key" "$short_id" "$sni" "$path" "$country_code")
                join_code=$(echo "REALITY-XHTTP|${ip_addr}|${link_port}|${uuid}|${public_key}|${short_id}|${sni}|${path}" | base64 -w 0)
                ;;
            vless-vision)
                link=$(gen_vless_vision_link "$ip_addr" "$link_port" "$uuid" "$sni" "$country_code")
                join_code=$(echo "VLESS-VISION|${ip_addr}|${link_port}|${uuid}|${sni}" | base64 -w 0)
                ;;
            vless-ws)
                link=$(gen_vless_ws_link "$ip_addr" "$link_port" "$uuid" "$sni" "$path" "$country_code")
                join_code=$(echo "VLESS-WS|${ip_addr}|${link_port}|${uuid}|${sni}|${path}" | base64 -w 0)
                ;;
            vmess-ws)
                link=$(gen_vmess_ws_link "$ip_addr" "$link_port" "$uuid" "$sni" "$path" "$country_code")
                join_code=$(echo "VMESS-WS|${ip_addr}|${link_port}|${uuid}|${sni}|${path}" | base64 -w 0)
                ;;
            ss2022)
                link=$(gen_ss2022_link "$ip_addr" "$link_port" "$method" "$password" "$country_code")
                join_code=$(echo "SS2022|${ip_addr}|${link_port}|${method}|${password}" | base64 -w 0)
                ;;
            hy2)
                link=$(gen_hy2_link "$ip_addr" "$link_port" "$password" "$sni" "$country_code")
                join_code=$(echo "HY2|${ip_addr}|${link_port}|${password}|${sni}" | base64 -w 0)
                ;;
            trojan)
                link=$(gen_trojan_link "$ip_addr" "$link_port" "$password" "$sni" "$country_code")
                join_code=$(echo "TROJAN|${ip_addr}|${link_port}|${password}|${sni}" | base64 -w 0)
                ;;
            snell)
                link=$(gen_snell_link "$ip_addr" "$link_port" "$psk" "$version" "$country_code")
                join_code=$(echo "SNELL|${ip_addr}|${link_port}|${psk}|${version}" | base64 -w 0)
                ;;
            snell-v5)
                link=$(gen_snell_v5_link "$ip_addr" "$link_port" "$psk" "$version" "$country_code")
                join_code=$(echo "SNELL-V5|${ip_addr}|${link_port}|${psk}|${version}" | base64 -w 0)
                ;;
            snell-shadowtls|snell-v5-shadowtls)
                local stls_ver="${version:-4}"
                [[ "$protocol" == "snell-v5-shadowtls" ]] && stls_ver="5"
                join_code=$(echo "SNELL-SHADOWTLS|${ip_addr}|${link_port}|${psk}|${stls_ver}|${stls_password}|${sni}" | base64 -w 0)
                link=""
                ;;
            ss2022-shadowtls)
                join_code=$(echo "SS2022-SHADOWTLS|${ip_addr}|${link_port}|${method}|${password}|${stls_password}|${sni}" | base64 -w 0)
                link=""
                ;;
            tuic)
                link=$(gen_tuic_link "$ip_addr" "$link_port" "$uuid" "$password" "$sni" "$country_code")
                join_code=$(echo "TUIC|${ip_addr}|${link_port}|${uuid}|${password}|${sni}" | base64 -w 0)
                ;;
            anytls)
                link=$(gen_anytls_link "$ip_addr" "$link_port" "$password" "$sni" "$country_code")
                join_code=$(echo "ANYTLS|${ip_addr}|${link_port}|${password}|${sni}" | base64 -w 0)
                ;;
            socks)
                link=$(gen_socks_link "$ip_addr" "$link_port" "$username" "$password" "$country_code")
                join_code=$(echo "SOCKS|${ip_addr}|${link_port}|${username}|${password}" | base64 -w 0)
                ;;
        esac
        
        # 显示 JOIN 码 (根据开关控制)
        if [[ "$SHOW_JOIN_CODE" == "on" ]]; then
            echo -e "  ${C}JOIN码:${NC}"
            echo -e "  ${G}$join_code${NC}"
            echo ""
        fi
        
        # ShadowTLS 组合协议只显示 JOIN 码
        if [[ "$protocol" != "snell-shadowtls" && "$protocol" != "snell-v5-shadowtls" && "$protocol" != "ss2022-shadowtls" ]]; then
            if [[ "$protocol" == "socks" ]]; then
                local socks_link="socks5://${username}:${password}@${ip_addr}:${link_port}#SOCKS5-${ip_addr}"
                echo -e "  ${C}分享链接:${NC}"
                echo -e "  ${G}$socks_link${NC}"
                echo ""
                echo -e "  ${C}二维码:${NC}"
                echo -e "  ${G}$(gen_qr "$socks_link")${NC}"
            else
                echo -e "  ${C}分享链接:${NC}"
                echo -e "  ${G}$link${NC}"
                echo ""
                echo -e "  ${C}二维码:${NC}"
                echo -e "  ${G}$(gen_qr "$link")${NC}"
            fi
        elif [[ "$SHOW_JOIN_CODE" != "on" ]]; then
            # ShadowTLS 协议且 JOIN 码关闭时，提示用户
            echo -e "  ${Y}提示: ShadowTLS 协议需要 JOIN 码才能配置客户端${NC}"
            echo -e "  ${D}如需显示 JOIN 码，请修改脚本头部 SHOW_JOIN_CODE=\"on\"${NC}"
            echo ""
        fi
    fi
    
    # IPv6 提示（仅双栈时显示，纯 IPv6 已经使用 IPv6 地址了）
    if [[ -n "$ipv4" && -n "$ipv6" ]]; then
        echo ""
        echo -e "  ${D}提示: 服务器支持 IPv6 ($ipv6)，如需使用请自行替换地址${NC}"
    fi
    
    # 自签名证书提示（VMess-WS、VLESS-WS、VLESS-Vision、Trojan、Hysteria2 使用自签名证书时）
    if [[ "$protocol" =~ ^(vmess-ws|vless-ws|vless-vision|trojan|hy2)$ ]]; then
        # 检查是否是自签名证书（没有真实域名）
        local is_self_signed=true
        if [[ -f "$CFG/cert_domain" ]]; then
            local cert_domain=$(cat "$CFG/cert_domain")
            # 检查证书是否由 CA 签发
            if [[ -f "$CFG/certs/server.crt" ]]; then
                local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
                if [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"ZeroSSL"* ]]; then
                    is_self_signed=false
                fi
            fi
        fi
        if [[ "$is_self_signed" == "true" ]]; then
            echo ""
            echo -e "  ${Y}⚠ 使用自签名证书，客户端需开启「跳过证书验证」或「允许不安全连接」${NC}"
        fi
    fi
    
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
# 信息显示与卸载
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
    echo -e "  • 软件包: anytls-server, shadow-tls"
    echo -e "  • ${G}域名证书: 下次安装将自动复用，无需重新申请${NC}"
    echo ""
    echo -e "  ${C}如需完全删除软件包，请执行:${NC}"
    echo -e "  ${G}rm -f /usr/local/bin/{xray,hysteria,snell-server*,tuic-*,anytls-*,shadow-tls}${NC}"
    echo ""
    echo -e "  ${C}如需删除证书，请执行:${NC}"
    echo -e "  ${G}rm -rf /etc/vless-reality/certs /etc/vless-reality/cert_domain${NC}"
}

#═══════════════════════════════════════════════════════════════════════════════
# 协议安装流程
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
    _item "4" "VMess + WS ${D}(回落分流/免流)${NC}"
    _item "5" "VLESS-XTLS-Vision ${D}(TLS主协议, 支持回落)${NC}"
    _item "6" "SOCKS5 ${D}(经典代理)${NC}"
    _item "7" "Hysteria2 ${D}(UDP加速, 高速)${NC}"
    _item "8" "Trojan ${D}(TLS主协议, 支持回落)${NC}"
    _item "9" "TUIC v5 ${D}(QUIC协议)${NC}"
    _item "10" "AnyTLS ${D}(多协议TLS代理)${NC}"
    _line
    echo -e "  ${W}Surge 专属${NC} ${D}(支持 ShadowTLS 插件)${NC}"
    _line
    _item "11" "Snell v4"
    _item "12" "Snell v5"
    _line
    echo -e "  ${W}Shadowsocks${NC} ${D}(支持 ShadowTLS 插件)${NC}"
    _line
    _item "13" "Shadowsocks 2022"
    echo ""
    echo -e "  ${D}提示: 先装主协议(5/8)占用443，再装WS(3/4)可共用端口${NC}"
    echo ""
    
    while true; do
        read -rp "  选择协议 [1-13]: " choice
        case $choice in
            1) SELECTED_PROTOCOL="vless"; break ;;
            2) SELECTED_PROTOCOL="vless-xhttp"; break ;;
            3) SELECTED_PROTOCOL="vless-ws"; break ;;
            4) SELECTED_PROTOCOL="vmess-ws"; break ;;
            5) SELECTED_PROTOCOL="vless-vision"; break ;;
            6) SELECTED_PROTOCOL="socks"; break ;;
            7) SELECTED_PROTOCOL="hy2"; break ;;
            8) SELECTED_PROTOCOL="trojan"; break ;;
            9) SELECTED_PROTOCOL="tuic"; break ;;
            10) SELECTED_PROTOCOL="anytls"; break ;;
            11) SELECTED_PROTOCOL="snell"; break ;;
            12) SELECTED_PROTOCOL="snell-v5"; break ;;
            13) SELECTED_PROTOCOL="ss2022"; break ;;
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

    # 检测并安装基础依赖
    _info "检测基础依赖..."
    check_dependencies || { _err "依赖检测失败"; return 1; }

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
        vless|vless-xhttp|vless-ws|vless-vision|ss2022|trojan)
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
        snell-shadowtls)
            install_snell || return
            install_shadowtls || return
            ;;
        snell-v5-shadowtls)
            install_snell_v5 || return
            install_shadowtls || return
            ;;
        ss2022-shadowtls)
            install_xray || return
            install_shadowtls || return
            ;;
        tuic)
            install_tuic "server" || return
            ;;
        anytls)
            install_anytls || return
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
            elif [[ -f "$CFG/certs/server.crt" ]]; then
                # 从证书中提取域名
                cert_domain=$(openssl x509 -in "$CFG/certs/server.crt" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')
            fi
            
            local final_sni=""
            local use_new_cert=false
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
                # 独立安装
                # 检查是否有真实证书（CA 签发的）
                local is_real_cert=false
                if [[ -f "$CFG/certs/server.crt" ]]; then
                    local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
                    if [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"R11"* ]] || [[ "$issuer" == *"E1"* ]] || [[ "$issuer" == *"ZeroSSL"* ]] || [[ "$issuer" == *"Buypass"* ]]; then
                        is_real_cert=true
                    fi
                fi
                
                if [[ "$is_real_cert" == "true" && -n "$cert_domain" ]]; then
                    # 有真实证书，强制使用证书域名
                    final_sni="$cert_domain"
                    echo ""
                    _ok "检测到真实证书 (域名: $cert_domain)"
                    _ok "SNI 将使用证书域名: $cert_domain"
                    use_new_cert=false
                else
                    # 没有证书或只有自签名证书，询问 SNI 并生成对应证书
                    use_new_cert=true
                    final_sni=$(ask_sni_config "$(gen_sni)" "")
                fi
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
            gen_vmess_ws_server_config "$uuid" "$port" "$final_sni" "$path" "$use_new_cert"
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
            echo -e "  ${W}ShadowTLS 插件${NC}"
            _line
            echo -e "  ${D}在高阻断环境下，您可能需要 ShadowTLS 伪装。${NC}"
            echo ""
            read -rp "  是否启用 ShadowTLS (v3) 插件? [y/N]: " enable_stls
            
            if [[ "$enable_stls" =~ ^[yY]$ ]]; then
                # 安装 ShadowTLS
                _info "安装 ShadowTLS..."
                install_shadowtls || { _err "ShadowTLS 安装失败"; return 1; }
                
                # 启用 ShadowTLS 模式
                local stls_password=$(gen_password)
                local default_sni=$(gen_sni)
                
                echo ""
                read -rp "  ShadowTLS 握手域名 [$default_sni]: " final_sni
                final_sni="${final_sni:-$default_sni}"
                
                # ShadowTLS 监听端口（对外暴露）
                echo ""
                echo -e "  ${D}ShadowTLS 监听端口 (对外暴露，建议 443)${NC}"
                local stls_port=$(ask_port "ss2022-shadowtls")
                
                # SS2022 内部端口（自动随机生成）
                local internal_port=$(gen_port)
                
                echo ""
                _line
                echo -e "  ${C}SS2022 + ShadowTLS 配置${NC}"
                _line
                echo -e "  对外端口: ${G}$stls_port${NC} (ShadowTLS)"
                echo -e "  内部端口: ${G}$internal_port${NC} (SS2022, 自动生成)"
                echo -e "  加密: ${G}$method${NC}"
                echo -e "  SNI: ${G}$final_sni${NC}"
                _line
                echo ""
                read -rp "  确认安装? [Y/n]: " confirm
                [[ "$confirm" =~ ^[nN]$ ]] && return
                
                # 切换协议为 ss2022-shadowtls
                protocol="ss2022-shadowtls"
                SELECTED_PROTOCOL="ss2022-shadowtls"
                
                _info "生成配置..."
                gen_ss2022_shadowtls_server_config "$password" "$stls_port" "$method" "$final_sni" "$stls_password" "$internal_port"
            else
                # 普通 SS2022 模式
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
            fi
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
            echo -e "  ${W}ShadowTLS 插件${NC}"
            _line
            echo -e "  ${D}Surge 用户通常建议直接使用 Snell。${NC}"
            echo -e "  ${D}但在高阻断环境下，您可能需要 ShadowTLS 伪装。${NC}"
            echo ""
            read -rp "  是否启用 ShadowTLS (v3) 插件? [y/N]: " enable_stls
            
            if [[ "$enable_stls" =~ ^[yY]$ ]]; then
                # 安装 ShadowTLS
                _info "安装 ShadowTLS..."
                install_shadowtls || { _err "ShadowTLS 安装失败"; return 1; }
                
                # 启用 ShadowTLS 模式
                local stls_password=$(gen_password)
                local default_sni=$(gen_sni)
                
                echo ""
                read -rp "  ShadowTLS 握手域名 [$default_sni]: " final_sni
                final_sni="${final_sni:-$default_sni}"
                
                # ShadowTLS 监听端口（对外暴露）
                echo ""
                echo -e "  ${D}ShadowTLS 监听端口 (对外暴露，建议 443)${NC}"
                local stls_port=$(ask_port "snell-shadowtls")
                
                # Snell 内部端口（自动随机生成）
                local internal_port=$(gen_port)
                
                echo ""
                _line
                echo -e "  ${C}Snell v4 + ShadowTLS 配置${NC}"
                _line
                echo -e "  对外端口: ${G}$stls_port${NC} (ShadowTLS)"
                echo -e "  内部端口: ${G}$internal_port${NC} (Snell, 自动生成)"
                echo -e "  PSK: ${G}$psk${NC}"
                echo -e "  SNI: ${G}$final_sni${NC}"
                _line
                echo ""
                read -rp "  确认安装? [Y/n]: " confirm
                [[ "$confirm" =~ ^[nN]$ ]] && return
                
                # 切换协议为 snell-shadowtls
                protocol="snell-shadowtls"
                SELECTED_PROTOCOL="snell-shadowtls"
                
                _info "生成配置..."
                gen_snell_shadowtls_server_config "$psk" "$stls_port" "$final_sni" "$stls_password" "4" "$internal_port"
            else
                # 普通 Snell 模式
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
            fi
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
        snell-v5)
            local psk=$(gen_password) version="5"
            
            echo ""
            _line
            echo -e "  ${W}ShadowTLS 插件${NC}"
            _line
            echo -e "  ${D}Surge 用户通常建议直接使用 Snell。${NC}"
            echo -e "  ${D}但在高阻断环境下，您可能需要 ShadowTLS 伪装。${NC}"
            echo ""
            read -rp "  是否启用 ShadowTLS (v3) 插件? [y/N]: " enable_stls
            
            if [[ "$enable_stls" =~ ^[yY]$ ]]; then
                # 安装 ShadowTLS
                _info "安装 ShadowTLS..."
                install_shadowtls || { _err "ShadowTLS 安装失败"; return 1; }
                
                # 启用 ShadowTLS 模式
                local stls_password=$(gen_password)
                local default_sni=$(gen_sni)
                
                echo ""
                read -rp "  ShadowTLS 握手域名 [$default_sni]: " final_sni
                final_sni="${final_sni:-$default_sni}"
                
                # ShadowTLS 监听端口（对外暴露）
                echo ""
                echo -e "  ${D}ShadowTLS 监听端口 (对外暴露，建议 443)${NC}"
                local stls_port=$(ask_port "snell-v5-shadowtls")
                
                # Snell 内部端口（自动随机生成）
                local internal_port=$(gen_port)
                
                echo ""
                _line
                echo -e "  ${C}Snell v5 + ShadowTLS 配置${NC}"
                _line
                echo -e "  对外端口: ${G}$stls_port${NC} (ShadowTLS)"
                echo -e "  内部端口: ${G}$internal_port${NC} (Snell, 自动生成)"
                echo -e "  PSK: ${G}$psk${NC}"
                echo -e "  SNI: ${G}$final_sni${NC}"
                _line
                echo ""
                read -rp "  确认安装? [Y/n]: " confirm
                [[ "$confirm" =~ ^[nN]$ ]] && return
                
                # 切换协议为 snell-v5-shadowtls
                protocol="snell-v5-shadowtls"
                SELECTED_PROTOCOL="snell-v5-shadowtls"
                
                _info "生成配置..."
                gen_snell_shadowtls_server_config "$psk" "$stls_port" "$final_sni" "$stls_password" "5" "$internal_port"
            else
                # 普通 Snell v5 模式
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
            fi
            ;;
    esac
    
    _info "创建服务..."
    create_server_scripts  # 生成服务端辅助脚本（watchdog 和 hy2-nat）
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


show_status() {
    local installed=$(get_installed_protocols)
    if [[ -n "$installed" ]]; then
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
        
        # 显示协议概要
        if [[ $protocol_count -eq 1 ]]; then
            local port=""
            source "$CFG/${installed}.info" 2>/dev/null
            echo -e "  协议: ${C}$(get_protocol_name $installed)${NC}"
            echo -e "  端口: ${C}$port${NC}"
        else
            echo -e "  协议: ${C}多协议 (${protocol_count}个)${NC}"
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
    else
        echo -e "  状态: ${D}○ 未安装${NC}"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 订阅与外部节点管理
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

EXTERNAL_LINKS_FILE="$CFG/external_links.txt"
EXTERNAL_SUBS_FILE="$CFG/external_subs.txt"
EXTERNAL_CACHE_DIR="$CFG/external_nodes_cache"

# 解析 vless:// 链接
parse_vless_link() {
    local link="$1"
    # vless://uuid@server:port?params#name
    local content="${link#vless://}"
    local name="${content##*#}"
    name=$(printf '%b' "${name//%/\\x}")  # URL 解码
    content="${content%%#*}"
    
    local uuid="${content%%@*}"
    content="${content#*@}"
    
    local server_port="${content%%\?*}"
    local server="" port=""
    # 处理 IPv6 地址 [xxxx]:port
    if [[ "$server_port" == \[*\]:* ]]; then
        server="${server_port%%]:*}]"
        port="${server_port##*]:}"
    else
        server="${server_port%:*}"
        port="${server_port##*:}"
    fi
    
    local params="${content#*\?}"
    
    # 解析参数
    local security="" type="" sni="" pbk="" sid="" flow="" path="" host="" fp=""
    IFS='&' read -ra PARAMS <<< "$params"
    for param in "${PARAMS[@]}"; do
        local key="${param%%=*}"
        local value="${param#*=}"
        value=$(printf '%b' "${value//%/\\x}")  # URL 解码
        case "$key" in
            security) security="$value" ;;
            type) type="$value" ;;
            sni) sni="$value" ;;
            pbk) pbk="$value" ;;
            sid) sid="$value" ;;
            flow) flow="$value" ;;
            path) path="$value" ;;
            host) host="$value" ;;
            fp) fp="$value" ;;
        esac
    done
    
    # 输出 JSON 格式
    cat << EOF
{"type":"vless","name":"$name","server":"$server","port":"$port","uuid":"$uuid","security":"$security","transport":"$type","sni":"$sni","pbk":"$pbk","sid":"$sid","flow":"$flow","path":"$path","host":"$host","fp":"$fp"}
EOF
}

# 解析 vmess:// 链接
parse_vmess_link() {
    local link="$1"
    # vmess://base64(json)
    local content="${link#vmess://}"
    local json=$(echo "$content" | base64 -d 2>/dev/null)
    [[ -z "$json" ]] && return 1
    
    local name=$(echo "$json" | jq -r '.ps // .name // "VMess"')
    local server=$(echo "$json" | jq -r '.add // .server')
    local port=$(echo "$json" | jq -r '.port')
    local uuid=$(echo "$json" | jq -r '.id // .uuid')
    local aid=$(echo "$json" | jq -r '.aid // "0"')
    local net=$(echo "$json" | jq -r '.net // "tcp"')
    local type=$(echo "$json" | jq -r '.type // "none"')
    local host=$(echo "$json" | jq -r '.host // ""')
    local path=$(echo "$json" | jq -r '.path // ""')
    local tls=$(echo "$json" | jq -r '.tls // ""')
    local sni=$(echo "$json" | jq -r '.sni // ""')
    
    cat << EOF
{"type":"vmess","name":"$name","server":"$server","port":"$port","uuid":"$uuid","aid":"$aid","network":"$net","host":"$host","path":"$path","tls":"$tls","sni":"$sni"}
EOF
}

# 解析 trojan:// 链接
parse_trojan_link() {
    local link="$1"
    # trojan://password@server:port?params#name
    local content="${link#trojan://}"
    local name="${content##*#}"
    name=$(printf '%b' "${name//%/\\x}")  # URL 解码
    content="${content%%#*}"
    
    local password="${content%%@*}"
    content="${content#*@}"
    
    local server_port="${content%%\?*}"
    local server="" port=""
    # 处理 IPv6 地址 [xxxx]:port
    if [[ "$server_port" == \[*\]:* ]]; then
        server="${server_port%%]:*}]"
        port="${server_port##*]:}"
    else
        server="${server_port%:*}"
        port="${server_port##*:}"
    fi
    
    local params="${content#*\?}"
    local sni="" type="tcp"
    IFS='&' read -ra PARAMS <<< "$params"
    for param in "${PARAMS[@]}"; do
        local key="${param%%=*}"
        local value="${param#*=}"
        case "$key" in
            sni) sni="$value" ;;
            type) type="$value" ;;
        esac
    done
    
    cat << EOF
{"type":"trojan","name":"$name","server":"$server","port":"$port","password":"$password","sni":"$sni","transport":"$type"}
EOF
}

# 解析 ss:// 链接
parse_ss_link() {
    local link="$1"
    # ss://base64(method:password)@server:port#name
    # 或 ss://base64(method:password@server:port)#name
    local content="${link#ss://}"
    local name="${content##*#}"
    name=$(printf '%b' "${name//%/\\x}")
    content="${content%%#*}"
    
    local server="" port="" method="" password=""
    
    if [[ "$content" == *"@"* ]]; then
        # 格式: base64@server:port
        local encoded="${content%%@*}"
        local decoded=$(echo "$encoded" | base64 -d 2>/dev/null)
        if [[ "$decoded" == *":"* ]]; then
            method="${decoded%%:*}"
            password="${decoded#*:}"
        fi
        local server_port="${content#*@}"
        # 处理 IPv6 地址 [xxxx]:port
        if [[ "$server_port" == \[*\]:* ]]; then
            server="${server_port%%]:*}]"
            port="${server_port##*]:}"
        else
            server="${server_port%:*}"
            port="${server_port##*:}"
        fi
    else
        # 格式: base64(全部)
        local decoded=$(echo "$content" | base64 -d 2>/dev/null)
        if [[ "$decoded" == *"@"* ]]; then
            local method_pass="${decoded%%@*}"
            method="${method_pass%%:*}"
            password="${method_pass#*:}"
            local server_port="${decoded#*@}"
            # 处理 IPv6 地址 [xxxx]:port
            if [[ "$server_port" == \[*\]:* ]]; then
                server="${server_port%%]:*}]"
                port="${server_port##*]:}"
            else
                server="${server_port%:*}"
                port="${server_port##*:}"
            fi
        fi
    fi
    
    cat << EOF
{"type":"ss","name":"$name","server":"$server","port":"$port","method":"$method","password":"$password"}
EOF
}

# 解析 hysteria2:// 链接
parse_hy2_link() {
    local link="$1"
    # hysteria2://password@server:port?params#name
    local content="${link#hysteria2://}"
    content="${content#hy2://}"
    local name="${content##*#}"
    name=$(printf '%b' "${name//%/\\x}")  # URL 解码
    content="${content%%#*}"
    
    local password="${content%%@*}"
    content="${content#*@}"
    
    local server_port="${content%%\?*}"
    local server="" port=""
    # 处理 IPv6 地址 [xxxx]:port
    if [[ "$server_port" == \[*\]:* ]]; then
        server="${server_port%%]:*}]"
        port="${server_port##*]:}"
    else
        server="${server_port%:*}"
        port="${server_port##*:}"
    fi
    
    local params="${content#*\?}"
    local sni="" insecure="1"
    IFS='&' read -ra PARAMS <<< "$params"
    for param in "${PARAMS[@]}"; do
        local key="${param%%=*}"
        local value="${param#*=}"
        case "$key" in
            sni) sni="$value" ;;
            insecure) insecure="$value" ;;
        esac
    done
    
    cat << EOF
{"type":"hysteria2","name":"$name","server":"$server","port":"$port","password":"$password","sni":"$sni"}
EOF
}

# 解析 anytls:// 链接
parse_anytls_link() {
    local link="$1"
    # anytls://password@server:port?sni=xxx#name
    local content="${link#anytls://}"
    local name="${content##*#}"
    name=$(printf '%b' "${name//%/\\x}")
    content="${content%%#*}"
    
    local password="${content%%@*}"
    content="${content#*@}"
    
    local server_port="${content%%\?*}"
    local server="" port=""
    # 处理 IPv6 地址 [xxxx]:port
    if [[ "$server_port" == \[*\]:* ]]; then
        server="${server_port%%]:*}]"
        port="${server_port##*]:}"
    else
        server="${server_port%:*}"
        port="${server_port##*:}"
    fi
    
    local params="${content#*\?}"
    local sni=""
    IFS='&' read -ra PARAMS <<< "$params"
    for param in "${PARAMS[@]}"; do
        local key="${param%%=*}"
        local value="${param#*=}"
        case "$key" in
            sni) sni="$value" ;;
        esac
    done
    
    cat << EOF
{"type":"anytls","name":"$name","server":"$server","port":"$port","password":"$password","sni":"$sni"}
EOF
}

# 解析任意分享链接
parse_share_link() {
    local link="$1"
    case "$link" in
        vless://*) parse_vless_link "$link" ;;
        vmess://*) parse_vmess_link "$link" ;;
        trojan://*) parse_trojan_link "$link" ;;
        ss://*) parse_ss_link "$link" ;;
        hysteria2://*|hy2://*) parse_hy2_link "$link" ;;
        anytls://*) parse_anytls_link "$link" ;;
        *) echo "" ;;
    esac
}

# 从分享链接提取节点名称
get_link_name() {
    local link="$1"
    local name="${link##*#}"
    name=$(printf '%b' "${name//%/\\x}")
    [[ -z "$name" || "$name" == "$link" ]] && name="未命名节点"
    echo "$name"
}

# 拉取订阅内容
fetch_subscription() {
    local url="$1"
    local content=$(curl -sL --connect-timeout 10 --max-time 30 "$url" 2>/dev/null)
    [[ -z "$content" ]] && return 1
    
    # 尝试 Base64 解码
    local decoded=$(echo "$content" | base64 -d 2>/dev/null)
    if [[ -n "$decoded" && "$decoded" == *"://"* ]]; then
        echo "$decoded"
        return 0
    fi
    
    # 检查是否是 Clash YAML
    if [[ "$content" == *"proxies:"* ]]; then
        # 解析 Clash YAML 节点，转换为分享链接
        local links=""
        local in_proxies=false
        local current_proxy=""
        local name="" type="" server="" port="" uuid="" password="" method=""
        local network="" tls="" sni="" path="" host="" flow="" pbk="" sid=""
        
        while IFS= read -r line || [[ -n "$line" ]]; do
            # 检测 proxies 段
            if [[ "$line" =~ ^proxies: ]]; then
                in_proxies=true
                continue
            fi
            
            # 检测离开 proxies 段
            if [[ "$in_proxies" == "true" && "$line" =~ ^[a-z-]+: && ! "$line" =~ ^[[:space:]] ]]; then
                in_proxies=false
            fi
            
            [[ "$in_proxies" != "true" ]] && continue
            
            # 新节点开始
            if [[ "$line" =~ ^[[:space:]]*-[[:space:]]*name: ]]; then
                # 保存上一个节点
                if [[ -n "$name" && -n "$type" && -n "$server" && -n "$port" ]]; then
                    case "$type" in
                        vless)
                            local link="vless://${uuid}@${server}:${port}?encryption=none"
                            [[ -n "$flow" ]] && link+="&flow=$flow"
                            [[ "$tls" == "true" ]] && link+="&security=reality&type=${network:-tcp}&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid" || link+="&security=none&type=${network:-tcp}"
                            [[ "$network" == "ws" ]] && link+="&type=ws&path=$(urlencode "$path")&host=$host"
                            link+="#$(urlencode "$name")"
                            links+="$link"$'\n'
                            ;;
                        vmess)
                            local vmess_json="{\"v\":\"2\",\"ps\":\"$name\",\"add\":\"$server\",\"port\":\"$port\",\"id\":\"$uuid\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"${network:-tcp}\",\"type\":\"none\",\"host\":\"$host\",\"path\":\"$path\",\"tls\":\"$([[ "$tls" == "true" ]] && echo "tls" || echo "")\",\"sni\":\"$sni\"}"
                            links+="vmess://$(echo -n "$vmess_json" | base64 -w 0)"$'\n'
                            ;;
                        trojan)
                            links+="trojan://${password}@${server}:${port}?sni=$sni#$(urlencode "$name")"$'\n'
                            ;;
                        ss)
                            local ss_encoded=$(echo -n "${method}:${password}" | base64 -w 0)
                            links+="ss://${ss_encoded}@${server}:${port}#$(urlencode "$name")"$'\n'
                            ;;
                        hysteria2)
                            links+="hysteria2://${password}@${server}:${port}?sni=$sni#$(urlencode "$name")"$'\n'
                            ;;
                        tuic)
                            links+="tuic://${uuid}:${password}@${server}:${port}?sni=$sni#$(urlencode "$name")"$'\n'
                            ;;
                    esac
                fi
                # 重置变量
                name="" type="" server="" port="" uuid="" password="" method=""
                network="" tls="" sni="" path="" host="" flow="" pbk="" sid=""
                name=$(echo "$line" | sed 's/.*name:[[:space:]]*"\?\([^"]*\)"\?.*/\1/')
                continue
            fi
            
            # 解析属性
            [[ "$line" =~ ^[[:space:]]*type:[[:space:]]*(.*) ]] && type="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^[[:space:]]*server:[[:space:]]*(.*) ]] && server="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^[[:space:]]*port:[[:space:]]*(.*) ]] && port="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^[[:space:]]*uuid:[[:space:]]*(.*) ]] && uuid="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^[[:space:]]*password:[[:space:]]*(.*) ]] && password="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^[[:space:]]*cipher:[[:space:]]*(.*) ]] && method="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^[[:space:]]*network:[[:space:]]*(.*) ]] && network="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^[[:space:]]*tls:[[:space:]]*(.*) ]] && tls="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^[[:space:]]*sni:[[:space:]]*(.*) ]] && sni="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^[[:space:]]*servername:[[:space:]]*(.*) ]] && sni="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^[[:space:]]*flow:[[:space:]]*(.*) ]] && flow="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^[[:space:]]*path:[[:space:]]*(.*) ]] && path="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^[[:space:]]*Host:[[:space:]]*(.*) ]] && host="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^[[:space:]]*public-key:[[:space:]]*(.*) ]] && pbk="${BASH_REMATCH[1]}"
            [[ "$line" =~ ^[[:space:]]*short-id:[[:space:]]*(.*) ]] && sid="${BASH_REMATCH[1]}"
        done <<< "$content"
        
        # 处理最后一个节点
        if [[ -n "$name" && -n "$type" && -n "$server" && -n "$port" ]]; then
            case "$type" in
                vless)
                    local link="vless://${uuid}@${server}:${port}?encryption=none"
                    [[ -n "$flow" ]] && link+="&flow=$flow"
                    [[ "$tls" == "true" ]] && link+="&security=reality&type=${network:-tcp}&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid" || link+="&security=none&type=${network:-tcp}"
                    link+="#$(urlencode "$name")"
                    links+="$link"$'\n'
                    ;;
                vmess)
                    local vmess_json="{\"v\":\"2\",\"ps\":\"$name\",\"add\":\"$server\",\"port\":\"$port\",\"id\":\"$uuid\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"${network:-tcp}\",\"type\":\"none\",\"host\":\"$host\",\"path\":\"$path\",\"tls\":\"$([[ "$tls" == "true" ]] && echo "tls" || echo "")\",\"sni\":\"$sni\"}"
                    links+="vmess://$(echo -n "$vmess_json" | base64 -w 0)"$'\n'
                    ;;
                trojan)
                    links+="trojan://${password}@${server}:${port}?sni=$sni#$(urlencode "$name")"$'\n'
                    ;;
                ss)
                    local ss_encoded=$(echo -n "${method}:${password}" | base64 -w 0)
                    links+="ss://${ss_encoded}@${server}:${port}#$(urlencode "$name")"$'\n'
                    ;;
                hysteria2)
                    links+="hysteria2://${password}@${server}:${port}?sni=$sni#$(urlencode "$name")"$'\n'
                    ;;
                tuic)
                    links+="tuic://${uuid}:${password}@${server}:${port}?sni=$sni#$(urlencode "$name")"$'\n'
                    ;;
            esac
        fi
        
        [[ -n "$links" ]] && echo "$links" && return 0
        return 1
    fi
    
    # 原样返回（可能已经是链接列表）
    if [[ "$content" == *"://"* ]]; then
        echo "$content"
        return 0
    fi
    
    return 1
}

# 刷新所有订阅
refresh_external_subs() {
    [[ ! -f "$EXTERNAL_SUBS_FILE" ]] && return 0
    
    mkdir -p "$EXTERNAL_CACHE_DIR"
    local count=0
    local idx=0
    
    while IFS= read -r url || [[ -n "$url" ]]; do
        [[ -z "$url" || "$url" == \#* ]] && continue
        ((idx++))
        
        _info "拉取订阅 $idx: $url"
        local content=$(fetch_subscription "$url")
        
        if [[ -n "$content" ]]; then
            echo "$content" > "$EXTERNAL_CACHE_DIR/sub_$idx.txt"
            local node_count=$(echo "$content" | grep -c '://' || echo 0)
            _ok "获取 $node_count 个节点"
            ((count+=node_count))
        else
            _warn "拉取失败: $url"
        fi
    done < "$EXTERNAL_SUBS_FILE"
    
    _ok "共刷新 $count 个外部节点"
    
    # 自动更新订阅文件
    [[ -f "$CFG/sub.info" ]] && generate_sub_files
}

# 获取所有外部节点链接
get_all_external_links() {
    local links=""
    
    # 直接添加的分享链接
    if [[ -f "$EXTERNAL_LINKS_FILE" ]]; then
        while IFS= read -r link || [[ -n "$link" ]]; do
            [[ -z "$link" || "$link" == \#* ]] && continue
            links+="$link"$'\n'
        done < "$EXTERNAL_LINKS_FILE"
    fi
    
    # 订阅缓存的节点
    if [[ -d "$EXTERNAL_CACHE_DIR" ]]; then
        for cache_file in "$EXTERNAL_CACHE_DIR"/*.txt; do
            [[ ! -f "$cache_file" ]] && continue
            while IFS= read -r link || [[ -n "$link" ]]; do
                [[ -z "$link" || "$link" == \#* ]] && continue
                [[ "$link" != *"://"* ]] && continue
                links+="$link"$'\n'
            done < "$cache_file"
        done
    fi
    
    echo -n "$links"
}

# 将外部节点转换为 Clash 格式
external_link_to_clash() {
    local link="$1"
    local json=$(parse_share_link "$link")
    [[ -z "$json" ]] && return
    
    local type=$(echo "$json" | jq -r '.type')
    local name=$(echo "$json" | jq -r '.name')
    local server=$(echo "$json" | jq -r '.server')
    local port=$(echo "$json" | jq -r '.port')
    
    # 给外部节点名称加上服务器标识，避免与本地节点重复
    local server_suffix=$(get_ip_suffix "$server")
    [[ -n "$server_suffix" && "$name" != *"-${server_suffix}"* && "$name" != *"-${server_suffix}" ]] && name="${name}-${server_suffix}"
    
    case "$type" in
        vless)
            local uuid=$(echo "$json" | jq -r '.uuid')
            local security=$(echo "$json" | jq -r '.security')
            local transport=$(echo "$json" | jq -r '.transport')
            local sni=$(echo "$json" | jq -r '.sni')
            local pbk=$(echo "$json" | jq -r '.pbk')
            local sid=$(echo "$json" | jq -r '.sid')
            local flow=$(echo "$json" | jq -r '.flow')
            local path=$(echo "$json" | jq -r '.path')
            
            if [[ "$security" == "reality" ]]; then
                cat << EOF
  - name: "$name"
    type: vless
    server: "$server"
    port: $port
    uuid: $uuid
    network: ${transport:-tcp}
    tls: true
    udp: true
    flow: $flow
    servername: $sni
    reality-opts:
      public-key: $pbk
      short-id: $sid
    client-fingerprint: chrome
EOF
            elif [[ "$transport" == "ws" ]]; then
                cat << EOF
  - name: "$name"
    type: vless
    server: "$server"
    port: $port
    uuid: $uuid
    network: ws
    tls: true
    udp: true
    skip-cert-verify: true
    servername: $sni
    ws-opts:
      path: $path
      headers:
        Host: $sni
EOF
            else
                cat << EOF
  - name: "$name"
    type: vless
    server: "$server"
    port: $port
    uuid: $uuid
    network: tcp
    tls: true
    udp: true
    skip-cert-verify: true
    servername: $sni
EOF
            fi
            ;;
        vmess)
            local uuid=$(echo "$json" | jq -r '.uuid')
            local network=$(echo "$json" | jq -r '.network')
            local tls=$(echo "$json" | jq -r '.tls')
            local sni=$(echo "$json" | jq -r '.sni')
            local path=$(echo "$json" | jq -r '.path')
            local host=$(echo "$json" | jq -r '.host')
            
            cat << EOF
  - name: "$name"
    type: vmess
    server: "$server"
    port: $port
    uuid: $uuid
    alterId: 0
    cipher: auto
    network: ${network:-tcp}
    tls: $([[ "$tls" == "tls" ]] && echo "true" || echo "false")
    skip-cert-verify: true
    servername: ${sni:-$host}
EOF
            if [[ "$network" == "ws" ]]; then
                cat << EOF
    ws-opts:
      path: ${path:-/}
      headers:
        Host: ${host:-$sni}
EOF
            fi
            ;;
        trojan)
            local password=$(echo "$json" | jq -r '.password')
            local sni=$(echo "$json" | jq -r '.sni')
            cat << EOF
  - name: "$name"
    type: trojan
    server: "$server"
    port: $port
    password: $password
    sni: $sni
    skip-cert-verify: true
    udp: true
EOF
            ;;
        ss)
            local method=$(echo "$json" | jq -r '.method')
            local password=$(echo "$json" | jq -r '.password')
            cat << EOF
  - name: "$name"
    type: ss
    server: "$server"
    port: $port
    cipher: $method
    password: $password
    udp: true
EOF
            ;;
        hysteria2)
            local password=$(echo "$json" | jq -r '.password')
            local sni=$(echo "$json" | jq -r '.sni')
            cat << EOF
  - name: "$name"
    type: hysteria2
    server: "$server"
    port: $port
    password: $password
    sni: $sni
    skip-cert-verify: true
EOF
            ;;
        anytls)
            local password=$(echo "$json" | jq -r '.password')
            local sni=$(echo "$json" | jq -r '.sni')
            cat << EOF
  - name: "$name"
    type: anytls
    server: "$server"
    port: $port
    password: $password
    sni: $sni
    skip-cert-verify: true
EOF
            ;;
    esac
}

# 将外部节点转换为 Surge 格式
external_link_to_surge() {
    local link="$1"
    local json=$(parse_share_link "$link")
    [[ -z "$json" ]] && return
    
    local type=$(echo "$json" | jq -r '.type')
    local name=$(echo "$json" | jq -r '.name')
    local server=$(echo "$json" | jq -r '.server')
    local port=$(echo "$json" | jq -r '.port')
    
    # 给外部节点名称加上服务器标识，避免与本地节点重复
    local server_suffix=$(get_ip_suffix "$server")
    [[ -n "$server_suffix" && "$name" != *"-${server_suffix}"* && "$name" != *"-${server_suffix}" ]] && name="${name}-${server_suffix}"
    
    case "$type" in
        vmess)
            local uuid=$(echo "$json" | jq -r '.uuid')
            local network=$(echo "$json" | jq -r '.network')
            local tls=$(echo "$json" | jq -r '.tls')
            local sni=$(echo "$json" | jq -r '.sni')
            local path=$(echo "$json" | jq -r '.path')
            if [[ "$network" == "ws" ]]; then
                echo "$name = vmess, $server, $port, $uuid, tls=$([[ "$tls" == "tls" ]] && echo "true" || echo "false"), ws=true, ws-path=${path:-/}, sni=$sni, skip-cert-verify=true"
            else
                echo "$name = vmess, $server, $port, $uuid, tls=$([[ "$tls" == "tls" ]] && echo "true" || echo "false"), skip-cert-verify=true"
            fi
            ;;
        trojan)
            local password=$(echo "$json" | jq -r '.password')
            local sni=$(echo "$json" | jq -r '.sni')
            echo "$name = trojan, $server, $port, password=$password, sni=$sni, skip-cert-verify=true"
            ;;
        ss)
            local method=$(echo "$json" | jq -r '.method')
            local password=$(echo "$json" | jq -r '.password')
            echo "$name = ss, $server, $port, encrypt-method=$method, password=$password"
            ;;
        hysteria2)
            local password=$(echo "$json" | jq -r '.password')
            local sni=$(echo "$json" | jq -r '.sni')
            echo "$name = hysteria2, $server, $port, password=$password, sni=$sni, skip-cert-verify=true"
            ;;
        anytls)
            local password=$(echo "$json" | jq -r '.password')
            local sni=$(echo "$json" | jq -r '.sni')
            echo "$name = anytls, $server, $port, password=$password, sni=$sni, skip-cert-verify=true"
            ;;
    esac
}

# 添加分享链接
add_external_link() {
    echo ""
    _line
    echo -e "  ${W}添加分享链接${NC}"
    echo -e "  ${D}支持: vless://, vmess://, trojan://, ss://, hysteria2://, anytls://${NC}"
    _line
    echo ""
    read -rp "  请输入分享链接: " link
    
    [[ -z "$link" ]] && return
    
    # 验证链接格式
    if [[ "$link" != *"://"* ]]; then
        _err "无效的链接格式"
        return 1
    fi
    
    # 检查是否已存在
    if [[ -f "$EXTERNAL_LINKS_FILE" ]] && grep -qF "$link" "$EXTERNAL_LINKS_FILE"; then
        _warn "该链接已存在"
        return 1
    fi
    
    # 解析获取名称
    local name=$(get_link_name "$link")
    
    # 保存
    mkdir -p "$(dirname "$EXTERNAL_LINKS_FILE")"
    echo "$link" >> "$EXTERNAL_LINKS_FILE"
    
    _ok "已添加节点: $name"
    
    # 自动更新订阅文件
    if [[ -f "$CFG/sub.info" ]]; then
        generate_sub_files
    fi
}

# 添加订阅链接
add_external_sub() {
    echo ""
    _line
    echo -e "  ${W}添加订阅链接${NC}"
    echo -e "  ${D}支持 V2Ray/Base64 订阅、Clash YAML 订阅${NC}"
    _line
    echo ""
    read -rp "  请输入订阅链接: " url
    
    [[ -z "$url" ]] && return
    
    # 验证 URL 格式
    if [[ "$url" != http://* && "$url" != https://* ]]; then
        _err "无效的 URL 格式"
        return 1
    fi
    
    # 检查是否已存在
    if [[ -f "$EXTERNAL_SUBS_FILE" ]] && grep -qF "$url" "$EXTERNAL_SUBS_FILE"; then
        _warn "该订阅已存在"
        return 1
    fi
    
    # 测试拉取
    _info "测试订阅链接..."
    local content=$(fetch_subscription "$url")
    
    if [[ -z "$content" ]]; then
        _err "无法获取订阅内容"
        return 1
    fi
    
    local node_count=$(echo "$content" | grep -c '://' || echo 0)
    
    # 保存
    mkdir -p "$(dirname "$EXTERNAL_SUBS_FILE")"
    echo "$url" >> "$EXTERNAL_SUBS_FILE"
    
    # 缓存节点
    mkdir -p "$EXTERNAL_CACHE_DIR"
    local idx=$(wc -l < "$EXTERNAL_SUBS_FILE" 2>/dev/null || echo 1)
    echo "$content" > "$EXTERNAL_CACHE_DIR/sub_$idx.txt"
    
    _ok "已添加订阅，包含 $node_count 个节点"
    
    # 自动更新订阅文件
    if [[ -f "$CFG/sub.info" ]]; then
        generate_sub_files
    fi
}

# 查看外部节点
show_external_nodes() {
    echo ""
    _line
    echo -e "  ${W}外部节点列表${NC}"
    _line
    
    local count=0
    
    # 显示分享链接
    if [[ -f "$EXTERNAL_LINKS_FILE" ]]; then
        echo -e "\n  ${Y}[分享链接]${NC}"
        local idx=0
        while IFS= read -r link || [[ -n "$link" ]]; do
            [[ -z "$link" || "$link" == \#* ]] && continue
            ((idx++))
            ((count++))
            local name=$(get_link_name "$link")
            local proto="${link%%://*}"
            echo -e "  ${G}$idx)${NC} [$proto] $name"
        done < "$EXTERNAL_LINKS_FILE"
        [[ $idx -eq 0 ]] && echo -e "  ${D}(无)${NC}"
    fi
    
    # 显示订阅
    if [[ -f "$EXTERNAL_SUBS_FILE" ]]; then
        echo -e "\n  ${Y}[订阅链接]${NC}"
        local idx=0
        while IFS= read -r url || [[ -n "$url" ]]; do
            [[ -z "$url" || "$url" == \#* ]] && continue
            ((idx++))
            local cache_file="$EXTERNAL_CACHE_DIR/sub_$idx.txt"
            local node_count=0
            [[ -f "$cache_file" ]] && node_count=$(grep -c '://' "$cache_file" 2>/dev/null || echo 0)
            ((count+=node_count))
            echo -e "  ${G}$idx)${NC} $url ${D}($node_count 个节点)${NC}"
        done < "$EXTERNAL_SUBS_FILE"
        [[ $idx -eq 0 ]] && echo -e "  ${D}(无)${NC}"
    fi
    
    echo ""
    _line
    echo -e "  ${C}共 $count 个外部节点${NC}"
    _line
}

# 删除外部节点
delete_external_node() {
    echo ""
    _line
    echo -e "  ${W}删除外部节点${NC}"
    _line
    echo -e "  ${G}1)${NC} 删除分享链接"
    echo -e "  ${G}2)${NC} 删除订阅链接"
    echo -e "  ${G}3)${NC} 清空所有外部节点"
    echo -e "  ${G}0)${NC} 返回"
    _line
    
    read -rp "  请选择: " choice
    
    case "$choice" in
        1)
            [[ ! -f "$EXTERNAL_LINKS_FILE" ]] && { _warn "没有分享链接"; return; }
            echo ""
            local idx=0
            while IFS= read -r link || [[ -n "$link" ]]; do
                [[ -z "$link" || "$link" == \#* ]] && continue
                ((idx++))
                local name=$(get_link_name "$link")
                echo -e "  ${G}$idx)${NC} $name"
            done < "$EXTERNAL_LINKS_FILE"
            echo ""
            read -rp "  输入序号删除 (0 取消): " del_idx
            [[ "$del_idx" == "0" || -z "$del_idx" ]] && return
            
            sed -i "${del_idx}d" "$EXTERNAL_LINKS_FILE" 2>/dev/null && _ok "已删除" || _err "删除失败"
            # 自动更新订阅文件
            [[ -f "$CFG/sub.info" ]] && generate_sub_files
            ;;
        2)
            [[ ! -f "$EXTERNAL_SUBS_FILE" ]] && { _warn "没有订阅链接"; return; }
            echo ""
            local idx=0
            while IFS= read -r url || [[ -n "$url" ]]; do
                [[ -z "$url" || "$url" == \#* ]] && continue
                ((idx++))
                echo -e "  ${G}$idx)${NC} $url"
            done < "$EXTERNAL_SUBS_FILE"
            echo ""
            read -rp "  输入序号删除 (0 取消): " del_idx
            [[ "$del_idx" == "0" || -z "$del_idx" ]] && return
            
            sed -i "${del_idx}d" "$EXTERNAL_SUBS_FILE" 2>/dev/null
            rm -f "$EXTERNAL_CACHE_DIR/sub_$del_idx.txt" 2>/dev/null
            _ok "已删除"
            # 自动更新订阅文件
            [[ -f "$CFG/sub.info" ]] && generate_sub_files
            ;;
        3)
            read -rp "  确认清空所有外部节点? [y/N]: " confirm
            [[ "$confirm" =~ ^[yY]$ ]] || return
            rm -f "$EXTERNAL_LINKS_FILE" "$EXTERNAL_SUBS_FILE"
            rm -rf "$EXTERNAL_CACHE_DIR"
            _ok "已清空所有外部节点"
            # 自动更新订阅文件
            [[ -f "$CFG/sub.info" ]] && generate_sub_files
            ;;
    esac
}

# 外部节点管理菜单
manage_external_nodes() {
    while true; do
        _header
        echo -e "  ${W}外部节点管理${NC}"
        _line
        _item "1" "添加分享链接"
        _item "2" "添加订阅链接"
        _item "3" "查看外部节点"
        _item "4" "删除外部节点"
        _item "5" "刷新订阅"
        _line
        _item "0" "返回"
        _line
        
        read -rp "  请选择: " choice
        
        case "$choice" in
            1) add_external_link ;;
            2) add_external_sub ;;
            3) show_external_nodes ;;
            4) delete_external_node ;;
            5) refresh_external_subs ;;
            0|"") return ;;
            *) _err "无效选择" ;;
        esac
        
        echo ""
        read -rp "按回车继续..."
    done
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
    
    # 获取地区代码
    local country_code=$(get_ip_country "$ipv4")
    [[ -z "$country_code" ]] && country_code=$(get_ip_country "$ipv6")
    
    # 确定使用的 IP 地址：优先 IPv4，纯 IPv6 环境使用 IPv6（带方括号）
    local server_ip="$ipv4"
    if [[ -z "$server_ip" && -n "$ipv6" ]]; then
        server_ip="[$ipv6]"
    fi
    
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
                [[ -n "$server_ip" ]] && link=$(gen_vless_link "$server_ip" "$actual_port" "$uuid" "$public_key" "$short_id" "$sni" "$country_code")
                ;;
            vless-xhttp)
                [[ -n "$server_ip" ]] && link=$(gen_vless_xhttp_link "$server_ip" "$actual_port" "$uuid" "$public_key" "$short_id" "$sni" "$path" "$country_code")
                ;;
            vless-ws)
                [[ -n "$server_ip" ]] && link=$(gen_vless_ws_link "$server_ip" "$actual_port" "$uuid" "$sni" "$path" "$country_code")
                ;;
            vless-vision)
                [[ -n "$server_ip" ]] && link=$(gen_vless_vision_link "$server_ip" "$actual_port" "$uuid" "$sni" "$country_code")
                ;;
            vmess-ws)
                [[ -n "$server_ip" ]] && link=$(gen_vmess_ws_link "$server_ip" "$actual_port" "$uuid" "$sni" "$path" "$country_code")
                ;;
            trojan)
                [[ -n "$server_ip" ]] && link=$(gen_trojan_link "$server_ip" "$actual_port" "$password" "$sni" "$country_code")
                ;;
            ss2022)
                [[ -n "$server_ip" ]] && link=$(gen_ss2022_link "$server_ip" "$actual_port" "$method" "$password" "$country_code")
                ;;
            hy2)
                [[ -n "$server_ip" ]] && link=$(gen_hy2_link "$server_ip" "$actual_port" "$password" "$sni" "$country_code")
                ;;
            tuic)
                [[ -n "$server_ip" ]] && link=$(gen_tuic_link "$server_ip" "$actual_port" "$uuid" "$password" "$sni" "$country_code")
                ;;
            anytls)
                [[ -n "$server_ip" ]] && link=$(gen_anytls_link "$server_ip" "$actual_port" "$password" "$sni" "$country_code")
                ;;
            snell)
                [[ -n "$server_ip" ]] && link=$(gen_snell_link "$server_ip" "$actual_port" "$psk" "4" "$country_code")
                ;;
            snell-v5)
                [[ -n "$server_ip" ]] && link=$(gen_snell_v5_link "$server_ip" "$actual_port" "$psk" "5" "$country_code")
                ;;
            shadowtls)
                local stls_password=""
                [[ -f "$CFG/shadowtls.info" ]] && stls_password=$(grep "^stls_password=" "$CFG/shadowtls.info" | cut -d= -f2)
                [[ -n "$server_ip" ]] && link=$(gen_shadowtls_link "$server_ip" "$actual_port" "$password" "$method" "$sni" "$stls_password" "$country_code")
                ;;
            socks)
                [[ -n "$server_ip" ]] && link=$(gen_socks_link "$server_ip" "$actual_port" "$username" "$password" "$country_code")
                ;;
        esac
        
        [[ -n "$link" ]] && links+="$link"$'\n'
    done
    
    # 合并外部节点
    local external_links=$(get_all_external_links)
    [[ -n "$external_links" ]] && links+="$external_links"
    
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
    
    # 获取地区代码和IP后缀
    local country_code=$(get_ip_country "$ipv4")
    [[ -z "$country_code" ]] && country_code=$(get_ip_country "$ipv6")
    
    # 确定使用的 IP 地址：优先 IPv4，纯 IPv6 环境使用 IPv6
    local server_ip="$ipv4"
    local ip_suffix="${ipv4##*.}"
    if [[ -z "$server_ip" && -n "$ipv6" ]]; then
        server_ip="$ipv6"
        ip_suffix=$(get_ip_suffix "$ipv6")
    fi
    
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
        
        local name="${country_code}-$(get_protocol_name $protocol)-${ip_suffix}"
        local proxy=""
        
        case "$protocol" in
            vless)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: vless
    server: \"$server_ip\"
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
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: vless
    server: \"$server_ip\"
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
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: vless
    server: \"$server_ip\"
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
            vless-vision)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: vless
    server: \"$server_ip\"
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
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: vmess
    server: \"$server_ip\"
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
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: trojan
    server: \"$server_ip\"
    port: $actual_port
    password: $password
    udp: true
    skip-cert-verify: true
    sni: $sni"
                ;;
            ss2022)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: ss
    server: \"$server_ip\"
    port: $port
    cipher: $method
    password: $password
    udp: true"
                ;;
            hy2)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: hysteria2
    server: \"$server_ip\"
    port: $port
    password: $password
    sni: $sni
    skip-cert-verify: true"
                ;;
            tuic)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: tuic
    server: \"$server_ip\"
    port: $port
    uuid: $uuid
    password: $password
    alpn: [h3]
    udp-relay-mode: native
    congestion-controller: bbr
    sni: $sni
    skip-cert-verify: true"
                ;;
            anytls)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: anytls
    server: \"$server_ip\"
    port: $port
    password: $password
    sni: $sni
    skip-cert-verify: true"
                ;;
        esac
        
        if [[ -n "$proxy" ]]; then
            proxies+="$proxy"$'\n'
            proxy_names+="      - \"$name\""$'\n'
        fi
    done
    
    # 合并外部节点
    local external_links=$(get_all_external_links)
    while IFS= read -r link || [[ -n "$link" ]]; do
        [[ -z "$link" || "$link" != *"://"* ]] && continue
        local ext_proxy=$(external_link_to_clash "$link")
        if [[ -n "$ext_proxy" ]]; then
            proxies+="$ext_proxy"$'\n'
            # 从生成的 proxy 中提取名称
            local ext_name=$(echo "$ext_proxy" | grep -m1 'name:' | sed 's/.*name:[[:space:]]*"\([^"]*\)".*/\1/')
            proxy_names+="      - \"$ext_name\""$'\n'
        fi
    done <<< "$external_links"
    
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
    local ipv6=$(get_ipv6)
    local proxies=""
    local proxy_names=""
    
    # 获取地区代码
    local country_code=$(get_ip_country "$ipv4")
    [[ -z "$country_code" ]] && country_code=$(get_ip_country "$ipv6")
    
    # 确定使用的 IP 地址：优先 IPv4，纯 IPv6 环境使用 IPv6
    local server_ip="$ipv4"
    local ip_suffix="${ipv4##*.}"
    if [[ -z "$server_ip" && -n "$ipv6" ]]; then
        server_ip="[$ipv6]"
        ip_suffix=$(get_ip_suffix "$ipv6")
    fi
    
    for protocol in $installed; do
        local info_file="$CFG/${protocol}.info"
        [[ ! -f "$info_file" ]] && continue
        
        local uuid="" port="" sni="" short_id="" public_key="" path=""
        local password="" username="" method="" psk=""
        source "$info_file"
        
        local name="${country_code}-$(get_protocol_name $protocol)-${ip_suffix}"
        local proxy=""
        
        case "$protocol" in
            trojan)
                [[ -n "$server_ip" ]] && proxy="$name = trojan, $server_ip, $port, password=$password, sni=$sni, skip-cert-verify=true"
                ;;
            ss2022)
                [[ -n "$server_ip" ]] && proxy="$name = ss, $server_ip, $port, encrypt-method=$method, password=$password"
                ;;
            hy2)
                [[ -n "$server_ip" ]] && proxy="$name = hysteria2, $server_ip, $port, password=$password, sni=$sni, skip-cert-verify=true"
                ;;
            snell|snell-v5)
                [[ -n "$server_ip" ]] && proxy="$name = snell, $server_ip, $port, psk=$psk, version=${version:-4}"
                ;;
        esac
        
        if [[ -n "$proxy" ]]; then
            proxies+="$proxy"$'\n'
            [[ -n "$proxy_names" ]] && proxy_names+=", "
            proxy_names+="$name"
        fi
    done
    
    # 合并外部节点 (仅支持 vmess/trojan/ss/hysteria2)
    local external_links=$(get_all_external_links)
    while IFS= read -r link || [[ -n "$link" ]]; do
        [[ -z "$link" || "$link" != *"://"* ]] && continue
        local ext_proxy=$(external_link_to_surge "$link")
        if [[ -n "$ext_proxy" ]]; then
            proxies+="$ext_proxy"$'\n'
            # 从生成的 proxy 中提取名称
            local ext_name=$(echo "$ext_proxy" | cut -d'=' -f1 | xargs)
            [[ -n "$proxy_names" ]] && proxy_names+=", "
            proxy_names+="$ext_name"
        fi
    done <<< "$external_links"
    
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
    
    # HTTPS 自签名证书提示
    if [[ "$sub_https" == "true" && -z "$sub_domain" ]]; then
        echo -e "  ${Y}提示: 使用自签名证书，部分客户端可能无法解析订阅${NC}"
        echo -e "  ${D}建议使用 HTTP 或绑定真实域名申请证书${NC}"
    fi
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
            _item "3" "外部节点管理"
            _item "4" "重新配置"
            _item "5" "停用订阅服务"
        else
            echo -e "  状态: ${D}未配置${NC}"
            echo ""
            _item "1" "启用订阅服务"
            _item "2" "外部节点管理"
        fi
        _item "0" "返回"
        _line
        
        read -rp "  请选择: " choice
        
        if [[ -f "$CFG/sub.info" ]]; then
            case $choice in
                1) show_sub_links; _pause ;;
                2) generate_sub_files; _ok "订阅内容已更新"; _pause ;;
                3) manage_external_nodes ;;
                4) setup_subscription_interactive ;;
                5) 
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
                2) manage_external_nodes ;;
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
    
    # 端口（带冲突检测）
    local default_port=8443
    local sub_port=""
    
    while true; do
        read -rp "  订阅端口 [$default_port]: " sub_port
        sub_port="${sub_port:-$default_port}"
        
        # 检查是否被已安装协议占用
        local conflict_proto=$(is_internal_port_occupied "$sub_port")
        if [[ -n "$conflict_proto" ]]; then
            _err "端口 $sub_port 已被 [$conflict_proto] 协议占用"
            _warn "请选择其他端口"
            continue
        fi
        
        # 检查系统端口占用
        if ss -tuln 2>/dev/null | grep -q ":$sub_port " || netstat -tuln 2>/dev/null | grep -q ":$sub_port "; then
            _warn "端口 $sub_port 已被系统占用"
            read -rp "  是否强制使用? [y/N]: " force
            [[ "$force" =~ ^[yY]$ ]] && break
            continue
        fi
        
        break
    done
    
    # 域名
    echo -e "  ${D}留空使用服务器IP${NC}"
    read -rp "  域名 (可选): " sub_domain
    
    # HTTPS
    local use_https="true"
    read -rp "  启用 HTTPS? [Y/n]: " https_choice
    [[ "$https_choice" =~ ^[nN]$ ]] && use_https="false"
    
    # 生成订阅文件
    generate_sub_files
    
    # 获取订阅 UUID
    local sub_uuid=$(get_sub_uuid)
    local sub_dir="$CFG/subscription/$sub_uuid"
    local server_name="${sub_domain:-$(get_ipv4)}"
    
    # 配置 Nginx
    local nginx_conf="/etc/nginx/conf.d/vless-sub.conf"
    mkdir -p /etc/nginx/conf.d
    
    # 删除可能冲突的旧配置
    rm -f /etc/nginx/conf.d/vless-fake.conf 2>/dev/null
    rm -f /etc/nginx/sites-enabled/vless-fake 2>/dev/null
    
    if [[ "$use_https" == "true" ]]; then
        # HTTPS 模式：需要证书
        local cert_file="$CFG/certs/server.crt"
        local key_file="$CFG/certs/server.key"
        
        # 检查证书是否存在，不存在则生成自签名证书
        if [[ ! -f "$cert_file" || ! -f "$key_file" ]]; then
            _info "生成自签名证书..."
            mkdir -p "$CFG/certs"
            openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
                -keyout "$key_file" -out "$cert_file" \
                -subj "/CN=$server_name" 2>/dev/null
        fi
        
        cat > "$nginx_conf" << EOF
server {
    listen $sub_port ssl http2;
    listen [::]:$sub_port ssl http2;
    server_name $server_name;

    ssl_certificate $cert_file;
    ssl_certificate_key $key_file;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    root /var/www/html;
    index index.html;

    # 订阅路径
    location ~ ^/sub/([a-f0-9-]+)/v2ray\$ {
        alias $CFG/subscription/\$1/base64;
        default_type text/plain;
        add_header Content-Type "text/plain; charset=utf-8";
    }

    location ~ ^/sub/([a-f0-9-]+)/clash\$ {
        alias $CFG/subscription/\$1/clash.yaml;
        default_type text/yaml;
    }

    location ~ ^/sub/([a-f0-9-]+)/surge\$ {
        alias $CFG/subscription/\$1/surge.conf;
        default_type text/plain;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }

    server_tokens off;
}
EOF
    else
        # HTTP 模式
        cat > "$nginx_conf" << EOF
server {
    listen $sub_port;
    listen [::]:$sub_port;
    server_name $server_name;

    root /var/www/html;
    index index.html;

    # 订阅路径
    location ~ ^/sub/([a-f0-9-]+)/v2ray\$ {
        alias $CFG/subscription/\$1/base64;
        default_type text/plain;
        add_header Content-Type "text/plain; charset=utf-8";
    }

    location ~ ^/sub/([a-f0-9-]+)/clash\$ {
        alias $CFG/subscription/\$1/clash.yaml;
        default_type text/yaml;
    }

    location ~ ^/sub/([a-f0-9-]+)/surge\$ {
        alias $CFG/subscription/\$1/surge.conf;
        default_type text/plain;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }

    server_tokens off;
}
EOF
    fi
    
    # 确保伪装网页存在
    mkdir -p /var/www/html
    if [[ ! -f "/var/www/html/index.html" ]]; then
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
    
    # 保存订阅配置
    cat > "$CFG/sub.info" << EOF
sub_uuid=$sub_uuid
sub_port=$sub_port
sub_domain=$sub_domain
sub_https=$use_https
EOF
    
    # 测试并重载 Nginx
    if nginx -t 2>/dev/null; then
        if [[ "$DISTRO" == "alpine" ]]; then
            rc-update add nginx default 2>/dev/null
            rc-service nginx restart 2>/dev/null
        else
            systemctl enable nginx 2>/dev/null
            systemctl restart nginx 2>/dev/null
        fi
        _ok "订阅服务已配置"
    else
        _err "Nginx 配置错误"
        nginx -t
        rm -f "$nginx_conf"
        _pause
        return
    fi
    
    echo ""
    show_sub_links
    _pause
}

#═══════════════════════════════════════════════════════════════════════════════
# 日志查看
#═══════════════════════════════════════════════════════════════════════════════

show_logs() {
    _header
    echo -e "  ${W}运行日志${NC}"
    _line
    
    echo -e "  ${G}1${NC}) 查看脚本日志 (最近 50 行)"
    echo -e "  ${G}2${NC}) 查看 Watchdog 日志 (最近 50 行)"
    echo -e "  ${G}3${NC}) 查看服务日志 (按协议选择)"
    echo -e "  ${G}4${NC}) 实时跟踪脚本日志"
    echo -e "  ${G}0${NC}) 返回"
    _line
    
    read -rp "  请选择: " log_choice
    
    case $log_choice in
        1)
            _line
            echo -e "  ${C}脚本日志 ($LOG_FILE):${NC}"
            _line
            if [[ -f "$LOG_FILE" ]]; then
                tail -n 50 "$LOG_FILE"
            else
                _warn "日志文件不存在"
            fi
            ;;
        2)
            _line
            echo -e "  ${C}Watchdog 日志:${NC}"
            _line
            if [[ -f "/var/log/vless-watchdog.log" ]]; then
                tail -n 50 /var/log/vless-watchdog.log
            else
                _warn "Watchdog 日志文件不存在"
            fi
            ;;
        3)
            show_service_logs
            ;;
        4)
            _line
            echo -e "  ${C}实时跟踪日志 (Ctrl+C 退出):${NC}"
            _line
            if [[ -f "$LOG_FILE" ]]; then
                tail -f "$LOG_FILE"
            else
                _warn "日志文件不存在"
            fi
            ;;
        0|"")
            return
            ;;
        *)
            _err "无效选择"
            ;;
    esac
}

# 按协议查看服务日志
show_service_logs() {
    _header
    echo -e "  ${W}服务日志${NC}"
    _line
    
    local installed=$(get_installed_protocols)
    if [[ -z "$installed" ]]; then
        _warn "未安装任何协议"
        return
    fi
    
    # 构建菜单
    local idx=1
    local proto_array=()
    
    # Xray 协议组
    local xray_protocols=$(get_xray_protocols)
    if [[ -n "$xray_protocols" ]]; then
        echo -e "  ${G}$idx${NC}) Xray 服务日志 (vless/vmess/trojan/ss2022/socks)"
        proto_array+=("xray")
        ((idx++))
    fi
    
    # 独立协议
    local independent_protocols=$(get_independent_protocols)
    for proto in $independent_protocols; do
        local proto_name=$(get_protocol_name $proto)
        echo -e "  ${G}$idx${NC}) $proto_name 服务日志"
        proto_array+=("$proto")
        ((idx++))
    done
    
    echo -e "  ${G}0${NC}) 返回"
    _line
    
    read -rp "  请选择: " svc_choice
    
    if [[ "$svc_choice" == "0" || -z "$svc_choice" ]]; then
        return
    fi
    
    if ! [[ "$svc_choice" =~ ^[0-9]+$ ]] || [[ $svc_choice -lt 1 ]] || [[ $svc_choice -ge $idx ]]; then
        _err "无效选择"
        return
    fi
    
    local selected="${proto_array[$((svc_choice-1))]}"
    local service_name=""
    local proc_name=""
    
    case "$selected" in
        xray)
            service_name="vless-reality"
            proc_name="xray"
            ;;
        hy2)
            service_name="vless-hy2"
            proc_name="hysteria"
            ;;
        tuic)
            service_name="vless-tuic"
            proc_name="tuic-server"
            ;;
        snell)
            service_name="vless-snell"
            proc_name="snell-server"
            ;;
        snell-v5)
            service_name="vless-snell-v5"
            proc_name="snell-server-v5"
            ;;
        snell-shadowtls|snell-v5-shadowtls|ss2022-shadowtls)
            service_name="vless-${selected}"
            proc_name="shadow-tls"
            ;;
        anytls)
            service_name="vless-anytls"
            proc_name="anytls-server"
            ;;
    esac
    
    _line
    echo -e "  ${C}$selected 服务日志 (最近 50 行):${NC}"
    _line
    
    if [[ "$DISTRO" == "alpine" ]]; then
        # Alpine: 从系统日志中过滤
        if [[ -f /var/log/messages ]]; then
            grep -iE "$proc_name|$service_name" /var/log/messages 2>/dev/null | tail -n 50
            if [[ $? -ne 0 ]]; then
                _warn "未找到相关日志"
            fi
        else
            _warn "系统日志不可用 (/var/log/messages)"
        fi
    else
        # systemd: 使用 journalctl
        if journalctl -u "$service_name" --no-pager -n 50 2>/dev/null; then
            :
        else
            _warn "无法获取服务日志，尝试从系统日志查找..."
            journalctl --no-pager -n 50 2>/dev/null | grep -iE "$proc_name|$service_name" || _warn "未找到相关日志"
        fi
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 脚本更新与主入口
#═══════════════════════════════════════════════════════════════════════════════

do_update() {
    _header
    echo -e "  ${W}脚本更新${NC}"
    _line
    
    echo -e "  当前版本: ${G}v${VERSION}${NC}"
    _info "检查最新版本..."
    
    local raw_url="https://raw.githubusercontent.com/Chil30/vless-all-in-one/main/vless-server.sh"
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
    init_log  # 初始化日志
    clean_corrupted_info_files  # 清理被污染的配置文件
    
    while true; do
        _header
        echo -e "  ${W}服务端管理${NC}"
        echo -e "  ${D}系统: $DISTRO${NC}"
        echo ""
        show_status
        echo ""
        _line
        
        local installed=$(get_installed_protocols)
        if [[ -n "$installed" ]]; then
            # 多协议服务端菜单
            _item "1" "安装新协议 (多协议共存)"
            _item "2" "查看所有协议配置"
            _item "3" "订阅服务管理"
            _item "4" "管理协议服务"
            _item "5" "BBR 网络优化"
            _item "6" "卸载指定协议"
            _item "7" "完全卸载"
            _item "8" "查看运行日志"
        else
            _item "1" "安装协议"
        fi
        _item "u" "检查更新"
        _item "0" "退出"
        _line
        
        read -rp "  请选择: " choice || exit 0
        
        if [[ -n "$installed" ]]; then
            case $choice in
                1) do_install_server ;;
                2) show_all_protocols_info ;;
                3) manage_subscription ;;
                4) manage_protocol_services ;;
                5) enable_bbr ;;
                6) uninstall_specific_protocol ;;
                7) do_uninstall ;;
                8) show_logs ;;
                u|U) do_update ;;
                0) exit 0 ;;
                *) _err "无效选择" ;;
            esac
        else
            case $choice in
                1) do_install_server ;;
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
