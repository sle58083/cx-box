#!/bin/bash
#
# cx-box 安装脚本 —— 对标 Teminuosi/s-ui 的 install.sh 复刻并适配 cx-box。
#
# 与 s-ui 的对应关系：
#   - 安装目录 /usr/local/s-ui        -> /usr/local/cx-box
#   - systemd 服务 s-ui.service       -> cx-box.service
#   - 管理脚本 /usr/bin/s-ui          -> /usr/bin/cx-box（cx-box.sh）
#   - 数据库 db/s-ui.db               -> db/cx-box.db（相对二进制所在目录）
#   - 发布包 s-ui-linux-<arch>.tar.gz -> cx-box-linux-<arch>.tar.gz
#   - 环境变量 SUI_AUTO               -> 保留同名（README 已按此发布），
#                                      同时支持 CXBOX_AUTO 覆盖。
#
# 与 s-ui 的差异（有意为之）：
#   - cx-box 的 sing-box 内核由 sui 进程内托管，没有独立的 sing-box.service，
#     本脚本绝不停止/删除其他程序的 sing-box.service。
#   - cx-box 没有 /etc/s-ui 这类配置目录，purge 只清自己的文件。

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

REPO="sle58083/cx-box"
INSTALL_DIR="/usr/local/cx-box"
BIN="${INSTALL_DIR}/sui"
MENU_BIN="/usr/bin/cx-box"
SERVICE_NAME="cx-box"
DB_FILE="${INSTALL_DIR}/db/cx-box.db"

# Full-auto is the DEFAULT install mode（与 s-ui 一致）：全程无交互。
# 全新安装时生成随机账号密码 + 随机面板路径 + 空闲端口 + API token 并放行防火墙；
# 升级时保留现有设置。要恢复交互流程，设置 SUI_AUTO=0（或 CXBOX_AUTO=0）。
#   bash <(curl -Ls https://raw.githubusercontent.com/sle58083/cx-box/main/install.sh)            # auto (default)
#   SUI_AUTO=1 bash <(curl -Ls https://raw.githubusercontent.com/sle58083/cx-box/main/install.sh) # auto
#   SUI_AUTO=0 bash <(curl -Ls https://raw.githubusercontent.com/sle58083/cx-box/main/install.sh) # interactive
CXBOX_AUTO="${CXBOX_AUTO:-${SUI_AUTO:-1}}"

is_auto() {
    [[ "$CXBOX_AUTO" != "0" && "$CXBOX_AUTO" != "n" && "$CXBOX_AUTO" != "N" ]]
}

# Alphanumeric random string (URL-safe, no base64 specials).
gen_random_string() {
    local length="$1"
    LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom 2>/dev/null | head -c "$length"
}

# Is a TCP port currently being listened on?
# 整行匹配「:端口 + 空白/行尾」，不按列取（不同版本 ss/netstat 列数不同）；
# 末尾边界防止 12096 / 20960 被误判成 2096。
is_port_in_use() {
    local port="$1"
    if command -v ss > /dev/null 2>&1; then
        ss -ltn 2> /dev/null | grep -qE "[:.]${port}([[:space:]]|$)"
        return
    fi
    if command -v netstat > /dev/null 2>&1; then
        netstat -lnt 2> /dev/null | grep -qE "[:.]${port}([[:space:]]|$)"
        return
    fi
    if command -v lsof > /dev/null 2>&1; then
        lsof -nP -iTCP:"${port}" -sTCP:LISTEN > /dev/null 2>&1 && return 0
    fi
    return 1
}

# Echo a free port: prefer $1, else fall back to a random port in 40001-60000.
pick_port() {
    local preferred="$1" p
    if ! is_port_in_use "$preferred"; then
        echo "$preferred"
        return
    fi
    for _ in $(seq 1 30); do
        p=$(shuf -i 40001-60000 -n 1)
        if ! is_port_in_use "$p"; then
            echo "$p"
            return
        fi
    done
    echo "$preferred"
}

# 升级时 cx-box 已停，若面板/订阅端口仍被占用，一定是别的进程
# （典型：同机另一个默认 2096 的面板）。不处理的话 cx-box 会因
# bind: address already in use 反复崩溃，这里自动迁移到空闲端口。
resolve_port_clash() {
    local cur_port cur_sub params=""
    cur_port=$(${BIN} setting -show 2>/dev/null | grep -i "Panel port:" | grep -oE '[0-9]+' | head -1)
    cur_sub=$(${BIN} setting -show 2>/dev/null | grep -i "Sub port:" | grep -oE '[0-9]+' | head -1)

    if [[ -n "$cur_port" ]] && is_port_in_use "$cur_port"; then
        local np=$(pick_port "$cur_port")
        params="$params -port $np"
        echo -e "${red}[auto] Panel port ${cur_port} is already in use by another process; moving the panel to ${np}.${plain}"
    fi
    if [[ -n "$cur_sub" ]] && is_port_in_use "$cur_sub"; then
        local ns=$(pick_port "$cur_sub")
        params="$params -subPort $ns"
        echo -e "${red}[auto] Sub port ${cur_sub} is already in use (another panel?); moving subscriptions to ${ns}.${plain}"
    fi
    if [[ -n "$params" ]]; then
        ${BIN} setting ${params}
        echo -e "${yellow}[auto] Ports changed to avoid a clash. Update any subscription links / bookmarks accordingly.${plain}"
    fi
}

arch() {
    case "$(uname -m)" in
    x86_64 | x64 | amd64) echo 'amd64' ;;
    i*86 | x86) echo '386' ;;
    armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
    armv7* | armv7 | arm) echo 'armv7' ;;
    armv6* | armv6) echo 'armv6' ;;
    armv5* | armv5) echo 'armv5' ;;
    s390x) echo 's390x' ;;
    *) echo -e "${green}Unsupported CPU architecture! ${plain}" && exit 1 ;;
    esac
}

install_base() {
    case "${release}" in
    centos | almalinux | rocky | oracle)
        yum -y update && yum install -y -q wget curl tar tzdata
        ;;
    fedora)
        dnf -y update && dnf install -y -q wget curl tar tzdata
        ;;
    arch | manjaro | parch)
        pacman -Syu && pacman -Syu --noconfirm wget curl tar tzdata
        ;;
    opensuse-tumbleweed)
        zypper refresh && zypper -q install -y wget curl tar timezone
        ;;
    *)
        apt-get update && apt-get install -y -q wget curl tar tzdata
        ;;
    esac
}

config_after_install() {
    # 先记录是否全新安装，再 migrate —— migrate 会创建数据库文件，
    # 之后再用文件是否存在判断就会永远误判成升级（s-ui 原脚本的坑，这里修正）。
    local was_fresh=0
    [[ ! -f "${DB_FILE}" ]] && was_fresh=1

    echo -e "${yellow}Migration... ${plain}"
    ${BIN} migrate

    # Full-auto mode: no prompts. Fresh install -> random credentials + random
    # panel path + free ports; upgrade -> keep existing settings untouched.
    if is_auto; then
        if [[ "${was_fresh}" == "1" ]]; then
            local config_account=$(gen_random_string 10)
            local config_password=$(gen_random_string 10)
            local config_path=$(gen_random_string 15)
            local config_port=$(pick_port 2095)
            local config_subPort=$(pick_port 2096)

            echo -e "${yellow}[auto] Fresh install: generating random credentials, panel path and free ports...${plain}"
            [[ "$config_port" != "2095" ]] && echo -e "${yellow}[auto] Port 2095 busy, using ${config_port} for the panel.${plain}"
            [[ "$config_subPort" != "2096" ]] && echo -e "${yellow}[auto] Port 2096 busy, using ${config_subPort} for subscriptions.${plain}"

            ${BIN} setting -port "${config_port}" -path "/${config_path}/" -subPort "${config_subPort}"
            ${BIN} admin -username "${config_account}" -password "${config_password}"

            # Generate an APIv2 token so this server can be managed from
            # another panel out of the box (central management).
            local config_token=$(${BIN} token 2>/dev/null)

            echo -e "###############################################"
            echo -e "${green}username:${config_account}${plain}"
            echo -e "${green}password:${config_password}${plain}"
            echo -e "${green}panel port:${config_port}${plain}"
            echo -e "${green}panel path:/${config_path}/${plain}"
            echo -e "${green}sub port:${config_subPort}${plain}"
            if [[ -n "$config_token" ]]; then
                echo -e "${green}API token (copy the line below):${plain}"
                echo -e "${config_token}"
            fi
            echo -e "###############################################"
            echo -e "${red}If you forget your login info, type ${green}cx-box${red} on the server for the menu.${plain}"
        else
            echo -e "${yellow}[auto] Upgrade detected: keeping existing settings.${plain}"
            resolve_port_clash
            local up_token=$(${BIN} token 2>/dev/null)
            echo -e "###############################################"
            ${BIN} admin -show 2>/dev/null
            if [[ -n "$up_token" ]]; then
                echo -e "${green}API token (copy the line below):${plain}"
                echo -e "${up_token}"
            fi
            echo -e "${red}If you forget your login info, type ${green}cx-box${red} on the server for the menu.${plain}"
            echo -e "###############################################"
        fi
        return
    fi

    echo -e "${yellow}Install/update finished! For security it's recommended to modify panel settings ${plain}"
    read -p "Do you want to continue with the modification [y/n]? " config_confirm

    if [[ "${config_confirm}" == "y" || "${config_confirm}" == "Y" ]]; then
        echo -e "Enter the ${yellow}panel port${plain} (leave blank for existing/default value):"
        read config_port
        echo -e "Enter the ${yellow}panel path${plain} (leave blank for existing/default value):"
        read config_path
        echo -e "Enter the ${yellow}subscription port${plain} (leave blank for existing/default value):"
        read config_subPort
        echo -e "Enter the ${yellow}subscription path${plain} (leave blank for existing/default value):"
        read config_subPath

        echo -e "${yellow}Initializing, please wait...${plain}"
        params=""
        [ -z "$config_port" ] || params="$params -port $config_port"
        [ -z "$config_path" ] || params="$params -path $config_path"
        [ -z "$config_subPort" ] || params="$params -subPort $config_subPort"
        [ -z "$config_subPath" ] || params="$params -subPath $config_subPath"
        ${BIN} setting ${params}

        read -p "Do you want to change admin credentials [y/n]? " admin_confirm
        if [[ "${admin_confirm}" == "y" || "${admin_confirm}" == "Y" ]]; then
            read -p "Please set up your username:" config_account
            read -p "Please set up your password:" config_password
            echo -e "${yellow}Initializing, please wait...${plain}"
            ${BIN} admin -username ${config_account} -password ${config_password}
        else
            echo -e "${yellow}Your current admin credentials: ${plain}"
            ${BIN} admin -show
        fi
    else
        echo -e "${red}cancel...${plain}"
        if [[ "${was_fresh}" == "1" ]]; then
            local usernameTemp=$(gen_random_string 10)
            local passwordTemp=$(gen_random_string 10)
            ${BIN} admin -username ${usernameTemp} -password ${passwordTemp}
            local config_token=$(${BIN} token 2>/dev/null)
            echo -e "this is a fresh installation, will generate random login info for security concerns:"
            echo -e "###############################################"
            echo -e "${green}username:${usernameTemp}${plain}"
            echo -e "${green}password:${passwordTemp}${plain}"
            if [[ -n "$config_token" ]]; then
                echo -e "${green}API token (copy the line below):${plain}"
                echo -e "${config_token}"
            fi
            echo -e "###############################################"
            echo -e "${red}if you forgot your login info, you can type ${green}cx-box${red} for configuration menu${plain}"
        else
            echo -e "${red} this is your upgrade, will keep old settings, if you forgot your login info, you can type ${green}cx-box${red} for configuration menu${plain}"
        fi
    fi
}

# Best-effort: open the panel/sub ports and the node port range in the host
# firewall so nodes are reachable out of the box. Full-auto only.
open_firewall() {
    is_auto || return 0
    local panel_port sub_port
    panel_port=$(${BIN} setting -show 2>/dev/null | grep -i "Panel port:" | grep -oE '[0-9]+' | head -1)
    sub_port=$(${BIN} setting -show 2>/dev/null | grep -i "Sub port:" | grep -oE '[0-9]+' | head -1)

    if command -v ufw > /dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        [[ -n "$panel_port" ]] && ufw allow "${panel_port}/tcp" > /dev/null 2>&1
        [[ -n "$sub_port" ]] && ufw allow "${sub_port}/tcp" > /dev/null 2>&1
        ufw allow 10000:60000/tcp > /dev/null 2>&1
        ufw allow 10000:60000/udp > /dev/null 2>&1
        ufw reload > /dev/null 2>&1
        echo -e "${green}[auto] Firewall (ufw) opened: ${panel_port}, ${sub_port}, 10000-60000 tcp/udp.${plain}"
    elif command -v firewall-cmd > /dev/null 2>&1 && firewall-cmd --state > /dev/null 2>&1; then
        [[ -n "$panel_port" ]] && firewall-cmd --permanent --add-port="${panel_port}/tcp" > /dev/null 2>&1
        [[ -n "$sub_port" ]] && firewall-cmd --permanent --add-port="${sub_port}/tcp" > /dev/null 2>&1
        firewall-cmd --permanent --add-port=10000-60000/tcp > /dev/null 2>&1
        firewall-cmd --permanent --add-port=10000-60000/udp > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
        echo -e "${green}[auto] Firewall (firewalld) opened: ${panel_port}, ${sub_port}, 10000-60000 tcp/udp.${plain}"
    fi
}

# Download a GitHub release asset with retry + mirror fallback, verifying the
# result is a real gzip each time so a mirror's HTML error page can't slip
# through as a "successful" download.
# Usage: download_release OUT_FILE GITHUB_URL
download_release() {
    local out="$1" gh_url="$2" src label
    local sources=(
        "$gh_url"
        "https://ghfast.top/$gh_url"
        "https://gh-proxy.com/$gh_url"
        "https://ghproxy.net/$gh_url"
    )
    for src in "${sources[@]}"; do
        if [[ "$src" == "$gh_url" ]]; then
            echo -e "${yellow}Downloading (direct github.com)...${plain}"
        else
            label="${src#https://}"; label="${label%%/*}"
            echo -e "${yellow}Direct download failed, retrying via mirror: ${label}${plain}"
        fi
        if wget --no-check-certificate --timeout=30 --tries=2 -O "$out" "$src" \
            && tar -tzf "$out" > /dev/null 2>&1; then
            return 0
        fi
        rm -f "$out"
    done
    return 1
}

install_cx-box() {
    cd /tmp/

    if [ $# == 0 ]; then
        last_version=$(curl -Ls "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
        # Fall back to the most recent release (covers prerelease-only repos).
        if [[ -z "$last_version" ]]; then
            last_version=$(curl -Ls "https://api.github.com/repos/${REPO}/releases" | grep '"tag_name":' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
        fi
        if [[ ! -n "$last_version" ]]; then
            echo -e "${red}Failed to fetch cx-box version, it may be due to Github API restrictions, please try it later${plain}"
            exit 1
        fi
        echo -e "Got cx-box latest version: ${last_version}, beginning the installation..."
        if ! download_release /tmp/cx-box-linux-$(arch).tar.gz "https://github.com/${REPO}/releases/download/${last_version}/cx-box-linux-$(arch).tar.gz"; then
            echo -e "${red}Downloading cx-box failed after trying direct + mirrors. Make sure your server can reach Github (or a proxy) and that /tmp has free disk space.${plain}"
            exit 1
        fi
    else
        last_version=$1
        url="https://github.com/${REPO}/releases/download/${last_version}/cx-box-linux-$(arch).tar.gz"
        echo -e "Beginning the install cx-box $1"
        if ! download_release /tmp/cx-box-linux-$(arch).tar.gz "${url}"; then
            echo -e "${red}download cx-box $1 failed (tried direct + mirrors), please check the version exists${plain}"
            exit 1
        fi
    fi

    if [[ -e "${INSTALL_DIR}/" ]]; then
        systemctl stop ${SERVICE_NAME} 2>/dev/null
    fi

    tar zxvf cx-box-linux-$(arch).tar.gz
    rm cx-box-linux-$(arch).tar.gz -f

    chmod +x cx-box/sui cx-box/cx-box.sh
    cp cx-box/cx-box.sh ${MENU_BIN}
    cp -rf cx-box /usr/local/
    cp -f cx-box/*.service /etc/systemd/system/
    rm -rf cx-box

    config_after_install
    open_firewall

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME} --now

    echo -e "${green}cx-box ${last_version}${plain} installation finished, it is up and running now..."
    echo -e "You may access the Panel with following URL(s):${green}"
    ${BIN} uri
    echo -e "${plain}"
    echo -e ""
    cx-box help
}

purge_cx-box() {
    echo -e "${yellow}Removing every trace of cx-box from this system...${plain}"
    # 每一步独立执行、失败不影响后面：装坏的机器上服务和文件往往只存在一部分。
    systemctl stop ${SERVICE_NAME} >/dev/null 2>&1
    systemctl disable ${SERVICE_NAME} >/dev/null 2>&1
    # 二进制被删后残留进程会占着端口，先杀干净（只匹配 cx-box 自己的路径）。
    pkill -9 -f '/usr/local/cx-box' >/dev/null 2>&1
    rm -f /etc/systemd/system/cx-box.service
    rm -f /etc/systemd/system/multi-user.target.wants/cx-box.service
    systemctl daemon-reload >/dev/null 2>&1
    systemctl reset-failed >/dev/null 2>&1
    rm -rf /usr/local/cx-box/
    rm -f /usr/bin/cx-box
    echo -e "${green}Done. cx-box has been completely removed.${plain}"
    echo -e "Reinstall with: ${green}bash <(curl -Ls https://raw.githubusercontent.com/sle58083/cx-box/main/install.sh)${plain}"
    exit 0
}

main() {
    # check root
    [[ $EUID -ne 0 ]] && echo -e "${red}Fatal error: ${plain} Please run this script with root privilege \n " && exit 1

    # 一键彻底清除入口: bash <(curl -Ls .../install.sh) purge
    # 不复用 cx-box.sh 的卸载：安装被中断时 /usr/bin/cx-box 可能还没铺下去。
    if [[ "$1" == "purge" || "$1" == "uninstall" || "$1" == "--purge" ]]; then
        purge_cx-box
    fi

    # Check OS and set release variable
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        release=$ID
    elif [[ -f /usr/lib/os-release ]]; then
        source /usr/lib/os-release
        release=$ID
    else
        echo "Failed to check the system OS, please contact the author!" >&2
        exit 1
    fi
    echo "The OS release is: $release"
    echo "arch: $(arch)"

    echo -e "${green}Executing...${plain}"
    install_base
    install_cx-box $1
}

# CX_BOX_INSTALL_SOURCE_ONLY=1 时只加载函数（供本地测试），不执行安装。
if [[ "${CX_BOX_INSTALL_SOURCE_ONLY:-}" != "1" ]]; then
    main "$@"
fi
