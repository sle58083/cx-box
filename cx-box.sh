#!/bin/bash
#
# cx-box 管理脚本（安装到 /usr/bin/cx-box）—— 对标 Teminuosi/s-ui 的 s-ui.sh。
# 只调用 cx-box 已实现的 CLI：cx-box run/uri/setting/admin/token/migrate。
# 尚未实现的面板能力（如 SSL 证书申请）不在菜单里假装可用，留待后续阶段。

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

INSTALL_URL="https://raw.githubusercontent.com/sle58083/cx-box/main/install.sh"
INSTALL_DIR="/usr/local/cx-box"
BIN="${INSTALL_DIR}/cx-box"
SERVICE_NAME="cx-box"

function LOGD() { echo -e "${yellow}[DEG] $* ${plain}"; }
function LOGE() { echo -e "${red}[ERR] $* ${plain}"; }
function LOGI() { echo -e "${green}[INF] $* ${plain}"; }

[[ $EUID -ne 0 ]] && LOGE "ERROR: You must be root to run this script! \n" && exit 1

confirm() {
    if [[ $# > 1 ]]; then
        echo && read -p "$1 [Default $2]: " temp
        if [[ x"${temp}" == x"" ]]; then
            temp=$2
        fi
    else
        read -p "$1 [y/n]: " temp
    fi
    if [[ x"${temp}" == x"y" || x"${temp}" == x"Y" ]]; then
        return 0
    else
        return 1
    fi
}

before_show_menu() {
    echo && echo -n -e "${yellow}Press enter to return to the main menu: ${plain}" && read temp
    show_menu
}

check_status() {
    if [[ ! -f "/etc/systemd/system/$1.service" ]]; then
        return 2
    fi
    temp=$(systemctl status "$1" 2>/dev/null | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [[ x"${temp}" == x"running" ]]; then
        return 0
    else
        return 1
    fi
}

install_panel() {
    bash <(curl -Ls ${INSTALL_URL})
    if [[ $? == 0 ]]; then
        start ${SERVICE_NAME}
    fi
}

update_panel() {
    confirm "This will reinstall the latest version; your data will not be lost. Continue?" "n"
    if [[ $? != 0 ]]; then
        LOGE "Cancelled"
        before_show_menu
        return 0
    fi
    bash <(curl -Ls ${INSTALL_URL})
    if [[ $? == 0 ]]; then
        LOGI "Update complete, panel has restarted"
        exit 0
    fi
}

custom_version() {
    echo "Enter the panel version (like v0.1.0):"
    read panel_version
    if [ -z "$panel_version" ]; then
        echo "Panel version cannot be empty. Exiting."
        exit 1
    fi
    case "$panel_version" in v*) ;; *) panel_version="v$panel_version" ;; esac
    echo "Downloading and installing panel version $panel_version..."
    bash <(curl -Ls ${INSTALL_URL}) $panel_version
}

uninstall_panel() {
    confirm "Are you sure you want to uninstall the panel?" "n"
    if [[ $? != 0 ]]; then
        show_menu
        return 0
    fi
    systemctl stop ${SERVICE_NAME} 2>/dev/null
    systemctl disable ${SERVICE_NAME} 2>/dev/null
    pkill -9 -f '/usr/local/cx-box' 2>/dev/null
    rm -f /etc/systemd/system/cx-box.service
    rm -f /etc/systemd/system/multi-user.target.wants/cx-box.service
    systemctl daemon-reload 2>/dev/null
    systemctl reset-failed 2>/dev/null
    rm -rf ${INSTALL_DIR}/
    rm -f /usr/bin/cx-box
    echo ""
    echo -e "${green}Uninstalled cleanly: binary, database, service unit and the cx-box menu script are all removed.${plain}"
    echo ""
    exit 0
}

reset_admin() {
    echo "It is not recommended to reset admin credentials to default (admin/admin)!"
    confirm "Are you sure you want to reset admin credentials to default?" "n"
    if [[ $? == 0 ]]; then
        ${BIN} admin -reset
    fi
    before_show_menu
}

set_admin() {
    read -p "Please set up your username:" config_account
    read -p "Please set up your password:" config_password
    ${BIN} admin -username ${config_account} -password ${config_password}
    before_show_menu
}

view_admin() {
    ${BIN} admin -show
    before_show_menu
}

gen_api_token() {
    echo "注意：每次生成都会新增一个 API token（旧 token 仍然有效）。"
    confirm "Generate a new API token?" "n"
    if [[ $? == 0 ]]; then
        local token=$(${BIN} token 2>/dev/null)
        if [[ -n "$token" ]]; then
            echo -e "${green}API token (copy the line below):${plain}"
            echo -e "${token}"
        else
            LOGE "Failed to generate token"
        fi
    fi
    before_show_menu
}

reset_setting() {
    confirm "Are you sure you want to reset settings to default (2095 /app/, 2096 /sub/)?" "n"
    if [[ $? == 0 ]]; then
        ${BIN} setting -reset
    fi
    before_show_menu
}

set_setting() {
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
    before_show_menu
}

view_setting() {
    ${BIN} setting -show
    view_uri
    before_show_menu
}

view_uri() {
    info=$(${BIN} uri)
    if [[ $? != 0 ]]; then
        LOGE "Get current uri error"
        return 1
    fi
    LOGI "You may access the Panel with following URL(s):"
    echo -e "${green}${info}${plain}"
}

start() {
    check_status $1
    if [[ $? == 0 ]]; then
        echo ""
        LOGI "$1 is running, no need to start again; use restart if needed"
    else
        systemctl start $1
        sleep 2
        check_status $1
        if [[ $? == 0 ]]; then
            LOGI "$1 started successfully"
        else
            LOGE "Failed to start $1, please check the log later"
        fi
    fi
    before_show_menu
}

stop() {
    check_status $1
    if [[ $? == 1 ]]; then
        echo ""
        LOGI "$1 stopped, no need to stop again!"
    else
        systemctl stop $1
        sleep 2
        check_status $1
        if [[ $? == 1 ]]; then
            LOGI "$1 stopped successfully"
        else
            LOGE "Failed to stop $1, please check the log later"
        fi
    fi
    before_show_menu
}

restart() {
    systemctl restart $1
    sleep 2
    check_status $1
    if [[ $? == 0 ]]; then
        LOGI "$1 restarted successfully"
    else
        LOGE "Failed to restart $1, please check the log later"
    fi
    before_show_menu
}

status() {
    systemctl status ${SERVICE_NAME} -l
    before_show_menu
}

enable() {
    systemctl enable $1
    if [[ $? == 0 ]]; then
        LOGI "Set $1 to start on boot successfully"
    else
        LOGE "Failed to set $1 autostart"
    fi
    before_show_menu
}

disable() {
    systemctl disable $1
    if [[ $? == 0 ]]; then
        LOGI "Autostart of $1 cancelled successfully"
    else
        LOGE "Failed to cancel $1 autostart"
    fi
    before_show_menu
}

show_log() {
    journalctl -u $1.service -e --no-pager -f
    before_show_menu
}

bbr_menu() {
    local cur=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    echo "当前 TCP 拥塞控制: ${cur}"
    if [[ "$cur" == "bbr" ]]; then
        LOGI "BBR 已启用"
        before_show_menu
        return
    fi
    confirm "Enable BBR?" "n"
    if [[ $? == 0 ]]; then
        modprobe tcp_bbr 2>/dev/null
        grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf 2>/dev/null || echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf 2>/dev/null || echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p > /dev/null 2>&1
        LOGI "BBR 当前状态: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
    fi
    before_show_menu
}

update_shell() {
    wget -O /usr/bin/cx-box -N --no-check-certificate https://github.com/sle58083/cx-box/raw/main/cx-box.sh
    if [[ $? != 0 ]]; then
        echo ""
        LOGE "Failed to download script, please check whether the machine can connect to Github"
        before_show_menu
    else
        chmod +x /usr/bin/cx-box
        LOGI "Upgrade script succeeded, please rerun cx-box" && exit 0
    fi
}

show_help() {
    echo "cx-box 管理脚本用法:"
    echo "  cx-box              显示管理菜单"
    echo "  cx-box start        启动面板"
    echo "  cx-box stop         停止面板"
    echo "  cx-box restart      重启面板"
    echo "  cx-box status       查看面板状态"
    echo "  cx-box install      安装面板"
    echo "  cx-box update       更新面板（保留数据）"
    echo "  cx-box uninstall    卸载面板"
    echo "  cx-box uri          查看面板访问地址"
    echo "  cx-box setting      查看面板设置"
    echo "  cx-box admin        查看管理员账号"
    echo "  cx-box token        生成新的 API token"
    echo "  cx-box firewall-on  开启防火墙（自动放行所需端口）"
    echo "  cx-box firewall-off 关闭防火墙"
    echo "  cx-box bbr          查看/启用 BBR"
    echo "  cx-box help         显示本帮助"
}

show_menu() {
    echo -e "
  ${green}cx-box 管理脚本${plain}

  ${green}0.${plain} 退出脚本
  ${green}1.${plain} 安装 cx-box
  ${green}2.${plain} 更新 cx-box
  ${green}3.${plain} 指定版本安装
  ${green}4.${plain} 卸载 cx-box
  ————————————
  ${green}5.${plain} 重置管理员账号（admin/admin）
  ${green}6.${plain} 修改管理员账号密码
  ${green}7.${plain} 查看管理员账号
  ————————————
  ${green}8.${plain} 重置面板设置（2095 /app/，2096 /sub/）
  ${green}9.${plain} 修改面板设置
  ${green}10.${plain} 查看面板设置与访问地址
  ————————————
  ${green}11.${plain} 启动 cx-box
  ${green}12.${plain} 停止 cx-box
  ${green}13.${plain} 重启 cx-box
  ${green}14.${plain} 查看 cx-box 状态
  ${green}15.${plain} 查看 cx-box 日志
  ————————————
  ${green}16.${plain} 启用开机自启
  ${green}17.${plain} 禁用开机自启
  ${green}18.${plain} 生成 API token
  ${green}19.${plain} BBR 管理
  ${green}20.${plain} 更新管理脚本
  ————————————
  ${green}21.${plain} 开启防火墙（自动放行面板/订阅/SSH 与全部协议端口）
  ${green}22.${plain} 关闭防火墙
 "
    echo && read -p "请输入选择 [0-22]: " num
    case "${num}" in
    0) exit 0 ;;
    1) install_panel ;;
    2) update_panel ;;
    3) custom_version ;;
    4) uninstall_panel ;;
    5) reset_admin ;;
    6) set_admin ;;
    7) view_admin ;;
    8) reset_setting ;;
    9) set_setting ;;
    10) view_setting ;;
    11) start ${SERVICE_NAME} ;;
    12) stop ${SERVICE_NAME} ;;
    13) restart ${SERVICE_NAME} ;;
    14) status ;;
    15) show_log ${SERVICE_NAME} ;;
    16) enable ${SERVICE_NAME} ;;
    17) disable ${SERVICE_NAME} ;;
    18) gen_api_token ;;
    19) bbr_menu ;;
    20) update_shell ;;
    21) ${BIN} firewall -on ;;
    22) ${BIN} firewall -off ;;
    *) LOGE "Please enter a correct number [0-22]" && show_menu ;;
    esac
}

# 子命令分发（对标 s-ui.sh 的参数模式）
if [[ $# > 0 ]]; then
    case "$1" in
    start) systemctl start ${SERVICE_NAME} ;;
    stop) systemctl stop ${SERVICE_NAME} ;;
    restart) systemctl restart ${SERVICE_NAME} ;;
    status) systemctl status ${SERVICE_NAME} -l ;;
    install) install_panel ;;
    update) update_panel ;;
    uninstall) uninstall_panel ;;
    uri) view_uri ;;
    setting) ${BIN} setting -show ;;
    admin) ${BIN} admin -show ;;
    token) ${BIN} token ;;
    firewall-on) ${BIN} firewall -on ;;
    firewall-off) ${BIN} firewall -off ;;
    firewall) ${BIN} firewall -status ;;
    bbr) bbr_menu ;;
    help) show_help ;;
    *) show_help ;;
    esac
else
    show_menu
fi
