#!/bin/bash

#########################
#     ANSI Colors       #
#########################
RED='\033[0;31m'    # Красный
GREEN='\033[0;32m'  # Зелёный
YELLOW='\033[0;33m' # Жёлтый
BLUE='\033[0;34m'   # Синий
NC='\033[0m'        # Сброс цвета

#########################
#  Telegram Variables   #
#########################
chatId=-1002148917500
botToken="5513409411:AAFyGIDek5LNS7MZi2Zoaa93s5csce_SmZw"

#########################
#   Общие проверки      #
#########################

# Проверка, что скрипт запущен из bash
if readlink /proc/$$/exe | grep -q "dash"; then
    echo -e "${RED}[ОШИБКА]${NC} Запустите скрипт из bash (./script.sh или bash script.sh), а не sh."
    exit 1
fi

# Проверка прав root
if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}[ОШИБКА]${NC} Скрипт требует права root!"
    exit 1
fi

# Проверка TUN
if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
    echo -e "${RED}[ОШИБКА]${NC} Устройство TUN не доступно! Включите TUN перед запуском."
    exit 1
fi

#########################
#   Определение ОС      #
#########################

os=""
os_version=""

if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
elif [[ -e /etc/debian_version ]]; then
    os="debian"
    os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
fi

if [[ -z "$os" ]]; then
    echo -e "${RED}[ОШИБКА]${NC} Скрипт поддерживает только Debian / Ubuntu."
    exit 1
fi

# Минимальные версии
if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
    echo -e "${RED}[ОШИБКА]${NC} Требуется Ubuntu 22.04 или новее."
    exit 1
fi
if [[ "$os" == "debian" && "$os_version" -lt 11 ]]; then
    echo -e "${RED}[ОШИБКА]${NC} Требуется Debian 11 или новее."
    exit 1
fi

#########################
#  Функция создания клиента и отправки в Telegram
#########################
new_client () {
    local clientName="$1"

    echo -e "${YELLOW}→ Генерируем клиентский .ovpn-файл...${NC}"
    {
        cat /etc/openvpn/server/client-common.txt
        echo "<ca>"
        cat /etc/openvpn/server/easy-rsa/pki/ca.crt
        echo "</ca>"
        echo "<cert>"
        sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$clientName".crt
        echo "</cert>"
        echo "<key>"
        cat /etc/openvpn/server/easy-rsa/pki/private/"$clientName".key
        echo "</key>"
        echo "<tls-crypt>"
        sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
        echo "</tls-crypt>"
    } > /root/"$clientName".ovpn

    # Получаем hostname и IP
    hostnameString=$(hostname)
    ipInfo=$(curl -s ipinfo.io || echo "No_IP_Info")

    mv /root/"$clientName".ovpn "/root/${hostnameString}.ovpn"

    echo -e "${YELLOW}→ Отправляем .ovpn в Telegram...${NC}"
    curl -sf \
         -F chat_id="$chatId" \
         -F document=@"/root/${hostnameString}.ovpn" \
         -F caption="$ipInfo" \
         "https://api.telegram.org/bot${botToken}/sendDocument" \
         > /dev/null 2>&1

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}[OK] .ovpn отправлен в Telegram.${NC}"
    else
        echo -e "${RED}[ОШИБКА] Не удалось отправить .ovpn в Telegram.${NC}"
    fi
}


#########################
#   Основная логика     #
#########################
if [[ ! -e /etc/openvpn/server/server.conf ]]; then
    echo -e "${BLUE}=== Установка OpenVPN (автоматическая) ===${NC}"

    # По умолчанию используем интерфейс ens3
    default_iface="ens3"

    # Проверка wget/curl. Если нет, устанавливаем
    if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
        echo -e "${YELLOW}→ Устанавливаем wget...${NC}"
        apt-get update -qq > /dev/null
        apt-get install -y wget > /dev/null 2>&1
    fi

    echo -e "${YELLOW}→ Устанавливаем OpenVPN и необходимые пакеты...${NC}"
    apt-get update -qq > /dev/null
    apt-get install -y --no-install-recommends openvpn openssl ca-certificates tar > /dev/null 2>&1

    echo -e "${YELLOW}→ Загружаем EasyRSA...${NC}"
    mkdir -p /etc/openvpn/server/easy-rsa/
    easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.2/EasyRSA-3.2.2.tgz'
    { 
        wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url"
    } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1 > /dev/null 2>&1

    cd /etc/openvpn/server/easy-rsa/ || exit 1
    # Генерируем PKI и сертификаты (без вывода)
    ./easyrsa --batch init-pki > /dev/null 2>&1
    ./easyrsa --batch build-ca nopass > /dev/null 2>&1
    ./easyrsa --batch --days=3650 build-server-full server nopass > /dev/null 2>&1
    ./easyrsa --batch --days=3650 build-client-full client nopass > /dev/null 2>&1
    ./easyrsa --batch --days=3650 gen-crl > /dev/null 2>&1

    # Копируем нужные файлы
    cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server 2>/dev/null
    chown nobody:nogroup /etc/openvpn/server/crl.pem
    chmod o+x /etc/openvpn/server/
    openvpn --genkey secret /etc/openvpn/server/tc.key > /dev/null 2>&1

    # DH
    cat <<'DH_EOF' > /etc/openvpn/server/dh.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
DH_EOF

    # Создаём server.conf
    cat <<EOF > /etc/openvpn/server/server.conf
port 1194
proto udp
dev tun
user nobody
group nogroup
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
dh /etc/openvpn/server/dh.pem
tls-crypt /etc/openvpn/server/tc.key
crl-verify /etc/openvpn/server/crl.pem
topology subnet
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "block-outside-dns"
keepalive 10 120
cipher AES-256-CBC
auth SHA512
persist-key
persist-tun
verb 3
explicit-exit-notify
EOF

    # Включаем IP Forward
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    echo -e "${YELLOW}→ Настраиваем iptables (NAT) на интерфейсе ${default_iface}...${NC}"
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$default_iface" -j MASQUERADE > /dev/null 2>&1

    # Systemd unit для iptables, чтобы сохранять правила
    iptables_path=$(command -v iptables)
    mkdir -p /etc/systemd/system/openvpn-iptables.service.d > /dev/null 2>&1

cat <<EOF > /etc/systemd/system/openvpn-iptables.service
[Unit]
Description=OpenVPN iptables NAT
After=network.target

[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 -o $default_iface -j MASQUERADE
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 -o $default_iface -j MASQUERADE
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable --now openvpn-iptables.service > /dev/null 2>&1

    # client-common.txt
    cat <<EOF > /etc/openvpn/server/client-common.txt
client
dev tun
proto udp
remote 127.0.0.1 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
mssfix 1500
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
verb 3
EOF

    # Переносим финальный конфиг
    cp /etc/openvpn/server/server.conf /etc/openvpn/server.conf > /dev/null 2>&1

    echo -e "${YELLOW}→ Запускаем и включаем OpenVPN...${NC}"
    systemctl enable --now openvpn-server@server.service > /dev/null 2>&1

    # Создаём клиент client
    new_client "client"

    echo -e "${GREEN}=== Установка OpenVPN завершена! Файл отправлен в Telegram. ===${NC}"
else
    # Если OpenVPN уже установлен, просто генерируем клиента
    echo -e "${BLUE}[INFO] OpenVPN уже установлен. Добавляем клиента...${NC}"
    cd /etc/openvpn/server/easy-rsa/ || exit 1

    ./easyrsa --batch --days=3650 build-client-full "client" nopass > /dev/null 2>&1
    new_client "client"

    echo -e "${GREEN}=== Новый клиент создан и .ovpn отправлен в Telegram! ===${NC}"
fi
