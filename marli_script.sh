#!/bin/bash

clear
echo  '     -----Menu------'
echo  $(tput setaf 2)
echo  '     '1. Useradd
echo  '     '2. Userdel
echo  '     '3. Show list user
echo  '     '4. Install Shadowshock-libev '+' Simple-obfs
echo  '     '5. Install OpenVPN
echo  '     '6. Install monitor openvpn
echo  '     '7. Create File Auto Start monitor openvpn
echo  '     '8. Stop monitor openvpn
echo  '     '9. Check status openvpn
echo  '     '10. Set standar permission
echo  '     '11. Set prevent multiple login
echo  '     '12. Show all Port TCP / UDP 
echo  '     '13. Wake on LAN / etherwake
echo  '     '14. Install X-UI VMESS,VLESS,SHADOWSOCKS,etc
echo  '     '15. Make Certificate cert and key
echo  '     '16. Install Softether VPN SSLVPN+OVPN+L2TP+IPSEC+VPN OVER DNS
echo  '     '17. Install SSL/TLS Tunnel
echo  '     '18. Install Docker '&' Docker Compose
echo  '     '19. Install Wireguard NAT UBUNTU 22.0.4
echo  '     '20. Install Driver TP-LINK Archer T4U
echo  '     '21. Install PI-HOLE
echo  '     '22. Install INSTALL CLOUDFLARE DOH
echo  '     '23. Port Forwading Client to Public
echo  '     '24. DNS Editor
echo  $(tput setaf 3)
echo  '     'h. Help
echo  $(tput setaf 1)
echo  '     'x. Exit
echo  $(tput setaf 7)

echo  '     '$(tput setaf 3)'Author Marli Rukmana'$(tput setaf 7)
echo

read -p  'Input: ' pilih

if [ $pilih == '' ] ; then
read -p  'Input: ' pilih
fi

if [ $pilih == '1' ] ; then
	
	clear
	read -p 'Username: ' uservar

	sudo useradd -r -s /sbin/nologin $uservar
	
	if [ $(getent group VPN) ]; then
	echo  $(tput setaf 1)
	echo '---------------'
	echo  $(tput setaf 7)
	else
	groupadd VPN
	fi
	
	usermod -a -G VPN  $uservar
	passwd $uservar

	echo
	echo  $(tput setaf 2)
	echo Thankyou $uservar we now have your login details
	echo  $(tput setaf 7)

fi

if [ $pilih == '2' ] ; then
	
	clear
	read -p 'Username delete: ' uservar
	userdel -r  $uservar
	rm -r $uservar'.ovpn'

	echo  $(tput setaf 2)
	echo
	echo Thankyou $uservar  Deleted
	echo  $(tput setaf 7)

fi

if [ $pilih == '3' ] ; then
	
	clear
	echo  $(tput setaf 2)
	echo for show all user input bellow less /etc/passwd  press q for quit 
	getent group | grep VPN
	echo  $(tput setaf 7)
	
fi

if [ $pilih == '4' ] ; then
	
    FILE=/etc/shadowsocks-libev/config.json
	if [ -f "$FILE" ]; then
	echo  $(tput setaf 1)
    echo "Shadowshock exists."
	echo  $(tput setaf 7)
	else
	
	read -p  'Are You Sure Want Install Shadowssocks? y/n : ' Choose
	if [ $Choose == 'y' ] ; then
	
	echo Install shadowsocks-libev via Ubuntu PPA
	sudo apt-get install software-properties-common -y
	sudo add-apt-repository ppa:max-c-lv/shadowsocks-libev -y
	sudo apt-get update
	sudo apt install shadowsocks-libev
	
	echo Install simple-obfs
	sudo apt-get install --no-install-recommends build-essential autoconf libtool libssl-dev libpcre3-dev libev-dev asciidoc xmlto automake
	sudo apt-get install git
	git clone https://github.com/shadowsocks/simple-obfs.git
	cd simple-obfs
	git submodule update --init --recursive
	./autogen.sh
	./configure && make
	sudo make install
	
	echo Make obfs-server able to listen on port 443
	
	setcap cap_net_bind_service+ep /usr/local/bin/obfs-server
	
	echo Server configuration
	echo
	echo
	rm -r /etc/shadowsocks-libev/config.json
	echo '{
    "server":"0.0.0.0",
    "server_port":8843,
    "local_port":1080,
    "password":"ChangeMe",
    "timeout":300,
    "method":"chacha20-ietf-poly1305",
    "workers":8,
    "plugin":"obfs-server",
    "plugin_opts": "obfs=tls;obfs-host=www.google.com",
    "fast_open":true,
    "reuse_port":true,
    "mode":"tcp_and_udp",
    "nameserver":"1.1.1.1"
	}' >>/etc/shadowsocks-libev/config.json
	
	systemctl enable shadowsocks-libev.service
	systemctl start shadowsocks-libev.service
	systemctl status shadowsocks-libev.service
	
	read -p  'Install BBR For Optimation? y/n : ' Choose2
	if [ $Choose2 == 'y' ] ; then
	
	wget https://github.com/teddysun/across/raw/master/bbr.sh && chmod +x bbr.sh && ./bbr.sh
	echo '
	fs.file-max = 51200

	net.core.rmem_max = 67108864
	net.core.wmem_max = 67108864
	net.core.netdev_max_backlog = 250000
	net.core.somaxconn = 4096

	net.ipv4.tcp_syncookies = 1
	net.ipv4.tcp_tw_reuse = 1
	net.ipv4.tcp_fin_timeout = 30
	net.ipv4.tcp_keepalive_time = 1200
	net.ipv4.ip_local_port_range = 10000 65000
	net.ipv4.tcp_max_syn_backlog = 8192
	net.ipv4.tcp_max_tw_buckets = 5000
	net.ipv4.tcp_fastopen = 3
	net.ipv4.tcp_mem = 25600 51200 102400
	net.ipv4.tcp_rmem = 4096 87380 67108864
	net.ipv4.tcp_wmem = 4096 65536 67108864
	net.ipv4.tcp_mtu_probing = 1 ' >> /etc/sysctl.d/local.conf
	
	echo please reboot
	
	fi
	fi
	fi

fi

if [ $pilih == '5' ] ; then
# Mulai Open VPN
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "The system is running an old kernel, which is incompatible with this installer."
	exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Ubuntu 18.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
	echo "Debian 9 or higher is required to use this installer.
This version of Debian is too old and unsupported."
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo "CentOS 7 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
	exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
	exit
fi

new_client () {
	# Generates the custom client.ovpn
	{
	cat /etc/openvpn/server/client-common.txt
	echo "<ca>"
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt
	echo "</ca>"
	echo "<cert>"
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
	echo "</cert>"
	echo "<key>"
	cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
	echo "</key>"
	echo "<tls-crypt>"
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
	echo "</tls-crypt>"
	} > ~/"$client".ovpn
}

if [[ ! -e /etc/openvpn/server/server.conf ]]; then
	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "Wget is required to use this installer."
		read -n1 -r -p "Press any key to install Wget and continue..."
		apt-get update
		apt-get install -y wget
	fi
	clear
	echo 'Welcome to this OpenVPN road warrior installer!'
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Which IPv4 address should be used?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# If $ip is a private IP address, the server must be behind NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	# If system has a single IPv6, it is selected automatically
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Which IPv6 address should be used?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "Which protocol should OpenVPN use?"
	echo "   1) UDP (recommended)"
	echo "   2) TCP"
	read -p "Protocol [1]: " protocol
	until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
		echo "$protocol: invalid selection."
		read -p "Protocol [1]: " protocol
	done
	case "$protocol" in
		1|"") 
		protocol=udp
		;;
		2) 
		protocol=tcp
		;;
	esac
	echo
	echo "What port should OpenVPN listen to?"
	read -p "Port [1194]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: invalid port."
		read -p "Port [1194]: " port
	done
	[[ -z "$port" ]] && port="1194"
	echo
	echo "Select a DNS server for the clients:"
	echo "   1) Current system resolvers"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) AdGuard"
	read -p "DNS server [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS server [1]: " dns
	done
	echo
	echo "Enter a name for the first client:"
	read -p "Name [client]: " unsanitized_client
	# Allow a limited set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	echo
	echo "OpenVPN installation is ready to begin."
	# Install a firewall if firewalld or iptables are not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			# We don't want to silently enable firewalld, so we give a subtle warning
			# If the user continues, firewalld will be installed and enabled during setup
			echo "firewalld, which is required to manage routing tables, will also be installed."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables is way less invasive than firewalld so no warning is given
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Press any key to continue..."
	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		apt-get update
		apt-get install -y openvpn openssl ca-certificates $firewall
	elif [[ "$os" = "centos" ]]; then
		yum install -y epel-release
		yum install -y openvpn openssl ca-certificates tar $firewall
	else
		# Else, OS must be Fedora
		dnf install -y openvpn openssl ca-certificates tar $firewall
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# Get easy-rsa
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
	chown -R root:root /etc/openvpn/server/easy-rsa/
	cd /etc/openvpn/server/easy-rsa/
	# Create the PKI, set up the CA and the server and client certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	# CRL is read with each client connection, while OpenVPN is dropped to nobody
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
	chmod o+x /etc/openvpn/server/
	# Generate key for tls-crypt
	openvpn --genkey --secret /etc/openvpn/server/tc.key
	# Create the DH parameters file using the predefined ffdhe2048 group
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
	# Generate server.conf
	echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0
client-cert-not-required
username-as-common-name
plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /etc/pam.d/login" > /etc/openvpn/server/server.conf
	# IPv6
	if [[ -z "$ip6" ]]; then
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	else
		echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
		echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	fi
	echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf
	# DNS
	case "$dns" in
		1|"")
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep -q '^nameserver 127.0.0.53' "/etc/resolv.conf"; then
				resolv_conf="/run/systemd/resolve/resolv.conf"
			else
				resolv_conf="/etc/resolv.conf"
			fi
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
			done
		;;
		2)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		3)
			echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
		;;
		4)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5)
			echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
		;;
		6)
			echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
comp-lzo
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server.conf
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
	fi
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				yum install -y policycoreutils-python
			else
				# CentOS 8 or Fedora
				dnf install -y policycoreutils-python-utils
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	# If the server is behind NAT, use the correct IP address
	[[ -n "$public_ip" ]] && ip="$public_ip"
	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
comp-lzo yes
auth-user-pass
auth-nocache
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3" > /etc/openvpn/server/client-common.txt
	# Enable and start the OpenVPN service
	systemctl enable --now openvpn-server@server.service
	# Generates the custom client.ovpn
	new_client
	echo
	echo "Finished!"
	echo
	echo "The client configuration is available in:" ~/"$client.ovpn"
	echo "New clients can be added by running this script again."
else
	clear
	echo "OpenVPN is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new Profile"
	echo "   2) Revoke an existing Profile"
	echo "   3) Remove OpenVPN"
	echo "   4) Exit"
	read -p "Option: " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	case "$option" in
		1)
			echo
			echo "Provide a name for the profile:"
			read -p "Name: " unsanitized_client
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
				echo "$client: invalid name."
				read -p "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			done
			cd /etc/openvpn/server/easy-rsa/
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
			# Generates the custom client.ovpn
			new_client
			echo
			echo "$client added. Configuration available in:" ~/"$client.ovpn"
			exit
		;;
		2)
			# This option could be documented a bit better and maybe even be simplified
			# ...but what can I say, I want some sleep too
			number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "There are no existing clients!"
				exit
			fi
			echo
			echo "Select the profile to revoke:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -p "Client: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo
			read -p "Confirm $client revocation? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo "$revoke: invalid selection."
				read -p "Confirm $client revocation? [y/N]: " revoke
			done
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				cd /etc/openvpn/server/easy-rsa/
				./easyrsa --batch revoke "$client"
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f /etc/openvpn/server/crl.pem
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				# CRL is read with each client connection, when OpenVPN is dropped to nobody
				chown nobody:"$group_name" /etc/openvpn/server/crl.pem
				echo
				echo "$client revoked!"
			else
				echo
				echo "$client revocation aborted!"
			fi
			exit
		;;
		3)
			echo
			read -p "Confirm OpenVPN removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm OpenVPN removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				systemctl disable --now openvpn-server@server.service
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/99-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					rm -rf /etc/openvpn/server
					apt-get remove --purge -y openvpn
				else
					# Else, OS must be CentOS or Fedora
					yum remove -y openvpn
					rm -rf /etc/openvpn/server
				fi
				echo
				echo "OpenVPN removed!"
			else
				echo
				echo "OpenVPN removal aborted!"
			fi
			exit
		;;
		4)
			exit
		;;
	esac
fi
# Akhir Open VPN

fi

if [ $pilih == '6' ] ; then
	
	FILE=/opt/openvpn-monitor/openvpn-monitor.conf
	if [ -f "$FILE" ]; then
	echo  $(tput setaf 1)
    echo "OPEN VPN MONITOR exists."
	echo  $(tput setaf 7)
	else
	
	FILE2=/etc/openvpn/server/server.conf
	if [ -f "$FILE2" ]; then
	
	clear
	cd
	echo 'management 127.0.0.1 5555' >> /etc/openvpn/server/server.conf
	cd
	mkdir '/opt/openvpn-monitor'
	cd '/opt/openvpn-monitor'
	apt install python3-virtualenv
	virtualenv venv
	source venv/bin/activate
	pip install openvpn-monitor gunicorn

	echo '[openvpn-monitor]
	site=your-openvpn-site
	#logo=logo.jpg

	datetime_format=%d/%m/%Y %H:%M:%S

	[VPN1]
	host=localhost
	port=
	name=Your VPN Server Name
	show_disconnect=False' > openvpn-monitor.conf

	gunicorn openvpn-monitor -b 0.0.0.0:80 --name openvpn-monitor --daemon
	
	echo 
	echo berhasil terinstall silahkan buka browser http://yourIP:80
	
	else
	echo  $(tput setaf 1)
	echo 'OPENVPN NOT INSTALLED'
	echo  $(tput setaf 7)
	fi
	
	fi
fi

if [ $pilih == '7' ] ; then
	
	clear
	cd
	FILE=monitor-ovpn.sh
	if [ -f "$FILE" ]; then
	echo  $(tput setaf 1)
    echo "OPENVPN MONITOR  FILE is Exists."
	echo  $(tput setaf 7)
	else
	
echo '#!/bin/bash
SHELL=/bin/bash 
PATH=/bin:/sbin:/usr/bin:/usr/sbin

source /opt/openvpn-monitor/venv/bin/activate
gunicorn openvpn-monitor -b 0.0.0.0:80 --name openvpn-monitor --daemon' > monitor-ovpn.sh
	
	chmod +x monitor-ovpn.sh
	
	#write out current crontab
	crontab -l > mycron
	#echo new cron into cron file
	echo "@reboot /bin/bash  ~/monitor-ovpn.sh" >> mycron
	#install new cron file
	crontab mycron
	rm mycron

	echo
	echo  $(tput setaf 2)	
	echo berhasil dibuat
	echo  $(tput setaf 7)
	fi
fi

if [ $pilih == '8' ] ; then
	
	clear
	cd
	cd '/opt/openvpn-monitor/venv/bin/'
	pkill gunicorn
	#deactive
	
	echo 
	echo  $(tput setaf 2)
	echo berhasil dimatikan
	echo  $(tput setaf 7)
	
fi

if [ $pilih == '9' ] ; then
	
	clear
	systemctl status openvpn-server@server.service
	
fi

if [ $pilih == '10' ] ; then
	
	clear
	STRING='PermitRootLogin yes'
	FILE=/etc/ssh/sshd_config
	if  grep -q "$STRING" "$FILE" ; then
		 echo  $(tput setaf 1)
         echo 'Already set Before' ; 
		 echo  $(tput setaf 7)
	else
	
	timedatectl set-timezone Asia/Jakarta
	sudo sed -i 's/#PermitRootLogin Prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
	apt-get install curl
	apt-get install git
	
	echo
	echo  $(tput setaf 2)
	echo Done
	echo  $(tput setaf 7)
	
	fi
	
fi

if [ $pilih == '11' ] ; then
	
	clear
	STRING='username - maxlogins 1'
	FILE=/etc/security/limits.conf
	if  grep -q "$STRING" "$FILE" ; then
		 echo  $(tput setaf 1)
         echo 'Already set Before' ; 
		 echo  $(tput setaf 7)
	else 

	echo 'username - maxlogins 1' >> /etc/security/limits.conf
	echo  $(tput setaf 2)
	echo berhasil 
	echo untuk melihat perubahan lihat pada 'nano /etc/security/limits.conf'
	echo  $(tput setaf 7)
	
	fi
	
fi

if [ $pilih == '12' ] ; then
	
	clear
	cat /etc/services
	
fi

if [ $pilih == '13' ] ; then
	
	clear
	echo  '     -----Menu Wake On LAN / Etherwake------'
	echo  $(tput setaf 2)
	echo  '     '1. Install Ehterwake
	echo  '     '2. Custom Mac Address 00:00:00:00:00
	echo  '     '3. wake on lan Server storage marugo D4:F5:EF:4A:5F:18
	echo  '     '4. wake on lan Server attendance marugo 40:2C:F4:EA:9E:F7
	echo  $(tput setaf 1)
	echo  '     'x. Exit
	echo  $(tput setaf 7)

	echo  '     '$(tput setaf 3)'Author Marli Rukmana'$(tput setaf 7)
	echo

	read -p  'Input: ' select
		
		if [ $select == '1' ] ; then
		
		sudo apt install etherwake
		
		fi
		
		if [ $select == '2' ] ; then
		
		read -p  'Input Mac Address: ' select2
		
			etherwake $select2
			
			echo "Wake on lan sent"
		
		fi
		
		if [ $select == '3' ] ; then
		
		etherwake D4:F5:EF:4A:5F:18
		
		echo "Wake on lan sent"
		
		fi
		
		if [ $select == '4' ] ; then
		
		etherwake 40:2C:F4:EA:9E:F7
		
		echo "Wake on lan sent"
		
		fi
	
fi

if [ $pilih == '14' ] ; then
	
	clear
	apt update
	apt install curl -y
    bash <(curl -Ls https://raw.githubusercontent.com/vaxilu/x-ui/master/install.sh)
	
fi

if [ $pilih == '15' ] ; then
	
    
	openssl genrsa -out key.pem 2048 && openssl req -new -x509 -key key.pem -out cert.pem -days 1095
	echo "berhasil"
	
fi

if [ $pilih == '16' ] ; then
	
    clear
	apt-get install build-essential gnupg2 gcc make -y
	wget http://www.softether-download.com/files/softether/v4.38-9760-rtm-2021.08.17-tree/Linux/SoftEther_VPN_Server/64bit_-_Intel_x64_or_AMD64/softether-vpnserver-v4.38-9760-rtm-2021.08.17-linux-x64-64bit.tar.gz
	tar -xvzf softether-vpnserver-v4.38-9760-rtm-2021.08.17-linux-x64-64bit.tar.gz
	cd vpnserver
	make
	
	cd ..
	mv vpnserver /usr/local/
	cd /usr/local/vpnserver/
	chmod 600 *
	chmod 700 vpnserver
	chmod 700 vpncmd
	cd

	echo '#!/bin/sh
### BEGIN INIT INFO
# Provides:          haltusbpower
# Required-Start:    $all
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:
# Short-Description: Halts USB power...
### END INIT INFO
# chkconfig: 2345 99 01
# description: SoftEther VPN Server
DAEMON=/usr/local/vpnserver/vpnserver
LOCK=/var/lock/subsys/vpnserver
test -x $DAEMON || exit 0
case "$1" in
start)
$DAEMON start
touch $LOCK
;;
stop)
$DAEMON stop
rm $LOCK
;;
restart)
$DAEMON stop
sleep 3
$DAEMON start
;;
*)
echo "Usage: $0 {start|stop|restart}"
exit 1
esac
exit 0' > /etc/init.d/vpnserver

	mkdir /var/lock/subsys
	chmod 755 /etc/init.d/vpnserver
	/etc/init.d/vpnserver start
	update-rc.d vpnserver defaults
	systemctl enable vpnserver.service
	
	cd
	cd /usr/local/vpnserver
	./vpncmd
	
	echo 'for set password input command : ServerPasswordSet'
	
fi

if [ $pilih == '17' ] ; then
	
    clear
#install dropbear
apt install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 443"/g' /etc/default/dropbear
service dropbear start
# detail nama perusahaan
country=ID
state=Karawang
locality=Jawa Barat
organization=Marugo
organizationalunit=IT
commonname=Marli Rukmana
email=it@marugo.co.id

# install stunnel
apt-get install stunnel4 -y

echo "cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
[dropbear]
accept = 443
connect = 127.0.0.1:443" > /etc/stunnel/stunnel.conf


echo "=================  membuat Sertifikat OpenSSL ======================"
echo "========================================================="
#membuat sertifikat
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# konfigurasi stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
service stunnel4 restart
	
fi

if [ $pilih == '18' ] ; then
	
    clear
	sudo apt update
	sudo apt-get install apt-transport-https ca-certificates curl gnupg-agent software-properties-common
	curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
	sudo apt-key fingerprint 0EBFCD88
	sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
	sudo apt-get install docker-ce=5:19.03.10~3-0~ubuntu-focal docker-ce-cli=5:19.03.10~3-0~ubuntu-focal containerd.io
	sudo apt-get install docker-ce docker-ce-cli containerd.io
	sudo usermod -aG docker $USER
	sudo curl -L "https://github.com/docker/compose/releases/download/1.26.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
	sudo chmod +x /usr/local/bin/docker-compose
	sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
	docker-compose --version
	sudo docker run hello-world
	
fi

if [ $pilih == '19' ] ; then
	
    clear
	wget https://git.io/wireguard -O wireguard-install.sh && bash wireguard-install.sh
	
fi

if [ $pilih == '20' ] ; then
	
    clear
	sudo apt install git dkms
	git clone https://github.com/cilynx/rtl88x2bu.git
	sudo dkms add ./rtl88x2bu
	sudo dkms install rtl88x2bu/5.8.7.1 
	
	sudo apt install git dkms
	git clone https://github.com/aircrack-ng/rtl8812au.git
	cd rtl8812au
	sudo make dkms_install
	
fi

if [ $pilih == '21' ] ; then

	wget -O basic-install.sh https://install.pi-hole.net
	sudo bash basic-install.sh

fi

if [ $pilih == '22' ] ; then

	wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
	sudo apt-get install ./cloudflared-linux-amd64.deb
	cloudflared -v
	echo making startup doh
	sudo useradd -s /usr/sbin/nologin -r -M cloudflared
	echo -e "# Commandline args for cloudflared, using Cloudflare DNS\nCLOUDFLARED_OPTS=--port 5053 --upstream https://1.1.1.1/dns-query --upstream https://1.0.0.1/dns-query" | sudo tee /etc/default/cloudflared > /dev/null
	sudo chown cloudflared:cloudflared /etc/default/cloudflared
	sudo chown cloudflared:cloudflared /usr/local/bin/cloudflared
	echo -e "[Unit]\nDescription=cloudflared DNS over HTTPS proxy\nAfter=syslog.target network-online.target\n\n[Service]\nType=simple\nUser=cloudflared\nEnvironmentFile=/etc/default/cloudflared\nExecStart=/usr/local/bin/cloudflared proxy-dns \$CLOUDFLARED_OPTS\nRestart=on-failure\nRestartSec=10\nKillMode=process\n\n[Install]\nWantedBy=multi-user.target" | sudo tee /etc/systemd/system/cloudflared.service > /dev/null
	sudo systemctl enable cloudflared
	sudo systemctl start cloudflared
	sudo systemctl status cloudflared
	dig @127.0.0.1 -p 5053 google.com
	echo input these dns on your pihole 127.0.0.1#5053
fi


if [ $pilih == '23' ] ; then

#!/bin/bash

# Function to read user input with a prompt and default value
read_input() {
    local prompt="$1"
    local default_value="$2"
    local input
    read -p "$prompt [$default_value]: " input
    echo "${input:-$default_value}"
}

# Function to add a port forwarding rule
add_rule() {
    local DEFAULT_PORT_TO_FORWARD=12345
    local DEFAULT_CLIENT_IP="10.0.0.2"
    local DEFAULT_CLIENT_PORT=12345
    local DEFAULT_PROTOCOL="tcp"

    PORT_TO_FORWARD=$(read_input "Enter the port to forward" $DEFAULT_PORT_TO_FORWARD)
    CLIENT_IP=$(read_input "Enter the client IP" $DEFAULT_CLIENT_IP)
    CLIENT_PORT=$(read_input "Enter the client port" $DEFAULT_CLIENT_PORT)
    PROTOCOL=$(read_input "Enter the protocol (tcp/udp)" $DEFAULT_PROTOCOL)

    if [[ "$PROTOCOL" != "tcp" && "$PROTOCOL" != "udp" ]]; then
        echo "Invalid protocol. Please enter 'tcp' or 'udp'."
        return
    fi

    echo "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1

    echo "Making IP forwarding persistent..."
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi

    echo "Setting up iptables rules for port forwarding..."
    iptables -t nat -A PREROUTING -p $PROTOCOL --dport $PORT_TO_FORWARD -j DNAT --to-destination $CLIENT_IP:$CLIENT_PORT
    iptables -t nat -A POSTROUTING -j MASQUERADE

    echo "Saving iptables rules..."
    iptables-save > /etc/iptables/rules.v4  # Save IPv4 rules

    echo "Port forwarding setup complete."
}

# Function to view current port forwarding rules
view_rules() {
    echo "Current port forwarding rules (NAT table):"
    iptables -t nat -L -n -v
    echo ""
    echo "DNAT rules (PREROUTING chain):"
    iptables -t nat -L PREROUTING -n -v --line-numbers
}

# Function to delete a specific port forwarding rule
delete_rule() {
    view_rules

    PROTOCOL=$(read_input "Enter the protocol (tcp/udp)" "")
    PORT_TO_FORWARD=$(read_input "Enter the port to forward" "")
    CLIENT_IP=$(read_input "Enter the client IP" "")
    CLIENT_PORT=$(read_input "Enter the client port" "")

    if [[ -z "$PROTOCOL" || -z "$PORT_TO_FORWARD" || -z "$CLIENT_IP" || -z "$CLIENT_PORT" ]]; then
        echo "All fields are required."
        return
    fi

    if [[ "$PROTOCOL" != "tcp" && "$PROTOCOL" != "udp" ]]; then
        echo "Invalid protocol. Please enter 'tcp' or 'udp'."
        return
    fi

    echo "Deleting port forwarding rule..."
    iptables -t nat -D PREROUTING -p $PROTOCOL --dport $PORT_TO_FORWARD -j DNAT --to-destination $CLIENT_IP:$CLIENT_PORT

    echo "Updated DNAT rules (PREROUTING chain):"
    iptables -t nat -L PREROUTING -n -v --line-numbers

    echo "Saving iptables rules..."
    iptables-save > /etc/iptables/rules.v4  # Save IPv4 rules
}

# Main menu
while true; do
    echo "1) Add port forwarding rule"
    echo "2) View port forwarding rules"
    echo "3) Delete port forwarding rule"
    echo "4) Exit"
    read -p "Select an option: " option

    case $option in
        1) add_rule ;;
        2) view_rules ;;
        3) delete_rule ;;
        4) exit ;;
        *) echo "Invalid option. Please select 1, 2, 3, or 4." ;;
    esac
done



fi

if [ pilih == 24 ] ; then

#!/bin/bash

# Function to add nameserver to /etc/resolv.conf
add_nameserver() {
    local nameserver="$1"

    # Check if the nameserver already exists in resolv.conf
    if grep -q "^nameserver $nameserver" /etc/resolv.conf; then
        echo "Nameserver $nameserver already exists in /etc/resolv.conf."
    else
        echo "Adding nameserver $nameserver to /etc/resolv.conf..."
        echo "nameserver $nameserver" >> /etc/resolv.conf
        echo "Nameserver added successfully."
    fi
}

# Function to view nameservers in /etc/resolv.conf
view_nameservers() {
    echo "Nameservers in /etc/resolv.conf:"
    grep "^nameserver" /etc/resolv.conf
}

# Function to delete nameserver from /etc/resolv.conf
delete_nameserver() {
    local nameserver="$1"

    # Check if the nameserver exists in resolv.conf
    if grep -q "^nameserver $nameserver" /etc/resolv.conf; then
        echo "Deleting nameserver $nameserver from /etc/resolv.conf..."
        sed -i "/^nameserver $nameserver/d" /etc/resolv.conf
        echo "Nameserver deleted successfully."
    else
        echo "Nameserver $nameserver does not exist in /etc/resolv.conf."
    fi
}

# Main menu
while true; do
    echo "1) Add nameserver to /etc/resolv.conf"
    echo "2) View nameservers in /etc/resolv.conf"
    echo "3) Delete nameserver from /etc/resolv.conf"
    echo "4) Exit"
    read -p "Select an option: " option

    case $option in
        1) read -p "Enter the nameserver to add: " ns_add; add_nameserver "$ns_add" ;;
        2) view_nameservers ;;
        3) read -p "Enter the nameserver to delete: " ns_del; delete_nameserver "$ns_del" ;;
        4) exit ;;
        *) echo "Invalid option. Please select 1, 2, 3, or 4." ;;
    esac
done



fi

if [ $pilih == 'h' ] ; then
	
	clear
	echo  $(tput setaf 2)
	echo ssh
	echo  $(tput setaf 7)
	echo ssh permit login root on file /etc/ssh/sshd_config change PermitRootLogin prohibit-password to  PermitRootLogin yes and restart with sudo service ssh restart
	echo add alias to 'nano ~/.bashrc' with the  alias menu='bash  menu.sh'
	echo
	echo  $(tput setaf 2)
	echo OVPN
	echo  $(tput setaf 7)
	echo for openvpn monitor you can access to http://yourIP:80
	echo 'For OVPN LXC PROXMOX please add lxc.cgroup2.devices.allow: c 10:200 rwm and lxc.mount.entry: /dev/net dev/net none bind,create=dir on /etc/pve/lxc/xxx.conf'
	echo
	echo  $(tput setaf 2)
	echo SHADOWSOCKS
	echo  $(tput setaf 7)
	echo Port shadowshock is TCP 8843  for change password on /etc/shadowsocks-libev/config.json
	echo  $(tput setaf 7)
	echo For backup Wireguard configuration please take on /etc/wireguard/wg0.conf and copy client conf


fi

if [ $pilih == 'x' ] ; then
	
	clear
	exit

fi

