# Raspberry Cellular Router Project
Build a cellular router with a Raspberry Pi Zero for the Internet of Things.

This example uses a Telekom APN where you get a public IP address (IPv4 only) and can login remotely to your Raspberry Pi Zero.

## Installation of configuration files
```
/boot/config.txt
/etc/afp.conf
/etc/blocklist
/etc/ddclient*
/etc/fail2ban
/etc/hosts
/etc/motd
/etc/ppp
/etc/chat*
/etc/resolvconf.conf
/etc/rsyslog.conf
/etc/samba
/etc/smartd.conf
/etc/squid
/etc/ssh
/etc/sysctl.conf
/etc/vnstat.conf
/var/spool/cron/crontabs/*
/etc/iptables
/etc/motion
/etc/systemd/system/ip*
/etc/default
/var/lib/vnstat
/root
```

## Early Configuration
```
chmod 700 /root
chmod 700 /var/backups
touch /var/log/all.log && chmod 600 /var/log/all.log
```

Add your own users and groups.

```
passwd root
userdel pi
```

## Setup time synchronization
```
dpkg-reconfigure tzdata
vi /etc/systemd/timesyncd.conf
```
```shell
[Time]
NTP=time.euro.apple.com
```

## Packages installation
```
apt-get update && apt-get dist-upgrade
DEBIAN_FRONTEND=noninteractive apt-get -y install bash powertop curl wget ppp ncftp hexedit bchunk bzip2 rsync zip unzip mc e2fsprogs smartmontools ifstat iftop lsof htop nmap kismet geoip-bin geoip-database libnet-cidr-lite-perl libsexy2 iperf iperf3 mutt gnupg screen vim git ettercap-graphical usb-modeswitch ddclient ipcheck minicom vnstat make libnotify3.0-cil xtightvncviewer x11vnc ssvnc tightvncserver vnc4server leafpad conky xvfb xinit xterm xtermset xserver-xorg xutils xosview fluxbox blackbox openbox bbpager libdockapp3 asmon wmnet wmwave wmnd irssi transmission-gtk phantomjs lynx w3m gnome-keyring dillo midori xombrero firefox-esr chromium-browser xdotool p7zip unrar-free openjdk-8-jre ffmpeg r-base python-pip python3-pip autoconf automake libtool shtool intltool bison samba hfsutils python-bsddb3 python3-bsddb3 python-gdbm python3-gdbm python-sqlite python-tk python3-tk python-psycopg2 python3-psycopg2 python-mutagen python3-mutagen python-gobject python-gtk2 python-geoip python3-geoip python-geoip2 python3-geoip2 python-miniupnpc fail2ban python-selenium python3-selenium netatalk adwaita-icon-theme arc-theme libffi-dev libssl-dev gpicview motion

systemctl stop exim4.service
systemctl disable exim4.service

systemctl stop samba.service
systemctl disable samba.service
systemctl stop smbd.service
systemctl disable smbd.service
systemctl stop nmbd.service
systemctl disable nmbd.service

systemctl stop netatalk.service
systemctl disable netatalk.service

systemctl stop minissdpd.service
systemctl disable minissdpd.service

systemctl stop smartd.service
systemctl disable smartd.service

systemctl stop ModemManager.service
systemctl disable ModemManager.service

systemctl stop polkit.service
systemctl disable polkit.service

service vnstat stop
vnstat --create -i eth0
vnstat --create -i wlan0
vnstat --create -i ppp0
service vnstat start

update-alternatives --config python
update-alternatives --config pip
pip install --upgrade speedtest-cli && pip install --upgrade youtube-dl && pip install --upgrade livestreamer && pip install --upgrade pysocks && pip install --upgrade pycrypto && pip install --upgrade streamlink && pip install --upgrade cfscrape && pip freeze --local | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 pip install -U
```

## Install nicotine
```
mkdir -p /usr/local/src && \
cd /usr/local/src && \
wget -O nicotine-plus-1.4.1.tar.gz https://github.com/Nicotine-Plus/nicotine-plus/archive/1.4.1.tar.gz && \
tar -xvzf nicotine-plus-1.4.1.tar.gz && \
cd nicotine-plus-1.4.1 && \
python2.7 setup.py install --optimize=1 --record=INSTALLED_FILES
```

## Boot options
```
vi /boot/config.txt
```
```config
# Disable optional hardware interfaces
dtoverlay=pi3-disable-bt
dtparam=i2c_arm=off
dtparam=i2s=off
dtparam=spi=off
#dtoverlay=pi3-disable-wifi

# Disable audio (loads snd_bcm2835)
dtparam=audio=off

# Enable UART
enable_uart=1

# Disable the ACT LED on the Pi Zero
dtparam=act_led_trigger=none
dtparam=act_led_activelow=on

# Don't start X
start_x=0

# GPU Memory split
gpu_mem=32
```

## Reduce power consumption
```
systemctl stop avahi-daemon.service
systemctl disable avahi-daemon.service

systemctl stop triggerhappy.service
systemctl disable triggerhappy.service

vi /etc/rc.local
```
```config
# Disable HDMI (/usr/bin/tvservice -p to re-enable)
/usr/bin/tvservice -o

# Enable powertop auto tuner
/usr/sbin/powertop --auto-tune
```

## SSH
```
vi /etc/ssh/sshd_config
```
```config
Port 22
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 2m
PermitRootLogin no
StrictModes yes
MaxAuthTries 6
MaxSessions 10
PubkeyAuthentication yes
AuthorizedKeysFile      .ssh/authorized_keys .ssh/authorized_keys2
IgnoreRhosts yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
X11UseLocalhost no
X11DisplayOffset 10
PrintMotd no
TCPKeepAlive yes
IPQoS 0x00
UsePrivilegeSeparation sandbox
ClientAliveInterval 100
ClientAliveCountMax 3
UseDNS no
VersionAddendum none
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server
```
```
service ssh restart
```

## Static resolv.conf
```
vi /etc/resolvconf.conf
```
```config
resolvconf=NO
name_servers="9.9.9.9 1.1.1.1"
```

## Auto-configure network interfaces
```
vi /etc/network/interfaces
```
```config
# interfaces(5) file used by ifup(8) and ifdown(8)

# Please note that this file is written to be used with dhcpcd
# For static IP, consult /etc/dhcpcd.conf and 'man dhcpcd.conf'

# Include files from /etc/network/interfaces.d:
source-directory /etc/network/interfaces.d

# Static resolv.conf
#dns-nameservers 9.9.9.9 1.1.1.1

# Bring up interfaces at boot
auto lo
auto eth0
auto wlan0
auto ppp0

iface lo inet loopback

allow-hotplug eth0
#iface eth0 inet dhcp

allow-hotplug wlan0
#iface wlan0 inet dhcp
#        wpa-conf /etc/wpa_supplicant/wpa_supplicant.conf

iface ppp0 inet ppp
        provider telekom
```

## Auto-configure network interfaces
```
iwlist wlan0 scan
vi /etc/wpa_supplicant/wpa_supplicant.conf
```
```config
ap_scan=1
ctrl_interface=/var/run/wpa_supplicant
network={
       ssid="XXXXXXXXXXX"
       scan_ssid=1
       proto=WPA RSN
       key_mgmt=WPA-PSK
       pairwise=CCMP TKIP
       group=CCMP TKIP
       psk=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
}
```
```
wpa_cli -i wlan0 reconfigure
ip link set wlan0 up
```

## Configure PPP
```
vi /etc/ppp/peers/telekom
```
```config
# example configuration for a dialup connection authenticated with PAP or CHAP
#
# This is the default configuration used by pon(1) and poff(1).
# See the manual page pppd(8) for information on all the options.

# MUST CHANGE: replace myusername@realm with the PPP login name given to
# your by your provider.
# There should be a matching entry with the password in /etc/ppp/pap-secrets
# and/or /etc/ppp/chap-secrets.
#user "myusername@realm"
#user "t-mobile"
#password "tm"

# MUST CHANGE: replace ******** with the phone number of your provider.
# The /etc/chatscripts/pap chat script may be modified to change the
# modem initialization string.
connect "/usr/sbin/chat -v -f /etc/chatscripts/gprs"

# Serial device to which the modem is connected.
/dev/ttyS0

# Speed of the serial line.
115200

nocrtscts

debug

#nodetach
#ipcp-accept-local
#ipcp-accept-remote

# Assumes that your IP address is allocated dynamically by the ISP.
noipdefault

# Try to get the name server addresses from the ISP.
#usepeerdns

# Use this connection as the default route.
defaultroute
replacedefaultroute

# Makes pppd "dial again" when the connection is lost.
persist

# Do not ask the remote to authenticate.
noauth

# Scripts to run
connect "/usr/sbin/chat -v -f /etc/chatscripts/telekom-connect"
disconnect "/usr/sbin/chat -v -f /etc/chatscripts/telekom-disconnect"
```

```
vi /etc/chatscripts/telekom-connect
```
```config
TIMEOUT 10
ABORT 'BUSY'
ABORT 'NO ANSWER'
ABORT 'ERROR'
SAY 'Starting Telekom connect script.\n'

""'ATZ'
SAY 'Setting APN\n'
OK 'AT+CGDCONT=1,"IP","internet.t-d1.de"'

ABORT 'NO CARRIER'
SAY 'Dialing...\n'
OK 'ATD*99***1#'
CONNECT
```

```
vi /etc/chatscripts/telekom-disconnect
```
```config
"" "\K"
"" "+++ATH0"
SAY "Telekom disconnected."
```

## Firewall
```
mkdir /etc/iptables
vi /etc/iptables/iptables.rules
```
```shell
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]

# Logdrop chain
-N LOGDROP
-A LOGDROP -m limit --limit 1/s -j LOG --log-level 4 --log-tcp-options --log-prefix "IPTABLES BAD FLAGS: "
-A LOGDROP -j DROP

# Checkflags chain
-N CHECK_FLAGS
-A CHECK_FLAGS -p tcp --tcp-flags ACK,FIN FIN -j LOGDROP
-A CHECK_FLAGS -p tcp --tcp-flags ACK,PSH PSH -j LOGDROP
-A CHECK_FLAGS -p tcp --tcp-flags ACK,URG URG -j LOGDROP
-A CHECK_FLAGS -p tcp --tcp-flags FIN,RST FIN,RST -j LOGDROP
-A CHECK_FLAGS -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOGDROP
-A CHECK_FLAGS -p tcp --tcp-flags SYN,RST SYN,RST -j LOGDROP
-A CHECK_FLAGS -p tcp --tcp-flags ALL ALL -j LOGDROP
-A CHECK_FLAGS -p tcp --tcp-flags ALL NONE -j LOGDROP
-A CHECK_FLAGS -p tcp --tcp-flags ALL FIN,PSH,URG -j LOGDROP
-A CHECK_FLAGS -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j LOGDROP
-A CHECK_FLAGS -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LOGDROP

# Fail2ban chain
-N f2b-sshd
-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd
-A f2b-sshd -j RETURN

# Loopback device
-A INPUT   -i lo -j ACCEPT
-A OUTPUT  -o lo -j ACCEPT
-A INPUT   -d 127.0.0.1 -j ACCEPT
-A OUTPUT  -s 127.0.0.1 -j ACCEPT

# Allow all OUTPUT
-A OUTPUT  -p ALL -o eth0  -j ACCEPT
-A OUTPUT  -p ALL -o wlan0 -j ACCEPT
-A OUTPUT  -p ALL -o ppp0  -j ACCEPT

# Allow new connections out
-A OUTPUT  -p ALL -o $LANIF -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# ICMP
-A OUTPUT   -p icmp -m icmp --icmp-type redirect -m limit --limit 1/s -j LOG --log-level 4 --log-prefix "IPTABLES OUTPUT: "
-A OUTPUT   -p icmp -m icmp --icmp-type redirect -j DROP
-A OUTPUT   -p icmp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# Blocklog everything else
-A OUTPUT -m limit --limit 1/s -j LOG --log-level 4 --log-prefix "IPTABLES OUTPUT: "
-A OUTPUT -j DROP

# Checkflags
-A INPUT   -p tcp --ipv4 -j CHECK_FLAGS

# Allow already ESTABLISHED connections
-A INPUT   -p ALL -i eth0  -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT   -p ALL -i wlan0 -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT   -p ALL -i ppp0  -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH
-A INPUT   -p tcp -i eth0  --sport 32768:65535 --dport 22 -m state --state NEW -j ACCEPT
-A INPUT   -p tcp -i wlan0 --sport 32768:65535 --dport 22 -m state --state NEW -j ACCEPT
-A INPUT   -p tcp -i ppp0  --sport 32768:65535 --dport 22 -m state --state NEW -j ACCEPT

# Web
-A INPUT   -p tcp -i eth0  --sport 32768:65535 --dport 8080:8081 -m state --state NEW -j ACCEPT
-A INPUT   -p tcp -i wlan0 --sport 32768:65535 --dport 8080:8081 -m state --state NEW -j ACCEPT

# VNC
-A INPUT   -p tcp -i eth0  --sport 32768:65535 --dport 5901 -m state --state NEW -j ACCEPT
-A INPUT   -p tcp -i wlan0 --sport 32768:65535 --dport 5901 -m state --state NEW -j ACCEPT

# ICMP on LAN
-A INPUT   -p icmp -i eth0  -m icmp --icmp-type echo-request -j ACCEPT
-A INPUT   -p icmp -i wlan0 -m icmp --icmp-type echo-request -j ACCEPT
-A INPUT   -p icmp -i eth0  -m icmp --icmp-type 3 -j ACCEPT
-A INPUT   -p icmp -i wlan0 -m icmp --icmp-type 3 -j ACCEPT

# Blocklog everything else
-A INPUT   -m limit --limit 1/s -j LOG --log-level 4 --log-prefix "IPTABLES INPUT: "
-A INPUT   -j DROP
```

```
vi /etc/iptables/ip6tables.rules
```
```shell
# Loopback device
-A INPUT   -i lo -j ACCEPT
-A OUTPUT  -o lo -j ACCEPT
-A INPUT   -s ::1 -d ::1 -j ACCEPT
-A OUTPUT  -s ::1 -d ::1 -j ACCEPT

# Allow already ESTABLISHED connections
-A INPUT   -p ALL -i eth0  -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT   -p ALL -i wlan0 -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT   -p ALL -i ppp0  -m state --state ESTABLISHED,RELATED -j ACCEPT

# Drop --rt-type 0
-A INPUT   -m rt --rt-type 0 -j DROP
-A OUTPUT  -m rt --rt-type 0 -j DROP
-A FORWARD -m rt --rt-type 0 -j DROP

# Allow all OUTPUT
-A OUTPUT  -p ALL -o eth0  -j ACCEPT
-A OUTPUT  -p ALL -o wlan0 -j ACCEPT
-A OUTPUT  -p ALL -o ppp0  -j ACCEPT

# SSH
-A INPUT   -p tcp -i eth0  --sport 32768:65535 --dport 22 -m state --state NEW -j ACCEPT
-A INPUT   -p tcp -i wlan0 --sport 32768:65535 --dport 22 -m state --state NEW -j ACCEPT
-A INPUT   -p tcp -i ppp0  --sport 32768:65535 --dport 22 -m state --state NEW -j ACCEPT

# Web
-A INPUT   -p tcp -i eth0  --sport 32768:65535 --dport 8080:8081 -m state --state NEW -j ACCEPT
-A INPUT   -p tcp -i wlan0 --sport 32768:65535 --dport 8080:8081 -m state --state NEW -j ACCEPT

# VNC
-A INPUT   -p tcp -i eth0  --sport 32768:65535 --dport 5901 -m state --state NEW -j ACCEPT
-A INPUT   -p tcp -i wlan0 --sport 32768:65535 --dport 5901 -m state --state NEW -j ACCEPT

# ICMP
-A INPUT   -p ipv6-icmp -j ACCEPT
-A OUTPUT  -p ipv6-icmp -j ACCEPT
```

```
vi /etc/iptables/flush-iptables.sh
```
```shell
#!/bin/sh
# Flushing existing chains and rules
iptables -t filter -F
iptables -t filter -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Default policy to accept everything
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
```

```
vi /etc/iptables/flush-ip6tables.sh
```
```shell
#!/bin/sh
ip6tables -F
ip6tables -X
ip6tables -Z
for table in $(</proc/net/ip6_tables_names)
do
	ip6tables -t $table -F
	ip6tables -t $table -X
	ip6tables -t $table -Z
done
ip6tables -P INPUT ACCEPT
ip6tables -P OUTPUT ACCEPT
ip6tables -P FORWARD ACCEPT
```

```
vi /etc/systemd/system/iptables.service
```
```config
[Unit]
Description=Packet Filtering Framework
DefaultDependencies=no
After=systemd-sysctl.service
Before=sysinit.target
[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/iptables.rules
ExecReload=/sbin/iptables-restore /etc/iptables/iptables.rules
ExecStop=/etc/iptables/flush-iptables.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
```

```
vi /etc/systemd/system/ip6tables.service
```
```config
[Unit]
Description=Packet Filtering Framework
DefaultDependencies=no
After=systemd-sysctl.service
Before=sysinit.target
[Service]
Type=oneshot
ExecStart=/sbin/ip6tables-restore /etc/iptables/ip6tables.rules
ExecReload=/sbin/ip6tables-restore /etc/iptables/ip6tables.rules
ExecStop=/etc/iptables/flush-ip6tables.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
```

```
systemctl daemon-reload

systemctl enable iptables.service
systemctl enable ip6tables.service

systemctl start iptables.service
systemctl start ip6tables.service
```
