#!/bin/bash
# Relay setup, run as root by `ops relay` from the directory it uploaded.
# The relay forwards every protocol's port to the server, so apps on networks
# that block the server's address connect here instead, and it carries the
# exit route: the server's traffic for those devices comes over the
# WireGuard link (wgr) and leaves from here. It keeps no keys besides its own
# link key and no user data. Idempotent.
set -euo pipefail
cd "$(dirname "$0")"
export DEBIAN_FRONTEND=noninteractive
# SERVER4 (the server's IPv4), LINK_ADDR (this end of the link), LINK_KEY,
# SERVER_LINK_PUB, and VIA: "public" forwards to SERVER4, "link" through wgr.
source ./relay.env

PACKAGES="wireguard-tools nftables unattended-upgrades"
if ! dpkg -s $PACKAGES >/dev/null 2>&1; then
	apt-get update -q
	apt-get install -y -q --no-install-recommends $PACKAGES
fi

install -m 644 sysctl.conf /etc/sysctl.d/99-relay.conf
sysctl -q --system

install -m 644 unattended.conf /etc/apt/apt.conf.d/52relay
install -m 644 sshd.conf /etc/ssh/sshd_config.d/00-relay.conf
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
mkdir -p /etc/systemd/journald.conf.d
install -m 644 journald.conf /etc/systemd/journald.conf.d/relay.conf
systemctl restart systemd-journald

target=$SERVER4
[ "$VIA" = link ] && target=10.9.0.1

cat >/etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet relay {
	chain input {
		type filter hook input priority filter; policy drop;
		iif lo accept
		ct state established,related accept
		ct state invalid drop
		meta l4proto { icmp, ipv6-icmp } accept
		tcp dport 22 accept
		udp dport 51830 accept
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		oifname "wgr" tcp flags syn / syn,rst tcp option maxseg size set rt mtu
		iifname "wgr" tcp flags syn / syn,rst tcp option maxseg size set rt mtu
		ct state established,related accept
		ct status dnat accept
		# The exit route: the server's connections out to the internet
		iifname "wgr" ip saddr 10.9.0.1 oifname != "wgr" ip daddr != { 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } tcp dport != 25 accept
		iifname "wgr" ip saddr 10.9.0.1 oifname != "wgr" ip daddr != { 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } meta l4proto != tcp accept
	}
}

table ip relay_nat {
	# Every port the server's protocols use, as nftables.conf on the server
	# accepts them; 20000-20999 are Hysteria2 Obfs's hops.
	chain prerouting {
		type nat hook prerouting priority dstnat;
		fib daddr type local tcp dport { 443, 2053, 2083, 2096 } dnat to $target
		fib daddr type local udp dport { 443, 500, 1194, 4443, 4500, 8443, 51820, 51821, 20000-20999 } dnat to $target
	}

	chain postrouting {
		type nat hook postrouting priority srcnat;
		ip daddr $target masquerade
		ip saddr 10.9.0.1 oifname != "wgr" masquerade
	}
}
EOF
systemctl enable -q nftables
systemctl restart nftables

install -d -m 700 /etc/wireguard
umask 077
cat >/etc/wireguard/wgr.conf.new <<EOF
[Interface]
Address = $LINK_ADDR/24
ListenPort = 51830
PrivateKey = $LINK_KEY

[Peer]
PublicKey = $SERVER_LINK_PUB
AllowedIPs = 10.9.0.1/32
Endpoint = $SERVER4:51830
PersistentKeepalive = 25
EOF
if ! cmp -s /etc/wireguard/wgr.conf.new /etc/wireguard/wgr.conf; then
	mv /etc/wireguard/wgr.conf.new /etc/wireguard/wgr.conf
	systemctl enable -q wg-quick@wgr
	systemctl restart wg-quick@wgr
else
	rm /etc/wireguard/wgr.conf.new
	systemctl enable -q --now wg-quick@wgr
fi
