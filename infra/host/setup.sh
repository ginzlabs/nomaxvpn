#!/bin/bash
# Idempotent host setup, run as root by `ops deploy` from the directory it uploaded.
set -euo pipefail
cd "$(dirname "$0")"
export DEBIAN_FRONTEND=noninteractive

PACKAGES="wireguard-tools nftables unattended-upgrades openvpn ocserv charon-systemd strongswan-swanctl
	libcharon-extauth-plugins libcharon-extra-plugins libstrongswan-standard-plugins"
if ! dpkg -s $PACKAGES >/dev/null 2>&1; then
	apt-get update -q
	apt-get install -y -q --no-install-recommends $PACKAGES
fi

if [ ! -f /swapfile ]; then
	fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null
	grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >>/etc/fstab
	swapon /swapfile
fi

install -m 644 sysctl.conf /etc/sysctl.d/99-nomax.conf
sysctl -q --system

install -m 755 nftables.conf /etc/nftables.conf
systemctl enable -q nftables
systemctl restart nftables

install -m 644 unattended.conf /etc/apt/apt.conf.d/52nomax
install -m 644 sshd.conf /etc/ssh/sshd_config.d/nomax.conf
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
mkdir -p /etc/systemd/journald.conf.d
install -m 644 journald.conf /etc/systemd/journald.conf.d/nomax.conf
systemctl restart systemd-journald

install -d -m 700 /etc/wireguard
install -m 600 wg0.conf /etc/wireguard/wg0.conf
systemctl enable -q wg-quick@wg0
systemctl is-active -q wg-quick@wg0 || systemctl start wg-quick@wg0

# The link to the relays (ops writes wgr.conf when RELAYS is set)
if [ -f wgr.conf ]; then
	if ! cmp -s wgr.conf /etc/wireguard/wgr.conf; then
		install -m 600 wgr.conf /etc/wireguard/wgr.conf
		systemctl enable -q wg-quick@wgr
		systemctl restart wg-quick@wgr
	else
		systemctl enable -q --now wg-quick@wgr
	fi
elif [ -f /etc/wireguard/wgr.conf ]; then
	systemctl disable -q --now wg-quick@wgr || true
	rm -f /etc/wireguard/wgr.conf
fi

id nomax >/dev/null 2>&1 || useradd --system --home-dir /var/lib/nomax --shell /usr/sbin/nologin nomax
install -d -m 750 -g nomax /etc/nomax
install -m 640 -g nomax nomax.env /etc/nomax/nomax.env
install -d -m 700 -o nomax -g nomax /var/lib/nomax

if [ -f state.tgz ] && [ ! -f /var/lib/nomax/nomax.db ]; then
	tar -xzf state.tgz -C /var/lib/nomax
	for f in /var/lib/nomax/ginzi.db*; do [ -e "$f" ] && mv "$f" "${f/ginzi.db/nomax.db}"; done
	chown -R nomax:nomax /var/lib/nomax
fi

install -d /etc/systemd/system/strongswan.service.d
if ! cmp -s strongswan.conf /etc/systemd/system/strongswan.service.d/nomax.conf; then
	install -m 644 strongswan.conf /etc/systemd/system/strongswan.service.d/nomax.conf
	systemctl daemon-reload
	systemctl enable -q strongswan
	systemctl restart strongswan
fi

install -d -m 700 -o nomax -g nomax /var/lib/nomax/ocserv
install -D -m 755 nomax-occtl /usr/local/libexec/nomax-occtl
install -m 644 nomax-occtl.socket nomax-occtl@.service /etc/systemd/system/
install -d /etc/systemd/system/ocserv.service.d
install -m 644 ocserv.override.conf /etc/systemd/system/ocserv.service.d/nomax.conf
ocserv_changed=
cmp -s ocserv.conf /etc/ocserv/ocserv.conf || ocserv_changed=1
install -m 644 ocserv.conf /etc/ocserv/ocserv.conf
systemctl daemon-reload
systemctl enable -q --now nomax-occtl.socket
systemctl enable -q ocserv
if [ -n "$ocserv_changed" ]; then systemctl restart ocserv; else systemctl start ocserv; fi

install -m 755 nomax /usr/local/bin/nomax.new
mv /usr/local/bin/nomax.new /usr/local/bin/nomax
install -m 644 nomax.service /etc/systemd/system/nomax.service
systemctl daemon-reload
systemctl enable -q nomax
systemctl restart nomax
