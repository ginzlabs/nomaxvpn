terraform {
  required_version = ">= 1.8"
  required_providers {
    upcloud = {
      source  = "UpCloudLtd/upcloud"
      version = "~> 5.49"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

# Credentials come from UPCLOUD_TOKEN and CLOUDFLARE_API_TOKEN (cmd/ops exports them from _cert/nomax.env).
provider "upcloud" {}
provider "cloudflare" {}

variable "domain" { type = string }
variable "zone" { type = string }
variable "plan" { type = string }
variable "cloudflare_zone_id" { type = string }
variable "ssh_public_key" { type = string }
variable "template" {
  type    = string
  default = "01000000-0000-4000-8000-000020080100" # Debian GNU/Linux 13 (Trixie)
}

resource "upcloud_server" "nomax" {
  hostname = replace(var.domain, ".", "-")
  zone     = var.zone
  plan     = var.plan
  metadata = true
  firewall = false # nftables on the host

  template {
    storage = var.template
    size    = 10
  }

  network_interface {
    type              = "public"
    ip_address_family = "IPv4"
  }

  network_interface {
    type              = "public"
    ip_address_family = "IPv6"
  }

  login {
    keys              = [var.ssh_public_key]
    create_password   = false
    password_delivery = "none"
  }

  labels = { app = "nomax" }
}

locals {
  ipv4 = one([for n in upcloud_server.nomax.network_interface : n.ip_address if n.ip_address_family == "IPv4"])
  ipv6 = one([for n in upcloud_server.nomax.network_interface : n.ip_address if n.ip_address_family == "IPv6"])
}

resource "cloudflare_dns_record" "a" {
  zone_id = var.cloudflare_zone_id
  name    = var.domain
  type    = "A"
  content = local.ipv4
  ttl     = 60
  proxied = false
}

resource "cloudflare_dns_record" "aaaa" {
  zone_id = var.cloudflare_zone_id
  name    = var.domain
  type    = "AAAA"
  content = local.ipv6
  ttl     = 60
  proxied = false
}

# IKEv2 clients connect here: iOS tries IPv6 first and, when that path drops
# IKE, waits 30 seconds before IPv4. NAT64 networks still synthesize an AAAA.
resource "cloudflare_dns_record" "v4" {
  zone_id = var.cloudflare_zone_id
  name    = "v4.${var.domain}"
  type    = "A"
  content = local.ipv4
  ttl     = 60
  proxied = false
}

# OpenConnect clients connect here; nomax tells its TLS apart by this name.
resource "cloudflare_dns_record" "vpn" {
  zone_id = var.cloudflare_zone_id
  name    = "m.${var.domain}"
  type    = "A"
  content = local.ipv4
  ttl     = 60
  proxied = false
}

resource "cloudflare_dns_record" "vpn6" {
  zone_id = var.cloudflare_zone_id
  name    = "m.${var.domain}"
  type    = "AAAA"
  content = local.ipv6
  ttl     = 60
  proxied = false
}

# The website through Cloudflare's proxy, for networks that block the server's
# own address. Tunnels can't use it, so the names above stay unproxied.
resource "cloudflare_dns_record" "web" {
  zone_id = var.cloudflare_zone_id
  name    = "web.${var.domain}"
  type    = "A"
  content = local.ipv4
  ttl     = 1
  proxied = true
}

resource "cloudflare_dns_record" "web6" {
  zone_id = var.cloudflare_zone_id
  name    = "web.${var.domain}"
  type    = "AAAA"
  content = local.ipv6
  ttl     = 1
  proxied = true
}

output "ipv4" { value = local.ipv4 }
output "ipv6" { value = local.ipv6 }
