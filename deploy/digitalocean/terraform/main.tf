# Terraform configuration for ant-quic Digital Ocean deployment

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

# Configure the Digital Ocean Provider
provider "digitalocean" {
  token = var.do_token
}

# Variables
variable "do_token" {
  description = "Digital Ocean API token"
  type        = string
  sensitive   = true
}

variable "region" {
  description = "DO region for deployment"
  type        = string
  default     = "nyc3"
}

variable "droplet_size" {
  description = "Size of the droplet"
  type        = string
  default     = "s-2vcpu-4gb"
}

variable "ssh_keys" {
  description = "SSH key fingerprints for access"
  type        = list(string)
  default     = []
}

# Create a new SSH key
resource "digitalocean_ssh_key" "ant_quic" {
  name       = "ant-quic-test-key"
  public_key = file("~/.ssh/ant-quic-do.pub")
}

# Create the droplet
resource "digitalocean_droplet" "ant_quic_test" {
  name     = "ant-quic-test-node"
  region   = var.region
  size     = var.droplet_size
  image    = "ubuntu-22-04-x64"
  
  ssh_keys = concat([digitalocean_ssh_key.ant_quic.fingerprint], var.ssh_keys)
  
  # Enable monitoring
  monitoring = true
  
  # Enable IPv6
  ipv6 = true
  
  # User data script for initial setup
  user_data = file("${path.module}/user-data.sh")
  
  tags = ["ant-quic", "test-node", "quic"]
}

# Create a firewall for QUIC
resource "digitalocean_firewall" "ant_quic" {
  name = "ant-quic-firewall"
  
  droplet_ids = [digitalocean_droplet.ant_quic_test.id]
  
  # Allow SSH
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  
  # Allow QUIC (UDP)
  inbound_rule {
    protocol         = "udp"
    port_range       = "9000-9010"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  
  # Allow HTTP/HTTPS for monitoring dashboard
  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  
  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  
  # Allow all outbound traffic
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  
  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  
  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# Create a floating IP
resource "digitalocean_floating_ip" "ant_quic" {
  region = var.region
}

# Assign the floating IP to the droplet
resource "digitalocean_floating_ip_assignment" "ant_quic" {
  ip_address = digitalocean_floating_ip.ant_quic.ip_address
  droplet_id = digitalocean_droplet.ant_quic_test.id
}

# Create a domain record for the test node
resource "digitalocean_domain" "ant_quic" {
  name = "ant-quic-test.example.com"  # Replace with actual domain
}

resource "digitalocean_record" "ant_quic_a" {
  domain = digitalocean_domain.ant_quic.id
  type   = "A"
  name   = "@"
  value  = digitalocean_floating_ip.ant_quic.ip_address
  ttl    = 300
}

resource "digitalocean_record" "ant_quic_aaaa" {
  domain = digitalocean_domain.ant_quic.id
  type   = "AAAA"
  name   = "@"
  value  = digitalocean_droplet.ant_quic_test.ipv6_address
  ttl    = 300
}

# Outputs
output "droplet_ip" {
  value = digitalocean_droplet.ant_quic_test.ipv4_address
}

output "floating_ip" {
  value = digitalocean_floating_ip.ant_quic.ip_address
}

output "ipv6_address" {
  value = digitalocean_droplet.ant_quic_test.ipv6_address
}

output "droplet_id" {
  value = digitalocean_droplet.ant_quic_test.id
}