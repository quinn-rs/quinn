#!/bin/bash
# Terraform Environment Setup for saorsa-infra
# Source this file before running terraform:
#   source scripts/terraform-env.sh
#   cd ../saorsa-infra/terraform && terraform plan

# Map API keys to Terraform variables
export TF_VAR_do_token="${DIGITALOCEAN_API_TOKEN}"
export TF_VAR_hetzner_token="${HETZNER_API_KEY}"
export TF_VAR_vultr_token="${VULTR_API_TOKEN:-}"

# Verify tokens
echo "Terraform environment:"
[ -n "$TF_VAR_do_token" ] && echo "  ✓ DO" || echo "  ✗ DO (set DIGITALOCEAN_API_TOKEN)"
[ -n "$TF_VAR_hetzner_token" ] && echo "  ✓ HZ" || echo "  ✗ HZ (set HETZNER_API_KEY)"
[ -n "$TF_VAR_vultr_token" ] && echo "  ✓ VT" || echo "  ○ VT (optional)"
