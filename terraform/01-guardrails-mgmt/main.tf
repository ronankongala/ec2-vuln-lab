locals {
  common_tags = {
    Project = "ec2-vuln-lab"
    Purpose = "intentionally-vulnerable-lab"
  }
}

# Containment SCP for the intentionally vulnerable lab.
# Blocks every path to the internet / out of the account, but deliberately does
# NOT restrict security group ingress (wide-open SGs are intended findings).
resource "aws_organizations_policy" "vuln_lab_containment" {
  name        = "vuln-lab-containment"
  description = "Contains the ec2-vuln-lab: no public IPs, no internet/NAT/peering paths, no public snapshot/AMI sharing, single region."
  type        = "SERVICE_CONTROL_POLICY"

  content = templatefile("${path.module}/scp-vuln-lab-containment.json.tftpl", {
    allowed_region = var.region
  })
}

# Attached to the Sandbox account only (not an OU, not the root).
resource "aws_organizations_policy_attachment" "sandbox" {
  policy_id = aws_organizations_policy.vuln_lab_containment.id
  target_id = var.sandbox_account_id
}
