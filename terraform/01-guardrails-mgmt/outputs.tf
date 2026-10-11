output "scp_id" {
  description = "ID of the vuln-lab-containment SCP."
  value       = aws_organizations_policy.vuln_lab_containment.id
}
