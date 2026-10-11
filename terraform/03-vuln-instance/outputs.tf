output "instance_id" {
  description = "ID of the vulnerable lab target instance."
  value       = aws_instance.target.id
}

output "private_ip" {
  description = "Private IP of the vulnerable lab target instance."
  value       = aws_instance.target.private_ip
}

output "security_group_id" {
  description = "ID of vuln-lab-target-sg."
  value       = aws_security_group.target.id
}

output "instance_role_name" {
  description = "Name of the IAM role attached to the instance."
  value       = aws_iam_role.target.name
}

output "ebs_default_encryption_enabled" {
  description = "Whether account-level EBS default encryption is on. If true, it overrides encrypted = false and CLD-05 won't reproduce."
  value       = data.aws_ebs_encryption_by_default.current.enabled
}
