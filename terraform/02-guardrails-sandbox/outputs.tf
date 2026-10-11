output "vpc_id" {
  description = "ID of vuln-lab-vpc."
  value       = aws_vpc.lab.id
}

output "private_subnet_id" {
  description = "ID of the single private subnet."
  value       = aws_subnet.private.id
}

output "route_table_id" {
  description = "ID of the private route table (local + S3 gateway endpoint routes only)."
  value       = aws_route_table.private.id
}

output "endpoint_security_group_id" {
  description = "ID of the security group attached to the SSM interface endpoints."
  value       = aws_security_group.endpoints.id
}

output "availability_zone" {
  description = "AZ the private subnet and interface endpoints live in."
  value       = aws_subnet.private.availability_zone
}
