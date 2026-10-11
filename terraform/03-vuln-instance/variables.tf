variable "sandbox_profile" {
  description = "AWS CLI named profile for the Sandbox member account."
  type        = string
  default     = "sandbox-tf"
}

variable "region" {
  description = "Region for the lab. Must match the region allowed by the vuln-lab-containment SCP."
  type        = string
  default     = "us-east-1"
}
