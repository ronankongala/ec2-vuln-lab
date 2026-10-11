variable "sandbox_profile" {
  description = "AWS CLI named profile for the Sandbox member account."
  type        = string
}

variable "region" {
  description = "Region for the lab. Must match the region allowed by the vuln-lab-containment SCP."
  type        = string
  default     = "us-east-1"
}

variable "budget_limit_usd" {
  description = "Monthly cost budget limit in USD."
  type        = number
  default     = 25

  validation {
    condition     = var.budget_limit_usd > 0
    error_message = "budget_limit_usd must be greater than 0."
  }
}

variable "alert_email" {
  description = "Email address that receives budget alerts."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be a valid email address."
  }
}

variable "availability_zone" {
  description = "AZ for the single private subnet. Leave null to use the first available AZ in the region."
  type        = string
  default     = null
}
