variable "mgmt_profile" {
  description = "AWS CLI named profile for the Organizations management account."
  type        = string
}

variable "sandbox_account_id" {
  description = "12-digit account ID of the Sandbox member account the SCP is attached to."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.sandbox_account_id))
    error_message = "sandbox_account_id must be a 12-digit AWS account ID."
  }
}

variable "region" {
  description = "The only region the Sandbox account may use (global services excepted)."
  type        = string
  default     = "us-east-1"
}
