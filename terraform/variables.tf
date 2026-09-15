variable "resource_group_name" {
  description = "Name of the resource group for the detection lab."
  type        = string
  default     = "rg-detection-lab"
}

variable "location" {
  description = "Azure region for all resources."
  type        = string
  default     = "uksouth"
}

variable "workspace_name" {
  description = "Log Analytics workspace name."
  type        = string
  default     = "law-detection-lab"
}

variable "log_retention_days" {
  description = "Log Analytics workspace retention, in days."
  type        = number
  default     = 90
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default = {
    project = "cloud-detection-lab"
    purpose = "portfolio-evidence"
  }
}
