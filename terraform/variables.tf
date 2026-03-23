variable "resource_group_name" {
  description = "Name of the Azure resource group"
  type        = string
  default     = "sentinel-security-rg"
}

variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "East US"
}

variable "prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "secauto"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "dev"
}

variable "tenant_id" {
  description = "Azure Active Directory tenant ID"
  type        = string
  sensitive   = true
}
