terraform {
  required_version = ">= 1.4.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
  }
}

provider "azurerm" {
  features {}
}

############################################
# RESOURCE GROUP
############################################
resource "azurerm_resource_group" "sentinel_rg" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    Environment = var.environment
    Project     = "azure-sentinel-security-automation"
    Owner       = "Oluwafemi Okunlola"
  }
}

############################################
# LOG ANALYTICS WORKSPACE (Sentinel backend)
############################################
resource "azurerm_log_analytics_workspace" "sentinel_workspace" {
  name                = "${var.prefix}-sentinel-workspace"
  location            = azurerm_resource_group.sentinel_rg.location
  resource_group_name = azurerm_resource_group.sentinel_rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 90

  tags = azurerm_resource_group.sentinel_rg.tags
}

############################################
# MICROSOFT SENTINEL
############################################
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id = azurerm_log_analytics_workspace.sentinel_workspace.id
}

############################################
# KEY VAULT (secrets storage)
############################################
resource "azurerm_key_vault" "sentinel_kv" {
  name                        = "${var.prefix}-sentinel-kv"
  location                    = azurerm_resource_group.sentinel_rg.location
  resource_group_name         = azurerm_resource_group.sentinel_rg.name
  sku_name                    = "standard"
  tenant_id                   = var.tenant_id
  purge_protection_enabled    = true
  soft_delete_retention_days  = 90
  enable_rbac_authorization   = true

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }

  tags = azurerm_resource_group.sentinel_rg.tags
}

############################################
# SERVICE BUS (alert routing)
############################################
resource "azurerm_servicebus_namespace" "sentinel_sb" {
  name                = "${var.prefix}-sentinel-sb"
  location            = azurerm_resource_group.sentinel_rg.location
  resource_group_name = azurerm_resource_group.sentinel_rg.name
  sku                 = "Standard"

  tags = azurerm_resource_group.sentinel_rg.tags
}

resource "azurerm_servicebus_queue" "high_risk_alerts" {
  name         = "high-risk-alerts"
  namespace_id = azurerm_servicebus_namespace.sentinel_sb.id

  enable_partitioning   = true
  max_delivery_count    = 5
  lock_duration         = "PT5M"
}

############################################
# STORAGE ACCOUNT (findings archive)
############################################
resource "azurerm_storage_account" "findings_store" {
  name                     = "${var.prefix}findings"
  resource_group_name      = azurerm_resource_group.sentinel_rg.name
  location                 = azurerm_resource_group.sentinel_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  blob_properties {
    versioning_enabled = true
  }

  tags = azurerm_resource_group.sentinel_rg.tags
}
