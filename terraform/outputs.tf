output "resource_group_name" {
  description = "Name of the created resource group"
  value       = azurerm_resource_group.sentinel_rg.name
}

output "log_analytics_workspace_id" {
  description = "Log Analytics Workspace ID for Sentinel"
  value       = azurerm_log_analytics_workspace.sentinel_workspace.id
}

output "key_vault_uri" {
  description = "URI of the Key Vault"
  value       = azurerm_key_vault.sentinel_kv.vault_uri
}

output "servicebus_namespace" {
  description = "Service Bus namespace name"
  value       = azurerm_servicebus_namespace.sentinel_sb.name
}

output "findings_storage_account" {
  description = "Storage account name for findings archive"
  value       = azurerm_storage_account.findings_store.name
}
