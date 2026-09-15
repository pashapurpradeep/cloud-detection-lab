output "resource_group_name" {
  value = azurerm_resource_group.lab.name
}

output "workspace_name" {
  value = azurerm_log_analytics_workspace.law.name
}

output "workspace_customer_id" {
  value = azurerm_log_analytics_workspace.law.workspace_id
}

output "storage_account_name" {
  value       = azurerm_storage_account.lab.name
  description = "Use this for the SAS-token re-detonation (Stratus Red Team's azure.exfiltration.storage-sas-export needs a container to target — testdata container is pre-created)."
}

output "subscription_id" {
  value = data.azurerm_subscription.current.subscription_id
}
