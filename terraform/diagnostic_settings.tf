# Three log sources feed law-detection-lab. Same three as the original
# lab: subscription Activity Log, tenant-wide Entra ID sign-in/audit
# logs, and this storage account's blob service logs.

# --- AzureActivity (subscription-level) --------------------------------
# The azurerm provider has no dedicated resource for subscription-scope
# Activity Log diagnostic settings (tracked upstream, never shipped —
# see hashicorp/terraform-provider-azurerm#11005), so this goes through
# the generic ARM resource provider instead. Functionally identical to
# `az monitor diagnostic-settings subscription create`.
resource "azapi_resource" "activity_log_to_law" {
  type      = "Microsoft.Insights/diagnosticSettings@2021-05-01-preview"
  name      = "activity-to-law"
  parent_id = data.azurerm_subscription.current.id

  body = {
    properties = {
      workspaceId = azurerm_log_analytics_workspace.law.id
      logs = [
        for category in [
          "Administrative", "Security", "ServiceHealth", "Alert",
          "Recommendation", "Policy", "Autoscale", "ResourceHealth"
        ] : {
          category = category
          enabled  = true
        }
      ]
    }
  }
}

# --- Entra ID sign-in / audit logs (tenant-level) -----------------------
# Tenant-scoped, not subscription-scoped — this exports the whole
# directory's sign-ins regardless of which subscription the workspace
# lives in. Named distinctly so it sits alongside the original lab's
# `entra-to-law` setting rather than colliding with it, if that lab is
# still running in the same tenant.
#
# Reminder from the original lab: SigninLogs export needs a completed
# Entra P1/P2 licence to be fully reliable. Azure for Students credit
# explicitly excludes Entra ID Premium, so that licensing gap is not
# solved by moving subscriptions — same open item either way.

# --- StorageBlobLogs (resource-level) -----------------------------------
# Closes the same control-plane-only gap documented in Day 06: AzureActivity
# never sees data-plane blob reads, so the SAS-token detection needs this
# resource-level setting on the storage account's blob service specifically.
resource "azurerm_monitor_diagnostic_setting" "blob_to_law" {
  name                       = "blob-to-law"
  target_resource_id         = "${azurerm_storage_account.lab.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id

  enabled_log {
    category_group = "allLogs"
  }
}
