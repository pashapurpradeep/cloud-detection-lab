# Core lab infrastructure: resource group, Log Analytics workspace,
# Sentinel onboarding, and a storage account for the SAS-token
# blob-read technique (Day 06 / T1530).

resource "azurerm_resource_group" "lab" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

resource "azurerm_log_analytics_workspace" "law" {
  name                = var.workspace_name
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = var.tags
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id = azurerm_log_analytics_workspace.law.id
}

# Globally-unique suffix for the storage account name (storage account
# names must be unique across all of Azure, not just this subscription).
resource "random_string" "storage_suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "azurerm_storage_account" "lab" {
  name                     = "detectionlab${random_string.storage_suffix.result}"
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = azurerm_resource_group.lab.location
  account_tier             = "Standard"
  account_kind             = "StorageV2"
  account_replication_type = "LRS"
  tags                     = var.tags
}

resource "azurerm_storage_container" "testdata" {
  name                  = "testdata"
  storage_account_id    = azurerm_storage_account.lab.id
  container_access_type = "private"
}
