terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "~> 1.13"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {}
  # Reads the active `az login` context. Set the AZURE_SUBSCRIPTION_ID
  # env var (same one Stratus Red Team needs) or `az account set
  # --subscription <id>` before running this against the Azure for
  # Students subscription, so you don't accidentally deploy into the
  # old free-trial one.
}

provider "azapi" {}

data "azurerm_subscription" "current" {}
data "azurerm_client_config" "current" {}
