# The 5 Sentinel Scheduled Analytics Rules, reverse-engineered from the
# ARM template exports already committed to the repo under /detections.
# Query text, severity, MITRE mapping, and entity mappings are copied
# verbatim from those JSON exports — nothing here is rewritten or
# improved on the original. Rule 1 genuinely has no entity mapping
# configured (its JSON export shows entityMappings: null); that's left
# as-is rather than "fixed" silently.

locals {
  workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
}

# 1. SAS Token Blob Read — T1530 (Collection)
resource "azurerm_sentinel_alert_rule_scheduled" "sas_token_blob_read" {
  name                       = "34ea058c-d89a-489b-9044-f853ad6e0fe8"
  log_analytics_workspace_id = local.workspace_id
  display_name               = "SAS Token Blob Read - Detection Lab"
  description                = "Detects blob reads authenticated via SAS token with no associated AAD identity (RequestObjectId empty) against the detection lab storage account."
  severity                   = "Medium"
  enabled                    = true

  query = <<-QUERY
    StorageBlobLogs
    | where OperationName in ("GetBlob", "GetBlobProperties")
    | where AuthenticationType == "SAS"
    | where isempty(RequesterObjectId)
    | project TimeGenerated, AccountName, OperationName, CallerIpAddress, UserAgentHeader, Uri
  QUERY

  query_frequency      = "PT5M"
  query_period         = "PT5M"
  trigger_operator     = "GreaterThan"
  trigger_threshold    = 0
  suppression_enabled  = false
  suppression_duration = "PT5H"

  tactics    = ["Collection"]
  techniques = ["T1530"]

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = false
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
    }
  }
}

# 2. Azure RBAC Elevate Access — T1078 (Privilege Escalation)
resource "azurerm_sentinel_alert_rule_scheduled" "rbac_elevate_access" {
  name                       = "30c9be82-5445-41ef-a0e1-2e7bdf037a55"
  log_analytics_workspace_id = local.workspace_id
  display_name               = "Azure RBAC Elevate Access - Detection Lab"
  severity                   = "High"
  enabled                    = true

  query = <<-QUERY
    AuditLogs
    | where Category =~ "AzureRBACRoleManagementElevateAccess"
    | where OperationName =~ "User has elevated their access to User Access Administrator for their Azure Resources"
    | extend Actor = tostring(InitiatedBy.user.userPrincipalName)
    | extend IPAddress = tostring(InitiatedBy.user.ipAddress)
    | project TimeGenerated, Actor, OperationName, IPAddress, Result
  QUERY

  query_frequency      = "PT5M"
  query_period         = "PT5M"
  trigger_operator     = "GreaterThan"
  trigger_threshold    = 0
  suppression_enabled  = false
  suppression_duration = "PT5H"

  tactics    = ["PrivilegeEscalation"]
  techniques = ["T1078"]

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "IPAddress"
    }
  }
  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "Actor"
    }
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = false
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
    }
  }
}

# 3. Service Principal Credential Added — T1098.001 (Persistence)
resource "azurerm_sentinel_alert_rule_scheduled" "sp_credential_added" {
  name                       = "f4278968-b068-41e1-bd85-b6bb9a67ef17"
  log_analytics_workspace_id = local.workspace_id
  display_name               = "Service Principal Credential Added - Detection Lab"
  severity                   = "Medium"
  enabled                    = true

  query = <<-QUERY
    AuditLogs
    | where Category == "ApplicationManagement"
    | where OperationName == "Add service principal credentials"
    | extend Actor = tostring(InitiatedBy.user.userPrincipalName)
    | extend IPAddress = tostring(InitiatedBy.user.ipAddress)
    | project TimeGenerated, Actor, OperationName, IPAddress, Result
  QUERY

  query_frequency      = "PT5M"
  query_period         = "PT5M"
  trigger_operator     = "GreaterThan"
  trigger_threshold    = 0
  suppression_enabled  = false
  suppression_duration = "PT5H"

  tactics    = ["Persistence"]
  techniques = ["T1098"] # base technique only, API rejects subtechnique format

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "Actor"
    }
  }
  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "IPAddress"
    }
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = false
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
    }
  }
}

# 4. Diagnostic Setting Deleted — T1562.008 (Defense Evasion)
resource "azurerm_sentinel_alert_rule_scheduled" "diagnostic_setting_deleted" {
  name                       = "bd4bf46d-cce6-40da-8171-8774e1bf944a"
  log_analytics_workspace_id = local.workspace_id
  display_name               = "Diagnostic Setting Deleted - Detection Lab"
  description                = "Detects deletion of an Azure Activity Log diagnostic setting (MITRE T1562.008 - Impair Defenses: Disable Cloud Logs"
  severity                   = "Medium"
  enabled                    = true

  query = <<-QUERY
    AzureActivity
    | where OperationNameValue =~ "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE"
    | where ActivityStatusValue == "Success"
    | extend Actor = tostring(Caller)
    | extend IPAddress = tostring(CallerIpAddress)
    | project TimeGenerated, Actor, IPAddress, OperationNameValue, ActivityStatusValue
  QUERY

  query_frequency      = "PT5M"
  query_period         = "PT5M"
  trigger_operator     = "GreaterThan"
  trigger_threshold    = 0
  suppression_enabled  = false
  suppression_duration = "PT5H"

  tactics    = ["DefenseEvasion"]
  techniques = ["T1562"] # base technique only, API rejects subtechnique format

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "Actor"
    }
  }
  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "IPAddress"
    }
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = false
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
    }
  }
}

# 5. Unusual Region Sign-In with Legacy Auth — T1078 (Initial Access)
# Schema-built, not attack-validated — see docs/day08-disabled-diagnostic-logging.md.
resource "azurerm_sentinel_alert_rule_scheduled" "unusual_region_legacy_auth" {
  name                       = "a2a367fc-a85a-442e-8aa4-f7ba3725d4bf"
  log_analytics_workspace_id = local.workspace_id
  display_name               = "Unusual Region Sign-In with Legacy Auth - Detection Lab"
  description                = "Detects successful sign-ins using legacy (pre-MFA-capable) authentication protocols from outside the expected country. Schema-built and syntax-validated against real sign-in data; not attack-validated (no real legacy-auth sign-in was performed, to avoid flagging the live account)."
  severity                   = "Medium"
  enabled                    = true

  query = <<-QUERY
    SigninLogs
    | where ResultType == "0"
    | where ClientAppUsed in ("Exchange ActiveSync", "Authenticated SMTP", "IMAP4", "IMAP", "MAPI Over HTTP", "Offline Address Book", "Outlook Anywhere (RPC over HTTP)", "POP3", "POP", "Reporting Web Services", "Exchange Web Services", "Other clients")
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | where Country != "GB"
    | project TimeGenerated, UserPrincipalName, AppDisplayName, ClientAppUsed, Country, IPAddress, ResultType
  QUERY

  query_frequency      = "PT5M"
  query_period         = "PT5M"
  trigger_operator     = "GreaterThan"
  trigger_threshold    = 0
  suppression_enabled  = false
  suppression_duration = "PT5H"

  tactics    = ["InitialAccess"]
  techniques = ["T1078"]

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "IPAddress"
    }
  }
  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "UserPrincipalName"
    }
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = false
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
    }
  }
}
