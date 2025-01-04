data "azurerm_client_config" "current" {}

resource "azapi_resource" "storage_account" {
  type      = "Microsoft.Storage/storageAccounts@2023-05-01"
  name      = var.name
  location  = var.location
  parent_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${var.resource_group_name}"

  body = {
    # TODO figure out what this should look like
    # extendedLocation = {
    #   name = var.edge_zone
    #   type = "EdgeZone"
    # }
    sku = {
      name = "${var.account_tier}_${var.account_replication_type}"
    }
    kind = var.account_kind

    identity = (var.managed_identities.system_assigned || length(var.managed_identities.user_assigned_resource_ids) > 0) ? {
      type = var.managed_identities.system_assigned && length(var.managed_identities.user_assigned_resource_ids) > 0 ? "SystemAssigned,UserAssigned" : length(var.managed_identities.user_assigned_resource_ids) > 0 ? "UserAssigned" : "SystemAssigned"
      userAssignedIdentities = length(var.managed_identities.user_assigned_resource_ids) > 0 ? {
        for id in var.managed_identities.user_assigned_resource_ids : id => {}
      } : null
    } : null

    properties = {
      accessTier                   = var.account_kind == "BlockBlobStorage" && var.account_tier == "Premium" ? null : var.access_tier
      allowBlobPublicAccess        = var.allow_nested_items_to_be_public
      allowedCopyScope             = var.allowed_copy_scope
      allowCrossTenantReplication  = var.cross_tenant_replication_enabled
      defaultToOAuthAuthentication = var.default_to_oauth_authentication
      supportsHttpsTrafficOnly     = var.https_traffic_only_enabled
      isHnsEnabled                 = var.is_hns_enabled
      largeFileSharesState         = var.large_file_share_enabled ? "Enabled" : "Disabled"
      minimumTlsVersion            = var.min_tls_version
      isNfsV3Enabled               = var.nfsv3_enabled
      publicNetworkAccess          = var.public_network_access_enabled ? "Enabled" : "Disabled"

      isSftpEnabled        = var.sftp_enabled
      allowSharedKeyAccess = var.shared_access_key_enabled

      azureFilesIdentityBasedAuthentication = var.azure_files_authentication != null ? {
        directoryServiceOptions = try(var.azure_files_authentication.directory_type, null)
        defaultSharePermission  = try(var.azure_files_authentication.default_share_level_permission, null)
        activeDirectoryProperties = try(var.azure_files_authentication.active_directory, null) != null ? [
          for ad in var.azure_files_authentication.active_directory : {
            accountType       = "Computer" # TODO Computer is a guess - its either that or User
            azureStorageSid   = try(ad.storage_sid, null)
            domainGuid        = try(ad.domain_guid, null)
            domainName        = try(ad.domain_name, null)
            domainSid         = try(ad.domain_sid, null)
            forestName        = try(ad.forest_name, null)
            netBiosDomainName = try(ad.netbios_domain_name, null)
            samAccountName    = var.name
          }
        ] : null
      } : null

      customDomain = var.custom_domain != null ? {
        name             = var.custom_domain.name
        useSubDomainName = var.custom_domain.use_subdomain
      } : null

      encryption = var.customer_managed_key != null ? {
        identity = {
          federatedIdentityClientId = var.customer_managed_key.user_assigned_identity.resource_id != null ? var.customer_managed_key.user_assigned_identity.federated_identity_client_id : null
          userAssignedIdentity      = var.customer_managed_key.user_assigned_identity.resource_id
        }
        keySource = "Microsoft.Keyvault"
        keyvaultproperties = {
          keyname     = var.customer_managed_key.key_name
          keyvaulturi = var.customer_managed_key.key_vault_resource_id
          keyversion  = var.customer_managed_key.key_version
        }
        requireInfrastructureEncryption = var.infrastructure_encryption_enabled
        services = {
          queue = {
            enabled = var.queue_encryption_key_type != null ? true : false
            keyType = var.queue_encryption_key_type
          }
          table = {
            enabled = var.table_encryption_key_type != null ? true : false
            keyType = var.table_encryption_key_type
          }
        }
        } : {
        identity                        = null
        keySource                       = "Microsoft.Storage"
        keyvaultproperties              = null
        requireInfrastructureEncryption = null
        services = {
          queue = null
          table = null
        }
      }

      immutableStorageWithVersioning = var.immutability_policy != null ? {
        enabled = var.immutability_policy.enabled
        immutabilityPolicy = {
          allowProtectedAppendWrites            = var.immutability_policy.allow_protected_append_writes
          immutabilityPeriodSinceCreationInDays = var.immutability_policy.period_since_creation_in_days
          state                                 = var.immutability_policy.state
        }
      } : null

      networkAcls = {
        defaultAction = var.network_rules.default_action
        bypass        = join(",", var.network_rules.bypass)
        ipRules = var.network_rules.ip_rules != null ? [
          for ip_rule in var.network_rules.ip_rules : {
            action = try(ip_rule.action, "Allow")
            value  = try(ip_rule.value, ip_rule)
          }
        ] : null
        virtualNetworkRules = var.network_rules.virtual_network_subnet_ids != null ? [
          for vnet_rule in var.network_rules.virtual_network_subnet_ids : {
            action = "Allow"
            id     = vnet_rule
          }
        ] : null
      }

      routingPreference = var.routing != null ? {
        publishInternetEndpoints  = var.routing.publish_internet_endpoints
        publishMicrosoftEndpoints = var.routing.publish_microsoft_endpoints
        routingChoice             = var.routing.choice
      } : null

      sasPolicy = var.sas_policy != null ? {
        expirationAction    = var.sas_policy.expiration_action
        sasExpirationPeriod = var.sas_policy.expiration_period
      } : null

    }
  }

  lifecycle {
    precondition {
      condition     = (var.account_kind == "StorageV2" || var.account_tier == "Premium")
      error_message = "`var.customer_managed_key` can only be set when the `account_kind` is set to `StorageV2` or `account_tier` set to `Premium`, and the identity type is `UserAssigned`."
    }
  }
}

resource "azapi_update_resource" "blob_service" {
  type        = "Microsoft.Storage/storageAccounts/blobServices@2023-05-01"
  resource_id = "${azapi_resource.storage_account.id}/blobServices/default"

  body = {
    properties = {
      # TODO  "Request parameters are invalid: Change Feed."
      # changeFeed = {
      #   enabled         = try(var.blob_properties.change_feed_enabled, false)
      #   retentionInDays = try(var.blob_properties.change_feed_retention_in_days, 7)
      # }
      containerDeleteRetentionPolicy = {
        days    = try(var.blob_properties.container_delete_retention_policy.days, 7)
        enabled = true
      }
      cors = {
        corsRules = try(var.blob_properties.cors_rule, null) != null ? [
          for cors_rule in var.blob_properties.cors_rule : {
            allowedHeaders  = try(cors_rule.allowed_headers, [])
            allowedMethods  = try(cors_rule.allowed_methods, [])
            allowedOrigins  = try(cors_rule.allowed_origins, [])
            exposedHeaders  = try(cors_rule.exposed_headers, [])
            maxAgeInSeconds = try(cors_rule.max_age_in_seconds, 0)
          }
        ] : []
      }
      defaultServiceVersion = try(var.blob_properties.default_service_version, null)
      deleteRetentionPolicy = {
        allowPermanentDelete = try(var.blob_properties.delete_retention_policy.permanent_delete_enabled, false)
        days                 = try(var.blob_properties.delete_retention_policy.days, 7)
        enabled              = true
      }
      isVersioningEnabled = try(var.blob_properties.versioning_enabled, false)
      lastAccessTimeTrackingPolicy = {
        enable = try(var.blob_properties.last_access_time_enabled, false)
      }
      restorePolicy = {
        days    = try(var.blob_properties.restore_policy.days, 7)
        enabled = try(var.blob_properties.restore_policy.days, false)
      }
    }
  }
}

resource "azapi_update_resource" "file_service" {
  type        = "Microsoft.Storage/storageAccounts/fileServices@2023-05-01"
  resource_id = "${azapi_resource.storage_account.id}/fileServices/default"

  body = {
    properties = {
      cors = {
        corsRules = try(var.share_properties.cors_rule, null) != null ? [
          for cors_rule in var.share_properties.cors_rule : {
            allowedHeaders  = try(cors_rule.allowed_headers, [])
            allowedMethods  = try(cors_rule.allowed_methods, [])
            allowedOrigins  = try(cors_rule.allowed_origins, [])
            exposedHeaders  = try(cors_rule.exposed_headers, [])
            maxAgeInSeconds = try(cors_rule.max_age_in_seconds, 0)
          }
        ] : []
      }
      protocolSettings = {
        smb = {
          authenticationMethods    = try(var.share_properties.smb.authentication_types, null)
          channelEncryption        = try(var.share_properties.smb.channel_encryption_type, null)
          kerberosTicketEncryption = try(var.share_properties.smb.kerberos_ticket_encryption_type, null)
          multichannel = var.account_tier == "Premium" ? {
            enabled = try(var.share_properties.smb.multichannel_enabled, false)
          } : null
          versions = try(var.share_properties.smb.versions, null)
        }
      }
      shareDeleteRetentionPolicy = {
        days    = try(var.share_properties.retention_policy.days, 7)
        enabled = true
      }
    }
  }
}

resource "azapi_update_resource" "queue_service" {
  type        = "Microsoft.Storage/storageAccounts/queueServices@2023-05-01"
  resource_id = "${azapi_resource.storage_account.id}/queueServices/default"

  body = {
    properties = {
      cors = {
        corsRules = try(var.queue_properties.cors_rule, null) != null ? [
          for cors_rule in var.queue_properties.cors_rule : {
            allowedHeaders  = try(cors_rule.allowed_headers, [])
            allowedMethods  = try(cors_rule.allowed_methods, [])
            allowedOrigins  = try(cors_rule.allowed_origins, [])
            exposedHeaders  = try(cors_rule.exposed_headers, [])
            maxAgeInSeconds = try(cors_rule.max_age_in_seconds, 0)
          }
        ] : []
      }
      # logging = {
      #   delete              = try(var.queue_properties.logging.delete, false)
      #   read                = try(var.queue_properties.logging.read, false)
      #   version             = try(var.queue_properties.logging.version, "1.0")
      #   write               = try(var.queue_properties.logging.write, false)
      #   retentionPolicyDays = try(var.queue_properties.logging.retention_policy_days, 7)
      # }
    }
  }
}

resource "azurerm_storage_account_local_user" "this" {
  for_each = var.local_user

  name                 = each.value.name
  storage_account_id   = azapi_resource.storage_account.id
  home_directory       = each.value.home_directory
  ssh_key_enabled      = each.value.ssh_key_enabled
  ssh_password_enabled = each.value.ssh_password_enabled

  dynamic "permission_scope" {
    for_each = each.value.permission_scope == null ? [] : each.value.permission_scope

    content {
      resource_name = permission_scope.value.resource_name
      service       = permission_scope.value.service

      dynamic "permissions" {
        for_each = [permission_scope.value.permissions]

        content {
          create = permissions.value.create
          delete = permissions.value.delete
          list   = permissions.value.list
          read   = permissions.value.read
          write  = permissions.value.write
        }
      }
    }
  }
  dynamic "ssh_authorized_key" {
    for_each = each.value.ssh_authorized_key == null ? [] : each.value.ssh_authorized_key

    content {
      key         = ssh_authorized_key.value.key
      description = ssh_authorized_key.value.description
    }
  }
  dynamic "timeouts" {
    for_each = each.value.timeouts == null ? [] : [each.value.timeouts]

    content {
      create = timeouts.value.create
      delete = timeouts.value.delete
      read   = timeouts.value.read
      update = timeouts.value.update
    }
  }
}

resource "azurerm_role_assignment" "storage_account" {
  for_each = var.role_assignments

  principal_id                           = each.value.principal_id
  scope                                  = azapi_resource.storage_account.id
  condition                              = each.value.condition
  condition_version                      = each.value.condition_version
  delegated_managed_identity_resource_id = each.value.delegated_managed_identity_resource_id
  role_definition_id                     = strcontains(lower(each.value.role_definition_id_or_name), lower(local.role_definition_resource_substring)) ? each.value.role_definition_id_or_name : null
  role_definition_name                   = strcontains(lower(each.value.role_definition_id_or_name), lower(local.role_definition_resource_substring)) ? null : each.value.role_definition_id_or_name
  skip_service_principal_aad_check       = each.value.skip_service_principal_aad_check
}
