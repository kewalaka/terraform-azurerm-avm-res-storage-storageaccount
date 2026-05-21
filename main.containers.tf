module "containers" {
  source   = "./modules/container"
  for_each = var.containers

  name                                        = each.value.name
  storage_account_id                          = azapi_resource.this.id
  container_immutability_policy_resource_type = var.resource_types.container_immutability_policy
  default_encryption_scope                    = each.value.default_encryption_scope
  deny_encryption_scope_override              = each.value.deny_encryption_scope_override
  enable_nfs_v3_all_squash                    = each.value.enable_nfs_v3_all_squash
  enable_nfs_v3_root_squash                   = each.value.enable_nfs_v3_root_squash
  immutability_policy                         = each.value.immutability_policy
  immutable_storage_with_versioning           = each.value.immutable_storage_with_versioning
  legal_hold                                  = each.value.legal_hold
  metadata                                    = each.value.metadata
  public_access                               = each.value.public_access
  resource_type                               = var.resource_types.blob_container
  retry                                       = var.retry
  role_assignment_definition_lookup_enabled   = var.role_assignment_definition_lookup_enabled
  role_assignments                            = each.value.role_assignments
  timeouts                                    = each.value.timeouts != null ? each.value.timeouts : var.timeouts
  tracing_tags_header                         = var.enable_telemetry ? local.avm_azapi_header : null
}
