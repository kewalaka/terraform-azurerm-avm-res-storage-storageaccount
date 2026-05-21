# NOTE: var.blob_properties (blob service-level versioning, change feed,
# CORS, retention policies) was removed in v1.0.0 (azapi rewrite). Configure
# those settings directly via
# Microsoft.Storage/storageAccounts/blobServices@2024-01-01 if needed; this
# module no longer exposes them.

variable "containers" {
  type = map(object({
    public_access                  = optional(string, "None")
    metadata                       = optional(map(string))
    name                           = string
    default_encryption_scope       = optional(string)
    deny_encryption_scope_override = optional(bool)
    enable_nfs_v3_all_squash       = optional(bool)
    enable_nfs_v3_root_squash      = optional(bool)
    immutable_storage_with_versioning = optional(object({
      enabled = bool
    }))
    immutability_policy = optional(object({
      allow_protected_append_writes     = optional(bool)
      allow_protected_append_writes_all = optional(bool)
      period_since_creation_in_days     = number
      state                             = optional(string, "Unlocked")
    }))
    legal_hold = optional(object({
      tags = list(string)
    }))

    role_assignments = optional(map(object({
      role_definition_id_or_name             = string
      principal_id                           = string
      principal_type                         = optional(string, null)
      description                            = optional(string, null)
      skip_service_principal_aad_check       = optional(bool, false)
      condition                              = optional(string, null)
      condition_version                      = optional(string, null)
      delegated_managed_identity_resource_id = optional(string, null)
    })), {})

    timeouts = optional(object({
      create = optional(string)
      delete = optional(string)
      read   = optional(string)
      update = optional(string)
    }))
  }))
  default     = {}
  description = <<-EOT
A map of containers to create on the storage account. The map key is arbitrary; the value supports the following attributes. Defaults to `{}` (no containers).

- `name` - (Required) The name of the Container which should be created within the Storage Account. Changing this forces a new resource to be created.
- `public_access` - (Optional) Specifies whether data in the container may be accessed publicly and the level of access. Possible values are `Container`, `Blob`, and `None`. Defaults to `None`. Changing this forces a new resource to be created.
- `metadata` - (Optional) A mapping of MetaData for this Container. All metadata keys should be lowercase. Defaults to `null`.
- `default_encryption_scope` - (Optional) The default encryption scope to use for blob operations on this container. Defaults to `null`.
- `deny_encryption_scope_override` - (Optional) When set to `true`, blocks blob uploads from specifying a different encryption scope. Defaults to `null`.
- `enable_nfs_v3_all_squash` - (Optional) Enable NFSv3 all squash (only valid for NFSv3 enabled accounts). Defaults to `null`.
- `enable_nfs_v3_root_squash` - (Optional) Enable NFSv3 root squash (only valid for NFSv3 enabled accounts). Defaults to `null`.
- `immutable_storage_with_versioning` - (Optional) Configures container-level immutability with version-level WORM. Defaults to `null`. Supports:
  - `enabled` - (Required) Whether immutable storage with versioning is enabled.
- `immutability_policy` - (Optional) A time-based immutability policy for the container. Defaults to `null`.
  - `period_since_creation_in_days` - (Required) The immutability period in days.
  - `state` - (Optional) Policy state. `Unlocked` (default, allows increases/decreases) or `Locked` (allows only increases, irreversible).
  - `allow_protected_append_writes` - (Optional) Allow new blocks to be written to append blobs. Defaults to `null`.
  - `allow_protected_append_writes_all` - (Optional) Allow new blocks to be written to both block and append blobs. Defaults to `null`.
- `legal_hold` - (Optional) A legal hold for the container. Defaults to `null`.
  - `tags` - (Required) A list of legal hold tags. Each tag must be alphanumeric, 3–23 chars.
  > **Note:** Legal hold is applied via a `setLegalHold` POST action. Removing `legal_hold` from configuration does NOT automatically call `clearLegalHold` — clearing requires manual intervention.
- `role_assignments` - (Optional) A map of role assignments to create on the container. Defaults to `{}`. Each entry supports:
  - `role_definition_id_or_name` - (Required) The role definition ID or name.
  - `principal_id` - (Required) The principal ID to assign the role to.
  - `description` - (Optional) Description of the role assignment.
  - `skip_service_principal_aad_check` - (Optional) Skip the Azure Active Directory check for service principals. Defaults to `false`.
  - `condition` - (Optional) The condition expression limiting the resources the role can be assigned to.
  - `condition_version` - (Optional) The condition version.
  - `delegated_managed_identity_resource_id` - (Optional) The delegated Azure Resource Id containing a Managed Identity.
  - `principal_type` - (Optional) The type of principal (`User`, `Group`, `ServicePrincipal`).
- `timeouts` - (Optional) Per-operation timeouts for the container resource. Defaults to `null` (uses provider defaults inherited from `var.timeouts`). Supports:
  - `create` - (Optional) Timeout for create operations. Defaults to 30 minutes.
  - `delete` - (Optional) Timeout for delete operations. Defaults to 30 minutes.
  - `read` - (Optional) Timeout for read operations. Defaults to 5 minutes.
  - `update` - (Optional) Timeout for update operations. Defaults to 30 minutes.

Example:

```terraform
containers = {
  compliance = {
    name          = "compliance-data"
    public_access = "None"
    immutability_policy = {
      period_since_creation_in_days = 30
      state                         = "Unlocked"
    }
  }
  legal = {
    name = "legal-evidence"
    legal_hold = {
      tags = ["case2024", "audithold"]
    }
  }
}
```
EOT
  nullable    = false
}

variable "immutability_policy" {
  type = object({
    allow_protected_append_writes = bool
    period_since_creation_in_days = number
    state                         = string
  })
  default     = null
  description = <<-EOT
Configures the account-level immutability policy. Defaults to `null` (no policy).

- `allow_protected_append_writes` - (Required) When enabled, new blocks can be written to an append blob while maintaining immutability protection and compliance. Only new blocks can be added; any existing blocks cannot be modified or deleted.
- `period_since_creation_in_days` - (Required) The immutability period for the blobs in the container since the policy creation, in days.
- `state` - (Required) The mode of the policy. `Disabled` disables the policy; `Unlocked` allows the immutability retention time to be increased or decreased and toggling `allow_protected_append_writes`; `Locked` only allows the immutability retention time to be increased. A policy may only be created in `Disabled` or `Unlocked`, may be toggled between those two, and `Unlocked` may transition to `Locked` (which cannot be reverted).
EOT
}

variable "is_hns_enabled" {
  type        = bool
  default     = null
  description = "(Optional) Is Hierarchical Namespace enabled? This can be used with Azure Data Lake Storage Gen 2 ([see here for more information](https://docs.microsoft.com/azure/storage/blobs/data-lake-storage-quickstart-create-account/)). Defaults to `null` (Azure platform default of `false`). Changing this forces a new resource to be created."
}
