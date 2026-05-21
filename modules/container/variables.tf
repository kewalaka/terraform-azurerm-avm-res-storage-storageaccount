variable "name" {
  type        = string
  description = "(Required) The name of the container."
  nullable    = false
}

variable "storage_account_id" {
  type        = string
  description = "(Required) The full resource ID of the parent storage account."
  nullable    = false
}

variable "container_immutability_policy_resource_type" {
  type        = string
  default     = "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2025-06-01"
  description = "(Optional) Override the AzAPI resource type for container immutability policies."
  nullable    = false
}

variable "default_encryption_scope" {
  type        = string
  default     = null
  description = "(Optional) The default encryption scope to use for blob operations on the container. Defaults to `null` (the storage account default encryption scope is used)."
}

variable "deny_encryption_scope_override" {
  type        = bool
  default     = null
  description = "(Optional) When set to `true`, blocks blob uploads from specifying a different encryption scope. Defaults to `null` (`false`)."
}

variable "enable_nfs_v3_all_squash" {
  type        = bool
  default     = null
  description = "(Optional) Enable NFSv3 all squash (only valid for NFSv3 enabled accounts). Defaults to `null` (`false`)."
}

variable "enable_nfs_v3_root_squash" {
  type        = bool
  default     = null
  description = "(Optional) Enable NFSv3 root squash (only valid for NFSv3 enabled accounts). Defaults to `null` (`false`)."
}

variable "immutable_storage_with_versioning" {
  type = object({
    enabled = bool
  })
  default     = null
  description = <<-EOT
(Optional) Configures container-level immutability with version-level WORM. Defaults to `null` (immutability disabled).

- `enabled` - (Required) Whether immutable storage with versioning is enabled.
EOT
}

variable "immutability_policy" {
  type = object({
    allow_protected_append_writes     = optional(bool)
    allow_protected_append_writes_all = optional(bool)
    period_since_creation_in_days     = number
    state                             = optional(string, "Unlocked")
  })
  default     = null
  description = <<-EOT
(Optional) A time-based immutability policy for the container. Defaults to `null`.

- `period_since_creation_in_days` - (Required) The immutability period in days.
- `state` - (Optional) `Unlocked` (can increase or decrease) or `Locked` (can only increase, irreversible). Defaults to `Unlocked`. Note: transitioning to `Locked` is irreversible and must be done manually via `azapi_resource_action` — this module manages the policy in `Unlocked` state only.
- `allow_protected_append_writes` - (Optional) Allow appending to append blobs while under immutability. Defaults to `null`.
- `allow_protected_append_writes_all` - (Optional) Allow appending to block and append blobs. Defaults to `null`.
EOT
}

variable "legal_hold" {
  type = object({
    tags = list(string)
  })
  default     = null
  description = <<-EOT
(Optional) A legal hold placed on the container. Defaults to `null`.

- `tags` - (Required) A list of legal hold tags. Each tag must be alphanumeric and 3–23 characters long.

> **Note:** Legal hold is applied via a `setLegalHold` POST action. Clearing the hold on destroy is not supported by this module — removing `legal_hold` from configuration will NOT automatically call `clearLegalHold`. To remove a legal hold, call `clearLegalHold` manually (e.g., via Azure CLI or a one-off `azapi_resource_action`).
EOT
}

variable "metadata" {
  type        = map(string)
  default     = null
  description = "(Optional) Container metadata. Keys must be lowercase. Defaults to `null` (no metadata)."
}

variable "public_access" {
  type        = string
  default     = "None"
  description = "(Optional) Specifies the level of public access. Valid values: `None`, `Blob`, `Container`. Defaults to `None`."
}

variable "resource_type" {
  type        = string
  default     = "Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01"
  description = "(Optional) Override the AzAPI `<provider>/<resource>@<api-version>` string used to manage the blob container. Defaults to the value tested with this module version."
  nullable    = false
}

variable "retry" {
  type = object({
    error_message_regex  = optional(list(string))
    interval_seconds     = optional(number)
    max_interval_seconds = optional(number)
  })
  default     = null
  description = <<-EOT
(Optional) Retry configuration applied to AzAPI resources managed by this module. Defaults to `null` (no custom retry).

- `error_message_regex` - (Optional) A list of regex patterns matching error messages that trigger a retry. Defaults to `null`.
- `interval_seconds` - (Optional) Initial interval between retries in seconds. Defaults to `null` (provider default).
- `max_interval_seconds` - (Optional) Maximum interval between retries in seconds. Defaults to `null` (provider default).
EOT
}

variable "role_assignment_definition_lookup_enabled" {
  type        = bool
  default     = true
  description = "(Optional) Whether the `role_assignments` submodule should resolve role definition names supplied via `role_definition_id_or_name` by querying the Azure Authorization API. Defaults to `true`. See the `role_assignments` submodule for details."
  nullable    = false
}

variable "role_assignments" {
  type = map(object({
    role_definition_id_or_name             = string
    principal_id                           = string
    description                            = optional(string, null)
    skip_service_principal_aad_check       = optional(bool, false)
    condition                              = optional(string, null)
    condition_version                      = optional(string, null)
    delegated_managed_identity_resource_id = optional(string, null)
    principal_type                         = optional(string, null)
  }))
  default     = {}
  description = "(Optional) A map of role assignments to create at the container scope. Defaults to `{}`. See the `role_assignments` submodule for the attribute schema."
  nullable    = false
}

variable "timeouts" {
  type = object({
    create = optional(string)
    read   = optional(string)
    update = optional(string)
    delete = optional(string)
  })
  default     = null
  description = <<-EOT
(Optional) Per-operation timeouts applied to AzAPI resources managed by this module. Defaults to `null` (provider defaults). Each value is a Go duration string (e.g. `30m`, `1h`).

- `create` - (Optional) Timeout for create operations. Defaults to `null`.
- `read` - (Optional) Timeout for read operations. Defaults to `null`.
- `update` - (Optional) Timeout for update operations. Defaults to `null`.
- `delete` - (Optional) Timeout for delete operations. Defaults to `null`.
EOT
}

variable "tracing_tags_header" {
  type        = string
  default     = null
  description = "(Optional) User-Agent string injected into AzAPI request headers. Defaults to `null` (no custom header)."
}
