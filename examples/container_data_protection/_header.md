# Container data protection example

This example demonstrates container-level data protection features of the storage account module.

**ARM Resource Types used:**

- `Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01`
- `Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2025-06-01`
- `Microsoft.Storage/storageAccounts/blobServices/containers` — `setLegalHold` action

## What this example deploys

- A storage account with two containers:
  - `compliance-data` — protected by a 30-day time-based immutability policy in `Unlocked` state
  - `legal-evidence` — protected by a legal hold with two tags

> **Note:** Legal hold is applied via a `setLegalHold` POST action. Removing `legal_hold` from configuration does **not** automatically clear the hold — you must call `clearLegalHold` manually (e.g., via Azure CLI) before deleting a container under legal hold.
>
> Transitioning an immutability policy to `Locked` state is irreversible and must be performed as a separate action outside this module.
