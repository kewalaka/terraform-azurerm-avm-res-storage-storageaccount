<!-- BEGIN_TF_DOCS -->
# Internal submodule: container

This is an internal submodule used by `terraform-azurerm-avm-res-storage-storageaccount`. Consumers MUST NOT call this submodule directly. Refer to the root module for supported inputs.

**ARM Resource Type**: `Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01`

## Features

- Public access control (`None`, `Blob`, `Container`)
- Container metadata
- Default encryption scope
- Immutable storage with versioning (container-level WORM)
- Time-based immutability policy with `Unlocked`/`Locked` state management
- Legal hold via `setLegalHold` POST action
- NFSv3 all/root squash settings
- Role assignments at container level

