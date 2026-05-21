# Container data protection example

This deploys the module with container-level data protection features:
- A 30-day time-based immutability policy in `Unlocked` state
- A legal hold on a separate container

> **Note:** Legal hold is applied via a `setLegalHold` POST action on create/update. Removing `legal_hold` from configuration does **not** automatically clear the hold — you must call `clearLegalHold` manually (e.g., via Azure CLI) before deleting a container under legal hold.
