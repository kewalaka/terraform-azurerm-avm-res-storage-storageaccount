output "containers" {
  description = "The containers created with data protection policies."
  value       = module.this.containers
}

output "resource" {
  description = "The storage account resource."
  sensitive   = true
  value       = module.this.resource
}
