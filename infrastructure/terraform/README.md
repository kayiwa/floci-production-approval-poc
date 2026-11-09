# Deliberately no Terraform deployment

This pilot has no providers, remote backend, Terraform/OpenTofu resources, credentials, state imports or applies. It is independent of any existing infrastructure configuration or state.

The disposable Floci fixture is created through guarded boto3 calls. IAM JSON and the SSM YAML are designs, not input to an automatic deployment. A future AWS implementation needs a separate security design review and explicit sandbox authorization before any infrastructure module is written or applied.
