# Check if IAM role exists and set Terraform variable
$roleName = "$env:TF_VAR_project_tag-ssm-role"
if (-not $roleName) { $roleName = "learn-tf-aws-vpc-ssm-role" }

try {
    aws iam get-role --role-name $roleName | Out-Null
    $env:TF_VAR_use_existing_iam = "true"
    Write-Host "IAM role exists - using existing resources"
} catch {
    $env:TF_VAR_use_existing_iam = "false"
    Write-Host "IAM role not found - will create new resources"
}

# Run Terraform
terraform plan