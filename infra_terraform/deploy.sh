#!/bin/bash

# Check if IAM role exists and set Terraform variable
if aws iam get-role --role-name "${TF_VAR_project_tag:-learn-tf-aws-vpc}-ssm-role" &>/dev/null; then
    export TF_VAR_use_existing_iam=true
    echo "IAM role exists - using existing resources"
else
    export TF_VAR_use_existing_iam=false
    echo "IAM role not found - will create new resources"
fi

# Run Terraform
terraform plan