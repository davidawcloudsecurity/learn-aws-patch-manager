#!/bin/bash

# Cleanup script for IAM resources
PROJECT_TAG="learn-tf-aws-vpc"
INSTANCE_PROFILE_NAME="${PROJECT_TAG}-ssm-profile"
ROLE_NAME="${PROJECT_TAG}-ssm-role"

echo "Cleaning up IAM resources for project: $PROJECT_TAG"

# Check and delete instance profile
if aws iam get-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME" >/dev/null 2>&1; then
    echo "Removing roles from instance profile..."
    ROLES=$(aws iam get-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME" --query 'InstanceProfile.Roles[*].RoleName' --output text)
    for ROLE in $ROLES; do
        aws iam remove-role-from-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME" --role-name "$ROLE"
        echo "Removed role $ROLE from instance profile"
    done
    sleep 2
    aws iam delete-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME"
    echo "Deleted instance profile: $INSTANCE_PROFILE_NAME"
else
    echo "Instance profile $INSTANCE_PROFILE_NAME doesn't exist"
fi

# Check and delete IAM role
if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
    # Detach managed policies
    aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    echo "Detached policy from role"
    
    # Delete role
    aws iam delete-role --role-name "$ROLE_NAME"
    echo "Deleted role: $ROLE_NAME"
else
    echo "Role $ROLE_NAME doesn't exist"
fi

echo "IAM cleanup completed"