#!/bin/bash

echo "Check if learn-tf-aws-vpc-ssm-role exists"
if [ -n "$(aws iam list-roles --query 'Roles[*].RoleName' | grep learn-tf-aws-vpc-ssm-role | sed 's/[",]//g')" ]; then
    ROLE_NAME="learn-tf-aws-vpc-ssm-role"
    INSTANCE_PROFILE_NAME="learn-tf-aws-vpc-ssm-profile"
    
    echo "Removing role from instance profile first..."
    # Remove role from instance profile
    aws iam remove-role-from-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME" --role-name "$ROLE_NAME" 2>/dev/null || echo "Role not in instance profile or doesn't exist"
    
    echo "Deleting instance profile: $INSTANCE_PROFILE_NAME"
    aws iam delete-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME" 2>/dev/null || echo "Instance profile doesn't exist"
    
    echo "Detaching managed policies from role: $ROLE_NAME"
    # Detach AWS managed policies
    aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore" 2>/dev/null || echo "Policy already detached or doesn't exist"
    
    echo "Detaching inline policies from role: $ROLE_NAME"
    # List and delete inline policies
    INLINE_POLICIES=$(aws iam list-role-policies --role-name "$ROLE_NAME" --query 'PolicyNames' --output text)
    for POLICY in $INLINE_POLICIES; do
        if [ "$POLICY" != "None" ] && [ -n "$POLICY" ]; then
            aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY"
            echo "Deleted inline policy: $POLICY"
        fi
    done
    
    echo "Deleting role: $ROLE_NAME"
    aws iam delete-role --role-name "$ROLE_NAME"
    echo "Role deleted successfully"
else
    echo "Role learn-tf-aws-vpc-ssm-role does not exist"
fi