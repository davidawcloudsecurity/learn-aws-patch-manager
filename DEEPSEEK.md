**Step 1: Ensure EC2 Instances Have SSM Connectivity**  
Start by verifying/adding the **IAM role** with the `AmazonSSMManagedInstanceCore` policy to your existing EC2 instances. SSM requires this to manage patches/configurations.  

### Terraform Snippet (IAM Role):  
```hcl
resource "aws_iam_role" "ssm_ec2_role" {
  name = "SSM-EC2-Managed-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ssm_ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
```  

**Next Step**: Attach this role to your existing EC2 instances (manually via AWS Console/CLI or via Terraform if managed).  

Let me know when you're ready for **Step 2** (SSM Patch Management setup). Keep it minimal?
