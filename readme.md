aws-lambda-firewall
===================

Fork of https://github.com/marekq/aws-lambda-firewall altered to support end users behind dynamic IPs who can "knock for access" using a valid API Gateway token. By making a valid call to this AWS Lambda function behind an AWS API Gateway, the end user's IP is added (for 24 hours) to a security group that permits access to other resources.

IAM policies required by the role assigned to the lambda
---------------------------------------------------------
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt1392679134000",
      "Effect": "Allow",
      "Action": [
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CreateSecurityGroup",
        "ec2:DeleteSecurityGroup",
        "ec2:DescribeInstanceAttribute",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeSecurityGroups",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupIngress"
      ],
      "Resource": [
        "*"
      ]
    },
    {
        "Sid": "cloudwatchloggingforwhitelister",
        "Effect": "Allow",
        "Action": [
            "logs:*"
        ],
        "Resource": [
            "arn:aws:logs:*:*:*"
        ]
    }
  ]
}
```

Description
------------

The Lambda firewall can be used in sensitive environments where you want to keep strict control over security groups. Users with a valid API gateway key can make a request to whitelist a IP address for a specific duration without the need for access to the console. After the security group expires, it is automatically detached from the EC2 instances and removed. You no longer need to add or remove security groups manually, which is especially useful for users with many different breakout IP addresses.

Installation
------------

You need to install two things in order for the firewall to work;

1. Add the Lambda function to your account with Python 2.x handler "lambda_function.lambda_handler"
2. Use the API Gateway trigger and for Security use "Open with Access Key"
3. Configure the Lambda with the IAM Role defined using the rules in the section above
4. Next, create a second trigger for your Lambda using CloudWatch and set it to call the lambda periodically to delete expired groups
5. Under API Gateway, create a Usage Plan with a set of API Keys
5. Add a valid API key and the correct Lambda URL in the "firewall_client" scripts and distribute it to your users.

Usage
-----
- Security groups are added by the firewall_client which can be called manually by your users.
- Rules are removed when the function is called by the API gateway or when a valid API call is received.

Contact
-------

For any questions or fixes, please reach out via github!
