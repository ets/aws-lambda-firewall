aws-lambda-firewall
===================

This was initially a fork of https://github.com/marekq/aws-lambda-firewall but was subsequently rewritten. Current usecase scenario is to support end users behind dynamic IPs who can "knock for access" using a valid API Gateway token. By making a valid call to this AWS Lambda function behind an AWS API Gateway, the end user's IP is added (for 24 hours) to security groups that permit access to other resources.

This allows us to restrict access to ports (e.g. SSH port on our Bastion host or 443 on the ELB that fronts our development & test servers) but allow access to authorized users without the need to establish a VPN or otherwise modify routing across the Internet.

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
        "ec2:ModifyInstanceAttribute",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupIngress",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:ModifyLoadBalancerAttributes",
        "elasticloadbalancing:SetSecurityGroups"
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
    },
    {
          "Sid": "simpleDBdatastorageforwhitelister",
          "Effect": "Allow",
          "Action": [
              "sdb:*"
          ],
          "Resource": [
              "arn:aws:sdb:us-east-1:903373720037:domain/SIMPLEDB_DOMAIN_NAME_DECLARED_IN_LAMBDA_SCRIPT"
          ]
      }    
  ]
}
```

Description
------------

The Lambda firewall can be used in sensitive environments where you want to keep strict control over security groups. Users with a valid API gateway key can make a request to temporarily whitelist their IP address for a specific duration without the need for access to the console or IAM permissions to alter Security Groups. After the whitelist entry expires, it is automatically removed. You no longer need to add or remove ingress rules or security groups manually, which is especially useful for users with many different breakout IP addresses.

Installation
------------

1. Add the Lambda function (lambda_function.py) to your account with a Python 2.x handler "lambda_function.lambda_handler"
2. Use the API Gateway trigger and for Security use "Open with Access Key"
3. Configure the Lambda with the IAM Role defined using the rules in the section above
4. Next, create a second trigger for your Lambda using CloudWatch and set it to call the lambda periodically to delete expired groups
5. Under API Gateway, create a Usage Plan with a set of API Keys
5. Add a valid API key and the correct Lambda URL in the "firewall_client" scripts and distribute it to your users.

Usage
-----
- To whitelist your IP, call the firewall_client (python and CURL examples included) manually

Contact
-------

For any questions or fixes, please reach out via github!
