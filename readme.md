aws-lambda-firewall
===================

Fork of https://github.com/marekq/aws-lambda-firewall altered to support end users behind dynamic IPs who can "knock for access" using a valid API Gateway token. By making a valid call to this AWS Lambda function behind an AWS API Gateway, the end user's IP is added (for 24 hours) to a security group that permits access to other resources.

IAM policies required by the role assigned to the lambda
---------------------------------------------------------
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
    }
  ]
}


Description
------------

The Lambda firewall can be used in sensitive environments where you want to keep strict control over security groups. Users with a valid API gateway key can make a request to whitelist a IP address for a specific duration without the need for access to the console. After the security group expires, it is automatically detached from the EC2 instances and removed. You no longer need to add or remove security groups manually, which is especially useful for users with many different  breakout IP addresses.

The steps how the Lambda firewall can be used are shown below;

![alt tag](https://raw.githubusercontent.com/marekq/aws-lambda-firewall/master/docs/1.png)


Besides security group management, the Lambda firewall will also write the state of security groups to an S3 folder so that it is possible to see the state of all security groups easily. This makes it very easy to review and check which ports are externally facing at any given time.




Installation
------------

You need to install two things in order for the firewall to work;

1. Add the Lambda function to your account with handler "lambda_function.handler" and configure it with proper IAM permissions to run, see "lambda_function.py".
2. Set the correct bucket name in the lambda function to write logs to S3 - you can skip this by entering a blank bucket name.
3. Create an API gateway and map the correct GET parameters to the Lambda function.
4. Create API keys for users in the API gateweay and deploy the gateway to production.
5. Next, create a trigger in CloudWatch so the Lambda function is called every 15 minutes to remove expired security groups.
6. Configure a valid API key and the correct Lambda URL in "firewall_client.py" and distribute it to your users.

Make sure to use and enable CloudWatch logs if the Lambda function does not work.




Usage
-----

- Security groups are added by the firewall_client which can be called manually by your users.
- Rules are removed when the function is called by the API gateway or when a valid API call is received.


If all steps are completed, users can whitelist an IP address and port simply by running "firewall_client.py" with the correct parameters. If these are skipped, default values are used;


![alt tag](https://raw.githubusercontent.com/marekq/aws-lambda-firewall/master/docs/4.png)


You should now see a new security group associated with all your EC2 instances;


![alt tag](https://raw.githubusercontent.com/marekq/aws-lambda-firewall/master/docs/5.png)


The group nameof the security group describes the source IP address which is whitelisted. The description contains two types of timestamps; the first two values describe when the security group was created while the last two describe when the security group should be removed.  




Screenshots
-----------

Configure the body templates of your API gateway as follows;


![alt tag](https://raw.githubusercontent.com/marekq/aws-lambda-firewall/master/docs/2.png)


```json
{
    "ip" : "$input.params('ip')",
    "port" : "$input.params('port')",
    "duration" : "$input.params('duration')",
    "proto" : "$input.params('proto')"
}
```

Your API gateway method should look as follows;

![alt tag](https://raw.githubusercontent.com/marekq/aws-lambda-firewall/master/docs/3.png)




Contact
-------

For any questions or fixes, please reach out to @marekq!
