#!/usr/bin/python

# 27/04/2017 - fork of https://github.com/marekq/aws-lambda-firewall completely rewritten by ets for differing usecase
#

cli_testing_mode = False
# TTL for dynamically whitelisted IPs
dynamicWhitelistDurationSeconds  = 60 * 60 * 24
# The region and VPC in which the whitelist will be applied
awsRegion = 'us-east-1'
vpcId = 'vpc-de87bab8'
# The SimpleDB domain name for recording the whitelist
simpleDBDomain = 'lambda-firewall'

# List of the ElasticIPs (We don't want to hardcode InstanceIds here since those might change) to whitelist for port 22 access
whitelistSSHTargets = ["34.204.105.155"]
# AWS currently limits any instance to 5 security groups, so that's the maximum number of groups you should define
whitelistSSHGroupNames = ['dyn-SSH-1','dyn-SSH-2','dyn-SSH-3','dyn-SSH-4']

# List of the ELB ARNs to whitelist for port 80 & 443 access
whiteListHTTPSTargets = ["arn:aws:elasticloadbalancing:us-east-1:903373720037:loadbalancer/app/DevelopmentELB/7b4a10ac9563927a"]
# AWS currently limits any instance to 5 security groups, so that's the maximum number of groups you should define
whitelistHTTPSGroupNames = ['dyn-HTTPS-1','dyn-HTTPS-2','dyn-HTTPS-3','dyn-HTTPS-4']

##### do not touch anything below this line #####

AWS_MAX_INGRESS_RULES_PER_SG = 100

import boto3, re, time, logging, sys
from botocore.exceptions import ClientError
from pprint import pformat
from operator import itemgetter
logger = logging.getLogger()
logger.setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

results = []

def add_ingress_rule(ec2Client,sdbClient,ipToWhitelist,sgId,portPairs):
    try:
        for pair in portPairs:
            ec2Client.authorize_security_group_ingress(GroupId = sgId, IpProtocol = 'TCP', CidrIp = ipToWhitelist+'/32', FromPort = pair[0], ToPort = pair[1])
    except  ClientError as e:
        if e.response['Error']['Code'] != 'InvalidPermission.Duplicate':
            logger.error("Error while adding ingress rule: "+str(e))
            return

    creationTime = int(time.time())
    expireTime = creationTime + int(dynamicWhitelistDurationSeconds)
    sdbClient.put_attributes(
        DomainName=simpleDBDomain,
        ItemName=ipToWhitelist,
        Attributes=[
            { 'Name': 'ipAddress', 'Value': ipToWhitelist, 'Replace': True },
            { 'Name': 'sgId', 'Value': sgId, 'Replace': False },
            { 'Name': 'expirationTime', 'Value': str(expireTime), 'Replace': True },
        ]
    )
    return

def add_https_security_group(ec2Client,sgName):
    sg = ec2Client.create_security_group(GroupName = sgName, Description = 'Knock first firewall maintained group.', VpcId = vpcId)
    sgId = sg.get(u'GroupId')
    elbClient = get_bolo_client('elbv2')
    for lbARN in whiteListHTTPSTargets:
        lbDetails = elbClient.describe_load_balancers(
            LoadBalancerArns=[lbARN]
        )
        for lb in lbDetails[u'LoadBalancers']:
            sgIds = lb[u'SecurityGroups']
            sgIds.append(sgId)
            elbClient.set_security_groups(
                LoadBalancerArn=lbARN,
                SecurityGroups=sgIds
            )

    logger.info("Created "+sgName+" ["+sgId+"]")
    return sgId

def update_https_access(ec2Client,sdbClient,ipToWhitelist):
    portPairs = [ [80,80],[443,443] ]
    for sgName in whitelistHTTPSGroupNames:
        securityGroups = ec2Client.describe_security_groups(Filters=[
            {
                'Name': 'group-name',
                'Values': [sgName],
            },
        ])
        if len(securityGroups['SecurityGroups']) <= 0:
            logger.info("Unable to describe security group "+sgName+" so we'll attempt to create it.")
            sgId = add_https_security_group(ec2Client,sgName)
            add_ingress_rule(ec2Client,sdbClient,ipToWhitelist,sgId,portPairs)
            return
        else:
            for sg in securityGroups['SecurityGroups']:
                ingressRules = sg['IpPermissions']
                if len(ingressRules) <= (AWS_MAX_INGRESS_RULES_PER_SG - len(portPairs) ):
                    add_ingress_rule(ec2Client,sdbClient,ipToWhitelist,sg.get(u'GroupId'),portPairs)
                    return

    logger.error("No free rule slots available across all security groups ["+whitelistHTTPSGroupNames+"]. Consider increasing your security group limit for HTTPS whitelisting.")

def add_ssh_security_group(ec2Client,sgName):
    sg = ec2Client.create_security_group(GroupName = sgName, Description = 'Knock first firewall maintained group.', VpcId = vpcId)
    sgId = sg.get(u'GroupId')
    ec2Instances = ec2Client.describe_instances(Filters=[
        {
            'Name': 'ip-address',
            'Values': whitelistSSHTargets
        },
    ])
    for x in ec2Instances[u'Reservations']:
        for y in range(len(x[u'Instances'])):
            instanceId    = x[u'Instances'][int(y)][u'InstanceId']
            securityGroups = ec2Client.describe_instance_attribute(Attribute='groupSet',InstanceId=instanceId)
            allSGIds = [group[u'GroupId'] for group in securityGroups[u'Groups']]
            allSGIds.append(sgId)
            ec2Client.modify_instance_attribute(Groups = allSGIds, InstanceId = instanceId)

    logger.info("Created "+sgName+" ["+sgId+"]")
    return sgId

def update_ssh_access(ec2Client,sdbClient,ipToWhitelist):
    portPairs = [ [22,22] ]
    for sgName in whitelistSSHGroupNames:
        securityGroups = ec2Client.describe_security_groups(Filters=[
            {
                'Name': 'group-name',
                'Values': [sgName],
            },
        ])
        if len(securityGroups['SecurityGroups']) <= 0:
            logger.info("Unable to describe security group "+sgName+" so we'll attempt to create it.")
            sgId = add_ssh_security_group(ec2Client,sgName)
            add_ingress_rule(ec2Client,sdbClient,ipToWhitelist,sgId,portPairs)
            return
        else:
            for sg in securityGroups['SecurityGroups']:
                ingressRules = sg['IpPermissions']
                if len(ingressRules) <= (AWS_MAX_INGRESS_RULES_PER_SG - len(portPairs) ):
                    add_ingress_rule(ec2Client,sdbClient,ipToWhitelist,sg.get(u'GroupId'),portPairs)
                    return

    logger.error("No free rule slots available across all security groups ["+whitelistSSHGroupNames+"]. Consider increasing your security group limit for SSH whitelisting.")

def whitelist_ip(ipToWhitelist):
    sdbClient = get_bolo_client('sdb')
    query = 'select * from `'+simpleDBDomain+'` where `ipAddress` = "'+ipToWhitelist+'"'
    logger.debug('Executing: '+query)
    existingRules = sdbClient.select(
        SelectExpression=query
    )
    try:
        logger.info("Whitelisting "+ipToWhitelist)
        if 'Items' not in existingRules or len(existingRules['Items']) <= 0:
            ec2Client = get_bolo_client('ec2')
            update_ssh_access(ec2Client,sdbClient,ipToWhitelist)
            update_https_access(ec2Client,sdbClient,ipToWhitelist)
            results.append('Whitelisted '+ipToWhitelist+' for access.')
        else:
            results.append("Your IP is already whitelisted for access")
    except Exception as e:
        msg = "Unable to whitelist "+ipToWhitelist+" due to: "+pformat(e)
        logger.error(msg)
        results.append(msg)

def get_bolo_client(serv):
    s               = boto3.session.Session()
    client         = s.client(serv, region_name = awsRegion )
    return client

def remove_expired_rules():
    logger.info("Removing expired rules.")
    sdbClient = get_bolo_client('sdb')
    now = int(time.time())
    query = "select * from `"+simpleDBDomain+"` where expirationTime < '"+str(now)+"'"
    logger.debug('Executing this: '+query)
    expiredRules = sdbClient.select(
        SelectExpression=query
    )
    logger.debug("Results: "+pformat(expiredRules))
    if 'Items' in expiredRules and len(expiredRules['Items']) > 0:
        ec2Client = get_bolo_client('ec2')
        for expiredItem in expiredRules['Items']:
            logger.debug("Attempting to delete: "+pformat(expiredItem))
            expiredRuleSecurityGroupIdList = [attr['Value'] for attr in expiredItem['Attributes'] if attr['Name'] == 'sgId']
            expiredRuleCidr = [attr['Value'] for attr in expiredItem['Attributes'] if attr['Name'] == 'ipAddress'][0] + '/32'
            securityGroups = ec2Client.describe_security_groups(Filters=[
                {
                    'Name': 'group-id',
                    'Values': expiredRuleSecurityGroupIdList,
                },
            ])
            try:
                for sg in securityGroups['SecurityGroups']:
                    ingressPorts = [attr['FromPort'] for attr in sg['IpPermissions'] if expiredRuleCidr in map(itemgetter('CidrIp'), attr['IpRanges']) ]
                    for port in ingressPorts:
                        ec2Client.revoke_security_group_ingress(
                            GroupId=sg['GroupId'],
                            IpPermissions=[
                                {
                                    'IpProtocol': 'TCP',
                                    'FromPort': port,
                                    'ToPort': port,
                                    'IpRanges': [
                                        {
                                            'CidrIp': expiredRuleCidr
                                        },
                                    ],
                                },
                            ]
                        )
                results.append('Expired access for '+expiredRuleCidr)
                response = sdbClient.delete_attributes(
                    DomainName=simpleDBDomain,
                    ItemName=expiredItem['Name'],
                    Attributes=expiredItem['Attributes']
                )
            except Exception as e:
                msg = "Unable to revoke ingress rule: "+pformat(e)
                results.append(msg)
                logger.error(msg)

def lambda_handler(event, context):
    logger.debug('got event{}'.format(event))
    try:
        try:
            ipToWhitelist = event['requestContext']['identity']['sourceIp']
            if ipToWhitelist:
                whitelist_ip(ipToWhitelist)
            else:
                remove_expired_rules()
        except KeyError as e:
            remove_expired_rules()
    except  ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchDomain':
            logger.info("Our SimpleDB domain does not exist. Creating it and retrying request.")
            sdbClient = get_bolo_client('sdb')
            sdbClient.create_domain(
                DomainName=simpleDBDomain
            )
            lambda_handler(event,context)
        else:
            logger.error("Error: "+str(e))


    return {
        "isBase64Encoded": False,
        "statusCode": 200,
        "headers": { },
        "body":  '. '.join(results)
    }

if cli_testing_mode:
    exampleLambdaAPIGatewayProxyRequest = {u'body': u'{"test":"body"}', u'resource': u'/{proxy+}', u'requestContext': {u'resourceId': u'123456', u'apiId': u'1234567890', u'resourcePath': u'/{proxy+}', u'httpMethod': u'POST', u'requestId': u'c6af9ac6-7b61-11e6-9a41-93e8deadbeef', u'stage': u'prod', u'identity': {u'apiKey': None, u'userArn': None, u'sourceIp': u'127.0.0.42', u'caller': None, u'cognitoIdentityId': None, u'user': None, u'cognitoIdentityPoolId': None, u'userAgent': u'Custom User Agent String', u'accountId': None, u'cognitoAuthenticationType': None, u'cognitoAuthenticationProvider': None}, u'accountId': u'123456789012'}, u'queryStringParameters': {u'foo': u'bar'}, u'httpMethod': u'POST', u'pathParameters': {u'proxy': u'path/to/resource'}, u'headers': {u'Via': u'1.1 08f323deadbeefa7af34d5feb414ce27.cloudfront.net (CloudFront)', u'Accept-Language': u'en-US,en;q=0.8', u'CloudFront-Is-Desktop-Viewer': u'true', u'CloudFront-Is-SmartTV-Viewer': u'false', u'CloudFront-Forwarded-Proto': u'https', u'X-Forwarded-Port': u'443', u'X-Forwarded-For': u'127.0.0.1, 127.0.0.2', u'CloudFront-Viewer-Country': u'US', u'Accept': u'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', u'Upgrade-Insecure-Requests': u'1', u'Host': u'1234567890.execute-api.us-east-1.amazonaws.com', u'X-Forwarded-Proto': u'https', u'X-Amz-Cf-Id': u'cDehVQoZnx43VYQb9j2-nvCh-9z396Uhbp027Y2JvkCPNLmGJHqlaA==', u'CloudFront-Is-Tablet-Viewer': u'false', u'Cache-Control': u'max-age=0', u'User-Agent': u'Custom User Agent String', u'CloudFront-Is-Mobile-Viewer': u'false', u'Accept-Encoding': u'gzip, deflate, sdch'}, u'stageVariables': {u'baz': u'qux'}, u'path': u'/path/to/resource'}
    result = lambda_handler(exampleLambdaAPIGatewayProxyRequest,None)
    logger.info("Result of lambda invocation: "+pformat(result) )
