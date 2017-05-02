#!/usr/bin/python

# 27/04/2017 - fork of https://github.com/marekq/aws-lambda-firewall completely rewritten by ets for differing usecase
#

# TTL for dynamically whitelisted IPs
dynamicWhitelistDurationSeconds  = 60 * 60 * 24
# The region and VPC in which the whitelist will be applied
awsRegion = 'us-east-1'
vpcId = 'vpc-de87bab8'
# A prefix of the SecurityGroup GroupName used to identify dynamic groups
dynamicSGPrefix = 'dyn-'

# List of the ElasticIPs (We don't want to hardcode InstanceIds here since those might change) to whitelist for port 22 access
whitelistSSHTargets = ["34.204.105.155"]
# List of the ELB ARNs to whitelist for port 80 & 443 access
whiteListHTTPTargets = ["arn:aws:elasticloadbalancing:us-east-1:903373720037:loadbalancer/app/DevelopmentELB/7b4a10ac9563927a"]

##### do not touch anything below this line #####

import boto3, re, time
from botocore.exceptions import ClientError
import logging, sys
from pprint import pformat
logger = logging.getLogger()
logger.setLevel(logging.WARNING)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.WARNING)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

results = []

def update_ssh_access(ec2Client,expiredGroupIds,ipToWhitelist):
    if len(whitelistSSHTargets) > 0:
        # Create the new SecurityGroup permitting SSH Ingress for the source IP
        sgidToAttach = None
        if ipToWhitelist:
            creationTime      = int(time.time())
            expireTime    = creationTime + int(dynamicWhitelistDurationSeconds)
            desc = 'ExpiresAt ' + str(expireTime)
            name = dynamicSGPrefix + 'SSH-' +ipToWhitelist
            try:
                resp = ec2Client.create_security_group(GroupName = name, Description = desc, VpcId = vpcId)
                sgidToAttach = resp.get(u'GroupId')
                ec2Client.authorize_security_group_ingress(GroupId = sgidToAttach, IpProtocol = 'TCP', CidrIp = ipToWhitelist+'/32', FromPort = 22, ToPort = 22)
                results.append("Added "+ipToWhitelist+" to firewall for SSH access.")                
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidGroup.Duplicate':
                    results.append("Your IP is already whitelisted for SSH access")
                    return
                else:
                    result = 'Unable to create SecurityGroup ['+name+'] for SSH access: '+str(e)
                    results.append(result)
                    logger.error( result )

        # If we have a new SecurityGroup to attach or any to remove...update the instances
        if sgidToAttach or len(expiredGroupIds) > 0:
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
                    unexpiredSGIds = [x for x in allSGIds if x not in expiredGroupIds]
                    if sgidToAttach:
                        unexpiredSGIds.append(sgidToAttach)
                    logger.info("Removed ["+pformat(expiredGroupIds)+"] from ["+pformat(allSGIds)+"] resulting in ["+pformat(unexpiredSGIds)+"]")
                    ec2Client.modify_instance_attribute(Groups = unexpiredSGIds, InstanceId = instanceId)

        return sgidToAttach

def update_https_access(ec2Client,expiredGroupIds,ipToWhitelist):
    if len(whiteListHTTPTargets) > 0:
        # Create the new SecurityGroup permitting HTTPS Ingress for the source IP
        sgidToAttach = None
        if ipToWhitelist:
            creationTime      = int(time.time())
            expireTime    = creationTime + int(dynamicWhitelistDurationSeconds)
            desc = 'ExpiresAt ' + str(expireTime)
            name = dynamicSGPrefix + 'HTTP-' +ipToWhitelist
            try:
                resp = ec2Client.create_security_group(GroupName = name, Description = desc, VpcId = vpcId)
                sgidToAttach = resp.get(u'GroupId')
                ec2Client.authorize_security_group_ingress(GroupId = sgidToAttach, IpProtocol = 'TCP', CidrIp = ipToWhitelist+'/32', FromPort = 80, ToPort = 80)
                ec2Client.authorize_security_group_ingress(GroupId = sgidToAttach, IpProtocol = 'TCP', CidrIp = ipToWhitelist+'/32', FromPort = 443, ToPort = 443)
                results.append("Added "+ipToWhitelist+" to firewall for HTTP/S access.")
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidGroup.Duplicate':
                    results.append("Your IP is already whitelisted for HTTP/S access")
                    return
                else:
                    result = 'Unable to create SecurityGroup ['+name+'] for HTTP/S access: '+str(e)
                    results.append(result)
                    logger.error( result )

        # If we have a new SecurityGroup to attach or any to remove...update the instances
        if sgidToAttach or len(expiredGroupIds) > 0:
            elbClient = get_bolo_client('elbv2')
            for lbARN in whiteListHTTPTargets:
                lbDetails = elbClient.describe_load_balancers(
                    LoadBalancerArns=[lbARN]
                )
                for lb in lbDetails[u'LoadBalancers']:
                    unexpiredSGIds = [x for x in lb[u'SecurityGroups'] if x not in expiredGroupIds]
                    if sgidToAttach:
                        unexpiredSGIds.append(sgidToAttach)
                    logger.info("Removed ["+pformat(expiredGroupIds)+"] from ["+pformat(lb[u'SecurityGroups'])+"] resulting in ["+pformat(unexpiredSGIds)+"]")
                    elbClient.set_security_groups(
                        LoadBalancerArn=lbARN,
                        SecurityGroups=unexpiredSGIds
                    )
        return sgidToAttach

def update_whitelist(ec2Client,expiredGroupIds,ipToWhitelist):
    update_https_access(ec2Client,expiredGroupIds,ipToWhitelist)
    update_ssh_access(ec2Client,expiredGroupIds,ipToWhitelist)

def get_bolo_client(serv):
    s               = boto3.session.Session()
    client         = s.client(serv, region_name = awsRegion )
    return client


def get_expired_security_groups(client):
    groupIds = []
    securityGroups = client.describe_security_groups(Filters=[
        {
            'Name': 'vpc-id',
            'Values': [vpcId],
        },
    ])

    # Check all dynamic SecurityGroups and delete any that have expired
    for sg in securityGroups['SecurityGroups']:
        groupName = sg['GroupName']
        if groupName.startswith( dynamicSGPrefix ):
            groupDesc = sg['Description']
            groupId = sg['GroupId']
            expireTime = groupDesc.split(' ')[1]
            timeTillExpiration   = int(time.time()) - int(expireTime)
            if timeTillExpiration > int(0):
                try:
                    groupIds.append(sg['GroupId'])
                except Exception as e:
                    result = 'FAIL: failed marking GroupId='+ str(groupId) + ' for deletion: ' + str(e)
                    results.append(result)
                    logger.error( result )

    return groupIds

def remove_security_groups(client,groupIds):
    for gid in groupIds:
        try:
            client.delete_security_group(GroupId = gid)
            logger.info( 'Deleted GroupId='+ str(gid) )
        except Exception as e:
            logger.error( 'FAIL: failed deleting GroupId='+ str(gid) + ': ' + str(e))

def lambda_handler(event, context):
    logger.info('got event{}'.format(event))
    ec2Client = get_bolo_client('ec2')
    expiredGroupIds = get_expired_security_groups(ec2Client)
    ipToWhitelist = None
    try:
        ipToWhitelist = event['requestContext']['identity']['sourceIp']
    except KeyError as e:
        # This is a CloudWatch request without a full API Gateway Proxy context
        ipToWhitelist = None

    update_whitelist(ec2Client,expiredGroupIds,ipToWhitelist)
    remove_security_groups(ec2Client,expiredGroupIds)
    return {
        "isBase64Encoded": False,
        "statusCode": 200,
        "headers": { },
        "body":  '. '.join(results)
    }

# CLI testing
#exampleLambdaAPIGatewayProxyRequest = {u'body': u'{"test":"body"}', u'resource': u'/{proxy+}', u'requestContext': {u'resourceId': u'123456', u'apiId': u'1234567890', u'resourcePath': u'/{proxy+}', u'httpMethod': u'POST', u'requestId': u'c6af9ac6-7b61-11e6-9a41-93e8deadbeef', u'stage': u'prod', u'identity': {u'apiKey': None, u'userArn': None, u'sourceIp': u'127.0.0.1', u'caller': None, u'cognitoIdentityId': None, u'user': None, u'cognitoIdentityPoolId': None, u'userAgent': u'Custom User Agent String', u'accountId': None, u'cognitoAuthenticationType': None, u'cognitoAuthenticationProvider': None}, u'accountId': u'123456789012'}, u'queryStringParameters': {u'foo': u'bar'}, u'httpMethod': u'POST', u'pathParameters': {u'proxy': u'path/to/resource'}, u'headers': {u'Via': u'1.1 08f323deadbeefa7af34d5feb414ce27.cloudfront.net (CloudFront)', u'Accept-Language': u'en-US,en;q=0.8', u'CloudFront-Is-Desktop-Viewer': u'true', u'CloudFront-Is-SmartTV-Viewer': u'false', u'CloudFront-Forwarded-Proto': u'https', u'X-Forwarded-Port': u'443', u'X-Forwarded-For': u'127.0.0.1, 127.0.0.2', u'CloudFront-Viewer-Country': u'US', u'Accept': u'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', u'Upgrade-Insecure-Requests': u'1', u'Host': u'1234567890.execute-api.us-east-1.amazonaws.com', u'X-Forwarded-Proto': u'https', u'X-Amz-Cf-Id': u'cDehVQoZnx43VYQb9j2-nvCh-9z396Uhbp027Y2JvkCPNLmGJHqlaA==', u'CloudFront-Is-Tablet-Viewer': u'false', u'Cache-Control': u'max-age=0', u'User-Agent': u'Custom User Agent String', u'CloudFront-Is-Mobile-Viewer': u'false', u'Accept-Encoding': u'gzip, deflate, sdch'}, u'stageVariables': {u'baz': u'qux'}, u'path': u'/path/to/resource'}
#result = lambda_handler(exampleLambdaAPIGatewayProxyRequest,None)
#logger.info("Result of lambda invocation: "+pformat(result) )
