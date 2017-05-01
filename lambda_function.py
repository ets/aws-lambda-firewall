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
import logging, sys
from pprint import pformat
logger = logging.getLogger()
logger.setLevel(logging.INFO)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

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
            except Exception as e:
                logger.error( 'Unable to create SecurityGroup ['+name+'] for SSH access: '+str(e))

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
            except Exception as e:
                logger.error( 'Unable to create SecurityGroup ['+name+'] for HTTPS access: '+str(e))

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
    return update_https_access(ec2Client,expiredGroupIds,ipToWhitelist) and update_ssh_access(ec2Client,expiredGroupIds,ipToWhitelist)


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
            logger.info("**** in debug mode defaulting to delete all the time *****")
            if timeTillExpiration > int(0):
                try:
                    groupIds.append(sg['GroupId'])
                except Exception as e:
                    logger.error( 'FAIL: failed marking GroupId='+ str(groupId) + ' for deletion: ' + str(e))

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
    ipToWhitelist  = event.get('ip', None)
    success = update_whitelist(ec2Client,expiredGroupIds,ipToWhitelist)
    remove_security_groups(ec2Client,expiredGroupIds)
    return success

# CLI testing
# logger.info("Result of lambda invocation: "+lambda_handler({'ip': '192.168.1.42'},None) )
