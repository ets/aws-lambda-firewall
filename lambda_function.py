#!/usr/bin/python

# 27/04/2017 - forked by ets from :
#
# marek.kuczynski
# @marekq
# www.marek.rocks

dynamicWhitelistDurationSeconds  = 60 * 60 * 24
awsRegion = 'us-east-1'
dynamicSGPrefix = 'dyn-'
# We don't want to hardcode IDs here since those might change. We whitelist based upon the public IP
# ElasticIPs attached to EC2 instances
whiteListEC2Map = {"34.204.105.155": [22]}
# ELB IPs
whiteListELBMap = {"ELB_IP": [443]}

##### do not touch anything below this line #####

import boto3, re, time
import logging, sys
logger = logging.getLogger()
logger.setLevel(logging.INFO)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


# CRUFT!
ids_ec2_instances_using_dynamicSG       = []

securityGroups         = {}
sgGroupidToRule        = {}
stGroupIdToDescription        = {}


def get_fw_rules(s, glist):
    resu            = []
    inst            = s.describe_instances()

    for x in inst[u'Reservations']:
        for y in range(len(x[u'Instances'])):
            inst    = x[u'Instances'][int(y)][u'InstanceId']
            stat    = x[u'Instances'][int(y)][u'State'][u'Name']
            ids_ec2_instances_using_dynamicSG.append(inst)

            if stat == 'running':
                pubi        = x[u'Instances'][int(y)][u'PublicIpAddress']

                for z in range(len(x[u'Instances'][int(y)][u'NetworkInterfaces'])):
                    for a in range(len(x[u'Instances'][int(y)][u'NetworkInterfaces'][int(z)][u'Groups'])):
                        sggr        = x[u'Instances'][int(y)][u'NetworkInterfaces'][int(z)][u'Groups'][int(a)][u'GroupId']

                        frpt        = sgGroupidToRule[sggr][0]
                        topt        = sgGroupidToRule[sggr][1]
                        cidr        = sgGroupidToRule[sggr][2]
                        groupName       = sgGroupidToRule[sggr][3]
                        desc        = sgGroupidToRule[sggr][4]

                for z in range(len(x[u'Instances'][int(y)][u'SecurityGroups'])):
                    groid       = x[u'Instances'][int(y)][u'SecurityGroups'][int(z)][u'GroupId']

                    if securityGroups.has_key(inst):
                        securityGroups[inst].append(groid)
                    else:
                        securityGroups[inst] = [groid]

    f       = open('/tmp/index.txt', 'w')

    for x in resu:
        f.write(str(x).strip())
        logger.info('RES: '+str(x).strip())
    f.close()

    secg    = s.describe_security_groups()
    dele    = []

    for x in set(ids_ec2_instances_using_dynamicSG):
        modi            = False

        for y in secg[u'SecurityGroups']:
            groid       = y[u'GroupId']
            desc        = y[u'Description']
            groupName       = y[u'GroupName']

            if re.search('/32_', groupName):
                unixt   = desc.split(' ')[3]

                if re.search(r"\b\d{10}\b", unixt):
                    z   = int(time.time()) - int(unixt)

                    if z > int(0):
                        if groid in securityGroups[x]:
                            securityGroups[x].remove(groid)

                        if y[u'GroupName'] not in dele:
                            dele.append(y[u'GroupName'])

                        modi    = True

                        logger.info( 'DEL: removing '+groid+', '+groupName+' from '+x+', age '+str(z/60)+' minutes, '+desc)
                    else:
                        logger.info( 'DEL: keeping '+groid+', '+groupName+' from '+x+', age '+str(z/60)+' minutes, '+desc)
                else:
                    logger.info( 'DEL: keeping '+groid+', '+groupName+' from '+x+', age '+str(z/60)+' minutes, '+desc)

            else:
                logger.info( 'DEL: keeping '+groid+', '+groupName+' from '+x+' , '+desc)

        if modi:
            s.modify_instance_attribute(Groups = securityGroups[x], InstanceId = x)

    return dele, resu




def whitelist_ip(ec2Client, ipToWhitelist):
    # For each public IP, find the ELB or EC2 instance using it
    elbClient = get_bolo_client('elb')
    loadbalancers = elbClient.describe_load_balancers()
    for lb in loadbalancers:


    ec2Instances = ec2Client.describe_instances(Filters=[
        {
            'Name': 'ip-address',
            'Values': [
                whiteListEC2Map.keys()
            ]
        },
    ])
    for instance in ec2Instances:
        instanceId    = x[u'Instances'][int(y)][u'InstanceId']
        s.modify_instance_attribute(Groups = a, InstanceId = instanceId)

http://boto3.readthedocs.io/en/latest/reference/services/elb.html#ElasticLoadBalancing.Client.describe_load_balancers
Remove API Gateway & lambda from Ohio  region

    for x in ec2Instances[u'Reservations']:
        for y in range(len(x[u'Instances'])):
            inst    = x[u'Instances'][int(y)][u'InstanceId']
            stat    = x[u'Instances'][int(y)][u'State'][u'Name']
            ids_ec2_instances_using_dynamicSG.append(inst)

            if stat == 'running':
                pubi        = x[u'Instances'][int(y)][u'PublicIpAddress']

                for z in range(len(x[u'Instances'][int(y)][u'NetworkInterfaces'])):
                    for a in range(len(x[u'Instances'][int(y)][u'NetworkInterfaces'][int(z)][u'Groups'])):
                        sggr        = x[u'Instances'][int(y)][u'NetworkInterfaces'][int(z)][u'Groups'][int(a)][u'GroupId']

                        frpt        = sgGroupidToRule[sggr][0]
                        topt        = sgGroupidToRule[sggr][1]
                        cidr        = sgGroupidToRule[sggr][2]
                        groupName       = sgGroupidToRule[sggr][3]
                        desc        = sgGroupidToRule[sggr][4]

                for z in range(len(x[u'Instances'][int(y)][u'SecurityGroups'])):
                    groid       = x[u'Instances'][int(y)][u'SecurityGroups'][int(z)][u'GroupId']

                    if securityGroups.has_key(inst):
                        securityGroups[inst].append(groid)
                    else:
                        securityGroups[inst] = [groid]

    # Create a SG with the appropriate ingress rule
    # Attach the new SG to the instance


    # Create the new SecurityGroup
    creationTime      = int(time.time())
    expireTime    = creationTime + int(dynamicWhitelistDurationSeconds)
    desc = 'ExpiresAt ' + str(expireTime)
    name = dynamicSGPrefix + 'ST-' +ipToWhitelist
    try:
        resp    = ec2Clientcreate_security_group(GroupName = name, Description = desc)
        sgid    = resp.get(u'GroupId')
        return sgid
    except Exception as e:
        logger.error( 'Unable to create SecuritGroup ['+name+']: '+str(e))

    # Then attached the SG to the appropriate instance or ELB
    s.modify_instance_attribute(Groups = securityGroups[x], InstanceId = x)




    for iid in set(ids_ec2_instances_using_dynamicSG):
        name        = cidr_ip+'/32_' + str(port)
        modi        = False

        crea_u      = int(time.time())
        crea_t      = time.strftime('%Y-%m-%d %H-%M-%S', time.localtime(crea_u))

        expire_u    = crea_u + int(dura)
        expire_t    = time.strftime('%Y-%m-%d %H-%M-%S', time.localtime(expire_u))

        desc        = str(crea_u) + ' ' + str(crea_t) + ' ' + str(expire_u) + ' ' + str(expire_t)

        if name not in glist:
            try:
                resp    = s.create_security_group(GroupName = name, Description = desc)
                sgid    = resp.get(u'GroupId')

                s.authorize_security_group_ingress(GroupId = sgid, IpProtocol = proto, CidrIp = cidr_ip+'/32', FromPort = int(port), ToPort = int(port))
                glist.append(name)
                modi    = True

            except Exception as e:
                logger.error( 'ERROR: '+str(e))

        else:
            for k, v in sgGroupidToRule.iteritems():
                if name     == v[2]+'_'+str(v[1]):
                    sgid    = k

        a           = securityGroups[iid]

        if modi:
            a.append(sgid)
            s.modify_instance_attribute(Groups = a, InstanceId = iid)


def get_bolo_client(serv):
    s               = boto3.session.Session()
    client         = s.client(serv, region_name = awsRegion )
    return client


def remove_expired_security_groups(client):
    groupIds = []
    securityGroups = client.describe_security_groups()

    # Check all dynamic SecurityGroups and delete any that have expired
    for sg in securityGroups['SecurityGroups']:
        groupName = sg['GroupName']
        if groupName.startswith( dynamicSGPrefix ):
            groupDesc = sg['Description']
            expireTime = groupDesc.split(' ')[1]
            timeTillExpiration   = int(time.time()) - int(expireTime)
            logger.info('timeTillExpiration= '+str(timeTillExpiration))
            if timeTillExpiration > int(0):
                try:
                    logger.info( 'DRY RUN: would have deleted GroupId='+ str(groupId) )
                    #s.delete_security_group(GroupId = groupId)
                except Exception as e:
                    logger.error( 'FAIL: failed deleting GroupId='+ str(GroupId).format( e))

            groupIds.append(sg['GroupId'])

    return groupIds

def lambda_handler(event, context):
    logger.info('got event{}'.format(event))
    ec2Client = get_bolo_client('ec2')
    dynGroupIds = remove_expired_security_groups(ec2Client)

    isAnAccessRequest  = event.get('ip', 'False')
    if isAnAccessRequest != 'False':
        ipToWhitelist       = event['ip']
        logger.info('Creating SG for '.format(ipToWhitelist))
        whitelist_ip(ec2Client, ipToWhitelist)
        result = 'FIN: created security groups to whitelist source IP '+ipToWhitelist+' for '+str(ruleDurationSeconds/60)+' minutes.'
        logger.info(result)
        return result
    else:
        return r

# CLI testing
ec2Client = get_bolo_client('ec2')
sgid = whitelist_ip(ec2Client,'173.73.153.176')
groupIds = remove_expired_security_groups(ec2Client)
logger.info(groupIds)
