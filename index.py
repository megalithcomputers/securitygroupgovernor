import os
import json 
import time
import boto3
from botocore.exceptions import ClientError

# for cloud9 env only, comment when deploying, and pass them via env variables
#os.environ['sns_topic_arn']="arn here"
#os.environ['own_username']="arn here"

# cloudformation passes everything as a string, hence the conversions
#os.environ['readonly']=str(0)

if 'readonly' in os.environ and int(os.environ['readonly']) == 0 or int(os.environ['readonly']) == 1:
    readonly = int(os.environ['readonly'])
else:
    readonly = 1

# setting to 0 will compare the app access tags on the sg and the instance, and if they do not match, detach them
ignoreappaccess = 1


def checktags(instancetags, sgs, message):
    keep = []
    detach = []
    ec2 = boto3.client('ec2')
    for sg in sgs:
        # ec2 and rds intance events have different dictionary keys for security groups.
        # ec2 has "groupId", and rds has vpcSecurityGroupId, so just dumping all vaues
        # then making sure they start with sg- (not necessary for ec2 but rds has extra items)
        groupid = list(sg.values())
        for i in groupid:
            if i[0:3] == 'sg-':
                groupid = i
                break
        response = ec2.describe_security_groups(GroupIds=[groupid])
        sginfo = response['SecurityGroups'][0]
        approved = 0
        appaccess = 0
        if 'Tags' in sginfo:
            for tag in sginfo['Tags']:
                if tag['Key'] == 'SecurityApproval':
                    if tag['Value'] == 'approved' or tag['Value'] == 'legacy':
                        approved = 1
                        print(groupid, ": has approved tag.")
                    else:
                        break
                elif tag['Key'] == 'AppAccess' and instancetags is not None:
                    sgappaccess = tag['Value']
                    print(groupid, ': sg AppAccess key is', sgappaccess)
                    for instancetag in instancetags:
                        if instancetag['Key'] == 'AppAccess':
                            if instancetag['Value'] == sgappaccess:
                                appaccess = 1
                                print(groupid, ": AppAccess on sg and instance match.")
                            else:
                                break
        elif 'Tags' not in sginfo:
            print(groupid, ": Security Group has no tags.")

        if ignoreappaccess == 1:
            appaccess = 1

        if appaccess == 0 or approved == 0:
            detach.append(groupid)
            print(groupid, ": group to be detached.")
            if appaccess == 0:
                message = (
                            message + groupid + ": The AppAccess tags on the security group and on the instance must match.\n")
            if approved == 0:
                message = (
                            message + groupid + ": The SecurityApproval tag on the security group must be set to \"approved\" or \"legacy\". \n")
        elif appaccess == 1 and approved == 1:
            keep.append(groupid)
            print(groupid, ": group will not be detached.")

    for i in keep:
        message = (message + "Security group " + i + " OK.\n")
    for i in detach:
        message = (message + "Security group " + i + " not compliant.\n")

    return keep, detach, message


def get_or_make_empty_sg(vpcid):
    ec2 = boto3.client('ec2')
    try:
        response = ec2.describe_security_groups(
            Filters=[
                {
                    'Name': 'group-name',
                    'Values': [
                        str('empty group assigned by sg governor ' + vpcid)
                    ]
                },
                {
                    'Name': 'tag:SecurityApproval',
                    'Values': [
                        str('approved')
                    ]
                }
            ]
        )
        keep = [response['SecurityGroups'][0]['GroupId']]
        print("Found existing empty security group to assign: ", keep[0])
    except:
        print("Existing empty group not found in same VPC, creating one.")
        try:
            response = ec2.create_security_group(
                Description='If an unapproved security group is detected, this is attached in its place.',
                GroupName='empty group assigned by sg governor ' + vpcid,
                VpcId=vpcid
            )
            keep = [response['GroupId']]
            print("Created: ", keep[0])
            ec2resource = boto3.resource('ec2')
            empty_sg = ec2resource.SecurityGroup(keep[0])
            # revoke the default 0.0.0.0/rule and add a pointless egress rule to prevent all outbound traffic
            response = empty_sg.revoke_egress(IpPermissions=empty_sg.ip_permissions_egress)
            response = empty_sg.authorize_egress(IpPermissions=[
                {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -1, 'IpRanges': [{'CidrIp': '127.0.0.1/32'}]}])
            response = empty_sg.create_tags(Tags=[{'Key': 'SecurityApproval', 'Value': 'approved'}])
        except ClientError as e:
            print(e.response['Error'])
            print("failure creating empty security group, see above response.")
    return keep


def lambda_handler(event, context):
    waitincrement = 1
    waitmax = 290

    ec = 0

    message = str()
    if readonly == 1:
        message = "-----=DRY RUN, NO CHANGES MADE=----- \n"
    changedback = 0

    print(event)
    # the sessionissuer doesn't always exist
    if 'sessionContext' in event['detail']['userIdentity'] and \
            'sessionIssuer' in event['detail']['userIdentity']['sessionContext'] and \
            'userName' in event['detail']['userIdentity']['sessionContext']['sessionIssuer']:
        # exit if this is one of the subevents of a db cluster event, etc; they look like ec2 events
        if event['detail']['userIdentity']['sessionContext']['sessionIssuer']['userName'] == 'AWSServiceRoleForRDS':
            print("subevent from RDS service role detected, exiting.")
            return
        # prevent recursion, own_username is provided by the cloudformation template
        if event['detail']['userIdentity']['sessionContext']['sessionIssuer']['userName'] == os.environ['own_username']:
            print("event was triggered by own username, exiting.")
            return

    # ignore failed API calls
    if 'errorCode' in event['detail']:
        print("ignoring failed event. API call failed with error: ", event['detail']['errorCode'])
        return

    # for ec2 instances
    if event['detail']['eventName'] == 'ModifyNetworkInterfaceAttribute' or \
            event['detail']['eventName'] == 'RunInstances':

        print("ec2 change detected")

        # iterate through multiple instances if multiple instances shown in "RunInstances" event
        if event['detail']['eventName'] == 'ModifyNetworkInterfaceAttribute':
            numinstances = 1
            print("event is ModifyNetworkInterfaceAttribute")
        elif event['detail']['eventName'] == 'RunInstances':
            numinstances = len(event['detail']['responseElements']['instancesSet']['items'])
            print("event is RunInstances, number of instances: ", numinstances)

        ec2 = boto3.client('ec2')
        for instancenum in range(numinstances):
            ec2resource = boto3.resource('ec2')
            if event['detail']['eventName'] == 'ModifyNetworkInterfaceAttribute':
                networkinterface = ec2resource.NetworkInterface(
                    event['detail']['requestParameters']['networkInterfaceId'])
                if 'InstanceId' not in networkinterface.attachment:
                    print("Network interface ", networkinterface.network_interface_id,
                          " has no instance ID attached, likely attached to a lambda. Exiting.")
                    return
                print("ModifyNetworkInterfaceAttribute event. Interface", networkinterface.network_interface_id,
                      "is attached to instance id", networkinterface.attachment['InstanceId'])
                ec2instance = ec2resource.Instance(networkinterface.attachment['InstanceId'])
                sgs = event['detail']['requestParameters']['groupSet']['items']

            # for starting new ec2 instances
            elif event['detail']['eventName'] == 'RunInstances':
                networkinterface = ec2resource.NetworkInterface(
                    event['detail']['responseElements']['instancesSet']['items'][instancenum]['networkInterfaceSet'][
                        'items'][0]['networkInterfaceId'])
                print("RunInstances event. Interface", networkinterface.network_interface_id,
                      "is attached to instance id", networkinterface.attachment['InstanceId'])
                ec2instance = ec2resource.Instance(networkinterface.attachment['InstanceId'])
                sgs = event['detail']['responseElements']['instancesSet']['items'][instancenum]['groupSet']['items']

            # initial sleep required before the API will show "pending", otherwise it shows running when it isn't
            time.sleep(5)
            waitcounter = 0
            while waitcounter < waitmax:
                time.sleep(waitincrement)
                response = ec2.describe_instance_status(
                    InstanceIds=[ec2instance.instance_id]
                )
                # sometimes we get a blank response from the API
                if len(response['InstanceStatuses']) == 0 or response['InstanceStatuses'][0]['InstanceState'][
                    'Name'] == 'pending':
                    waitcounter += 1
                    continue
                else:
                    break
            print("had to wait ", waitcounter, "counts of ", waitincrement, "second(s)")

            instancename = str()
            message = str(
                message + "\nSecurity group governor message regarding instance: " + networkinterface.attachment[
                    'InstanceId'] + "\n")
            if ec2instance.tags is not None:
                for instancetag in ec2instance.tags:
                    if instancetag['Key'] == 'Name':
                        instancename = instancetag['Value']
                        message = str(message + "Instance name is: " + instancename + "\n")

            keep, detach, message = checktags(ec2instance.tags, sgs, message)

            if len(detach) > 0 and readonly == 0:
                if len(keep) == 0:
                    # if there are no compliant security groups, a new, empty one must be created
                    response = ec2.describe_security_groups(GroupIds=detach)
                    vpcid = response['SecurityGroups'][0]['VpcId']
                    keep = get_or_make_empty_sg(vpcid)
                try:
                    response = ec2.modify_network_interface_attribute(
                        Groups=keep,
                        NetworkInterfaceId=networkinterface.network_interface_id
                    )
                    changedback = 1
                except ClientError as e:
                    print(e.response['Error'])
                    print("EC2 instance update failed due to above error")
                    changedback = 0

    # DBs
    elif event['detail']['eventName'] == 'ModifyDBCluster' or \
            event['detail']['eventName'] == 'ModifyDBInstance' or \
            event['detail']['eventName'] == 'CreateDBCluster' or \
            event['detail']['eventName'] == 'CreateDBInstance':
        cluster = 0
        instance = 0
        rds = boto3.client('rds')
        ec2 = boto3.client('ec2')

        # aurora clusters
        if event['detail']['eventName'] == 'ModifyDBCluster' or \
                event['detail']['eventName'] == 'CreateDBCluster':
            cluster = 1
            dbidentifier = event['detail']['responseElements']['dBClusterIdentifier']
            dbarn = event['detail']['responseElements']['dBClusterArn']
            message = str("Security group governor message regarding DB cluster: " + dbidentifier + "\n")

            # it takes a few seconds for "modifying" to even show up to the API's describe function,
            # so requires initial sleep, then a wait loop
            time.sleep(5)
            waitcounter = 0
            while waitcounter < waitmax:
                time.sleep(waitincrement)
                response = rds.describe_db_clusters(
                    DBClusterIdentifier=dbidentifier
                )
                print(response)
                if response['DBClusters'][0]['Status'] != 'available':
                    waitcounter += 1
                    continue
                else:
                    break
            print("had to wait ", waitcounter, "counts of ", waitincrement, "second(s)")

        # rds instances
        elif event['detail']['eventName'] == 'ModifyDBInstance' or \
                event['detail']['eventName'] == 'CreateDBInstance':
            if 'dBClusterIdentifier' in event['detail']['requestParameters']:
                print("Instance is part of a cluster, likely RDS subevent, exiting.")
                return
            instance = 1
            dbidentifier = event['detail']['requestParameters']['dBInstanceIdentifier']
            dbarn = event['detail']['responseElements']['dBInstanceArn']
            message = str("Security group governor message regarding DB instance: " + dbidentifier + "\n")

            time.sleep(5)
            waitcounter = 0
            while waitcounter < waitmax:
                time.sleep(waitincrement)
                response = rds.describe_db_instances(
                    DBInstanceIdentifier=dbidentifier
                )
                if len(response['DBInstances']) == 0 or response['DBInstances'][0]['DBInstanceStatus'] != 'available':
                    waitcounter += 1
                    continue
                else:
                    break
            print("had to wait ", waitcounter, "counts of ", waitincrement, "second(s)")

        print("DB instance", dbidentifier, "modified.")
        rdstags = rds.list_tags_for_resource(ResourceName=dbarn)
        sgs = event['detail']['responseElements']['vpcSecurityGroups']
        keep, detach, message = checktags(rdstags['TagList'], sgs, message)

        if len(detach) > 0 and readonly == 0:
            if len(keep) == 0:
                # if there are no compliant security groups, a new, empty one must be created
                response = ec2.describe_security_groups(GroupIds=detach)
                vpcid = response['SecurityGroups'][0]['VpcId']
                keep = get_or_make_empty_sg(vpcid)
            if cluster == 1:
                try:
                    response = rds.modify_db_cluster(
                        # note: in aurora serverless clusters, instead of the db identifier, it really expects the ARN (apparent AWS bug)
                        #      to do: detect aurora serverless and work around, or wait for AWS to fix it
                        # DBClusterIdentifier=dbarn,
                        DBClusterIdentifier=dbidentifier,
                        VpcSecurityGroupIds=keep
                    )
                    changedback = 1
                except ClientError as e:
                    print(e.response['Error'])
                    print("DB cluster update failed due to above error.")
                    changedback = 0
            elif instance == 1:
                try:
                    response = rds.modify_db_instance(
                        DBInstanceIdentifier=dbidentifier,
                        VpcSecurityGroupIds=keep
                    )
                    changedback = 1
                except ClientError as e:
                    print(e.response['Error'])
                    print("DB instance update failed due to above error")
                    changedback = 0

    # exit if no matching event
    else:
        print("No matching events found.")
        return 0

    if changedback == 1:
        message = (message + "Noncompliant security groups detached.")
    if changedback == 0:
        message = (
                    message + "Noncompliant security groups could not be detached automatically, please remove them manually to maintain compliance.")
        ec = 1

    print(message)

    if len(detach) > 0:
        # get own account name, use account number if no name(alias) is available
        try:
            iam = boto3.client('iam')
            accountname = iam.list_account_aliases()['AccountAliases'][0]
        except:
            sts = boto3.client('sts')
            accountname = sts.get_caller_identity()['Account']
        boto3.client('sns').publish(
            TargetArn=os.environ['sns_topic_arn'],
            Message=message,
            Subject=str("Unapproved security group(s) detected in account: " + accountname)
        )
    return ec
