Security Group Governor - control the usage of AWS security groups (firewall rulesets) based on tags.

Many large organizations require that firewall rules be approved by a separate team which handles security. In AWS, this usually means that for regular users the ability to create and edit security groups is disabled, and they are required to ask a security team to do it for them so that they can ensure compliance with whatever regulatory framework they are using.

This could be handled by having developers or a DevOps team write their infrastructure (including security groups) in something like Terraform or CloudFormation, check it into a repo, and then a security team can approve it there and have it feed into a CI/CD pipeline which then creates all of the resources.

But maybe for whatever reason this isn't an option -- for example, maybe you have lots of legacy applications and can't rewrite them all as infrastructure as code in order to solve this problem, and want to simply control access to the security groups based on tags.

Then your workflow would be:
1) The user/developer creates a security group.
2) The security team approves the security group by setting a tag on the security group.
3) The user is then allowed to attach the security group to their resources.

Some of this can be done in IAM, but IAM currently lacks the granularity to prevent attaching a security group to a resource based on the resource tags of the security group**. That's why the lambda and all of the associated resources like cloudtrail and cloudwatch events are required.

Security Group Governor is made of two main components:
1) IAM Rules. These rules prevent the user from setting the “SecurityApproval” tag value to “approved” or “legacy”, and prevents the user from editing the rules within the security group when these tags are set.
2) A lambda function. This is triggered by events where the security groups attached to resources can be changed, then it evaluates the security groups, and if any of them don't have the "SecurityApproval : approved" value, they are detached from the resource

The IAM rules are relatively simple compared to the lambda, which has to process the various types of events where security groups can be changed and then respond appropriately.

This can be deployed with regular cloudformation stacks, as well as stacksets.

Deployment Steps:
1) Create an S3 Bucket to store the index.zip that will hold the lambda.
2) Zip up the index.py and upload it to the s3 bucket.
3) In the account where you are deploying, you will need to add a tag to all the existing security groups
   so they are ignored by the lambda.
    
    3a) Go to Resource Groups - > Tag editor
    
    3b) Pick the security group resource type and select all groups
    
    3c) Add the tag "SecurityApproval" with a value "approved" or "legacy"
4) Deploy the cloudformation template and set the LambdaReadOnly variable to 1.
5) Test it out a bit, attach a security group with and without the tags and make sure the lambda is writing logs properly. 
   (NOTE: If you did not already have cloudtrails enabled, it make take an hour or so for the events start processing.)
6) Apply the "prevent_modify_approved" policy that came with the cloudformation script to users who will be subject to the 
   access control rules.
7) After you have read the logs while the lambda is in readonly mode for a while, you can update the cloudformation stack to set
   the readonly value to 0.
8) Any terraform or cloudformation scripts that create security groups will have to be updated to set the SecurityApproval:approved 
   tag. This is part of the reason to run it in read-only mode for a while: so you can see what scripts (if any) need an update.

NOTE: If you already have a cloudtrail enabled in the account and don't want another trail, you can take out the cloudtrail portion in the cloudformation script.

Please let me know if you have any questions or bug reports.

** You could prevent the RunInstances and StartInstances API call, but not ModifyNetworkInterface. Then if you wanted, you could prevent access to the to the ModifyNetworkInterface API call unless the ec2 instance was down, which would force users to shut down their ec2 instance in order to change the associated security groups or ANY other network interface parameter.
