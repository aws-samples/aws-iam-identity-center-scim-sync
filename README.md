## AWS IAM Identity Center SCIM Sync

## Overview
This repo contains a PowerShell script and AWS CloudFormation templates used to establish a container-based environment to periodically sync Active Directory / LDAP users and groups to AWS IAM Identity Center using SCIM where customers are federating with a service that does not natively support SCIM.
 - This repo is based on the steps outlined in this [article](URL-to-be-provided) updated July 2023.

##Architectural Drawing
![AWS Fargate runs the PowerShell script from a container image in Amazon Elastic Container Registry which retrieves credentials from AWS Secrets Manager, gathers runtime parameters from AWS Systems Manager Parameter Store, queries the on-premises Active Directory, and uses SCIM to perform CRUD actions on AWS IAM Identity Center users and groups. ](https://github.com/aws-samples/aws-iam-identity-center-scim-sync/blob/main/images/architectural-diagram.jpg?raw=true)


## July 2023
Initial content push.

## Getting Started

### Prerequisites

 - You have already enabled and configured AWS IAM Identity Center with ADFS as the External Identity Provider.
 - You have enabled automatic provisioning and noted the SCIM API endpoint and SCIM token.
 - You have created an AD user account with read-only permissions to the AD objects that will be synced.
 - You have configured an Outbound Resolver in Amazon Route 53 to support resolution of on-premises domain controllers from the AWS environment.
 - You have an Amazon Virtual Private Cloud (VPC) with a private subnet with a NAT gateway and connectivity to the on-premises AD environment.
 - You have Docker Desktop installed on a machine to build the container image that will run the PowerShell script.
 - You have installed AWS CLI v2 on the machine where the container image is built and have a configured the CLI to access the AWS account where the solution will be hosted.

### Deployment

#### AWS Secrets Manager and AWS Systems Manager Parameter Store

- Deploy the SecretsManagerAndSSM.json CloudFormation template

#### Create and publish the container image

- Authenticate to the target AWS account using the AWS CLI v2
- Use the "Push Commands" from the AWS Elastic Container Repository to create and push the container image

#### Amazon ECS Fargate cluster and task creation

- Deploy the ECSFargate.json CloudFormation template

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.