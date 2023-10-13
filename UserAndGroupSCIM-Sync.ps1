## Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: MIT-0

param(
    $awsRegion = "us-east-2"
)

function Format-UserInfo {
    param (
        $user, $iamidcUserID, $sidMatchFound
    )

    $subEmails = @()
    $subEmails += [pscustomobject]@{
        "value"=$user.userPrincipalName;
        "type"="work";
        "primary"="true";
    }

    $jsonBody = [PSCustomObject]@{
        "id" = $iamidcUserID;
        "externalId" = $user.sid.Value;
        "userName" = $user.userPrincipalName;
        "name" = @{
        "formatted" = $user.givenName + " " + $user.sn;
        "familyName" = $user.sn;
        "givenName" = $user.givenName;
        };
        "displayName" = $user.displayName;
        "title" = $user.title;
        "active" = $user.Enabled;
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User" = @{
        "organization" = $user.Company;
        "department" = $user.department;
        }
        emails = $subEmails
    }

    #Need to remove the "id" property if this is a new user creation in IDC as it will be null until the user is created
    if (! $sidMatchFound)
    {
        $jsonBody.PSObject.properties.Remove("id")
    }
    $jsonBody = $jsonBody | ConvertTo-JSON -Depth 3
    return $jsonBody
}

#Retrieve URI and AD Group Name from AWS SSM Parameter Store
$uri = (Get-SSMParameter -Name /IAM-IDC/SCIM-URI -WithDecryption $true -Region $awsRegion).Value
$uriUsers = $uri + "Users"
$uriGroups = $uri + "Groups"


$ADGroupName = (Get-SSMParameter -Name /IAM-IDC/AD-Group-Name -WithDecryption $true -Region $awsRegion).Value

$ADDC = (Get-SSMParameter -Name /IAM-IDC/Domain-Controller -WithDecryption $true -Region $awsRegion).Value

#Retreive the SCIM API Token from AWS Secrets Manager
$scimToken = Get-SECSecretValue -SecretId "IAM-IDC/SCIM-API-Token" -Select SecretString -Region $awsRegion | ConvertFrom-Json | Select-Object -ExpandProperty SCIM-API-Token | ConvertTo-SecureString -AsplainText -Force

#Gather the group prefix and location for the groups that need to be reviewed and created/updated
$searchBase = (Get-SSMParameter -Name /IAM-IDC/AD-Search-Base -WithDecryption $true -Region $awsRegion).Value
$groupPrefix = (Get-SSMParameter -Name /IAM-IDC/AD-Group-Prefix -WithDecryption $true -Region $awsRegion).Value

#Retrieve the AD Username and Password from AWS Secrets Manager
$userName = Get-SECSecretValue -SecretId "IAM-IDC/AD-RO-UserCreds" -Select SecretString -Region $awsRegion | ConvertFrom-Json | Select-Object -ExpandProperty username
$userPassword = Get-SECSecretValue -SecretId "IAM-IDC/AD-RO-UserCreds" -Select SecretString -Region $awsRegion | ConvertFrom-Json | Select-Object -ExpandProperty userPassword | ConvertTo-SecureString -AsplainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ($userName, $userPassword)


#Scan AD for groups which start with AWS-* and for each group check IAM IDC to see if it exists.  Create the group if it doesn't exist.
#Once/if the group exists check the members list and add/remove users as appropriate.
#Get all AD groups in scope
try {
    $adGroups = Get-ADGroup -Filter "Name -like '$groupPrefix'" -SearchBase $searchBase -Credential $Credential -Server $ADDC
}
catch {
    Write-Output($_.Exception.Message)
}
Write-Output("AD Group Count = " + $adGroups.Count)

#Iterate through AD groups list and query IDC to see if group exists.  If it does not exist create it and add members using the IDC group ID returned by the create.
#If it does exist execute a member removal first by obtaining all IDC group members and compare that against AD.  If the user exists in IDC and not in the AD group membership remove them.  Then flip the iteration
#around and go through the AD group membership, comparing against IDC group membership and if the user isn't there add them.
foreach ($adGroup in $adGroups)
{
    if ($adGroup.Name.ToLower() -ne $ADGroupName.ToLower())
    {
        $uriFindGroups = $uriGroups+"?filter=displayName%20eq%20"""+$adGroup.Name+""""
        $responseGroupsGet = Invoke-RestMethod -Uri $uriFindGroups -Authentication Bearer -Method Get -Token $scimToken -Headers @{"Cache-Control"="no-cache"}
        if ($responseGroupsGet.totalResults -eq 0)
        {
            Write-Output ("The group " + $adGroup.Name + " does not exists in IDC and will be created.")
            $jsonBody = [PSCustomObject]@{
                "displayName" = $adGroup.Name;
            }
            $jsonBody = $jsonBody | ConvertTo-JSON -Depth 3

            Write-Output ("Creating IAM IDC group from AD group object " + $adGroup.Name)
            $responseGroupPost = Invoke-RestMethod -Uri $uriGroups -Authentication Bearer -Method Post -Body $jsonBody -Token $scimToken -Headers @{"Cache-Control"="no-cache"}
            Write-Output ($responseGroupPost)
        }
        else {
            Write-Output ("The group " + $adGroup.Name + " already exists in IDC.")
        }
    }
}

# Install requirements
$requirements = @(
    "ActiveDirectory"
    "AWS.Tools.SecretsManager",
    "AWS.Tools.SimpleSystemsManagement"
)

foreach ($requirement in $requirements) {
    try {
        Write-Debug "Importing ${requirement}..."
        Import-Module $requirement -ErrorAction Stop -WarningAction Stop -Force
    }
    catch {
        Install-Module $requirement -Force -Scope CurrentUser
        Import-Module $requirement  -ErrorAction Stop -Force
    }
}

#Now retrieve a list of all groups in IAM IDC.  This will be used later to sync user membership
$responseGroupsGet = Invoke-RestMethod -Uri $uriGroups -Authentication Bearer -Method Get -Token $scimToken -Headers @{"Cache-Control"="no-cache"}
$iamIDCGroups = $responseGroupsGet.Resources


#Get the members of the AD group name retrieved from SSM and gather their key attributes to support IAM IDC sync
$groupMembers = Get-ADGroupMember -Identity $ADGroupName -Credential $Credential -Server $ADDC | Select-Object name, sid

Write-Output ("Retrieved group members for the AD group $ADGroupName and found a total of " + $groupMembers.Count + " group members.")

foreach ($groupMember in $groupMembers)
{
    $user = Get-ADUser -Identity $groupMember.sid -Properties name,sid,userPrincipalName,Company,givenName,sn,displayName,department,title,Enabled -Credential $Credential -Server $ADDC

    $userLookupURI = $uriUsers+"?filter=externalId%20eq%20"""+$user.SID.Value+""""
    Write-Output ("Checking if user " + $user.UserPrincipalName + " exists in IAM IDC based on a AD SID to IAM IDC externalId match of " + $user.SID)
    $responseGetUser = Invoke-RestMethod -Uri $userLookupURI -Authentication Bearer -Method Get -Token $scimToken -Headers @{"Cache-Control"="no-cache"}
    if ($responseGetUser.totalResults -eq 1)
    {
        Write-Output ("Found a match between the IAM IDC external ID and the AD User's SID")
        Write-Output ("IAM IDC user:  " + $responseGetUser.Resources[0].userName + "     AD User:  " + $user.UserPrincipalName)
        $sidMatchFound = $true
        $iamidcUserID = $responseGetUser.Resources[0].id
    }
    else {
        Write-Output ("No match for the SID in IAM IDC.  Creating a new user with the username " + $user.UserPrincipalName)
        $sidMatchFound = $false
    }

    #ExternalId will be the user's SID
    if ($sidMatchFound)
    {
        #Update existing IAM IDC user
        $jsonBody = Format-UserInfo -user $user -iamidcUserID  $iamidcUserID -sidMatchFound  $sidMatchFound
        $updateURI = $uriUsers + "/" + $iamidcUserID
        $responseUserPut = Invoke-RestMethod -Uri $updateURI -Authentication Bearer -Method Put -Body $jsonBody -Token $scimToken -Headers @{"Cache-Control"="no-cache"}
        $responseUserPut
    }
    else
    {
        #Create new IAM IDC user
        $jsonBody = Format-UserInfo -user $user -iamidcUserID  $iamidcUserID -sidMatchFound  $sidMatchFound
        $responseUserPost = Invoke-RestMethod -Uri $uriUsers -Authentication Bearer -Method Post -Body $jsonBody -Token $scimToken -Headers @{"Cache-Control"="no-cache"}
        $responseUserPost

        #Retrieving IAM IDC user ID for later use
        $responseGetUser = Invoke-RestMethod -Uri $userLookupURI -Authentication Bearer -Method Get -Token $scimToken -Headers @{"Cache-Control"="no-cache"}
        $iamidcUserID = $responseGetUser.Resources[0].id
    }

    #Now sync the user's membership in the IAM IDC groups
    #Get all groups the user is a member of that match the prefix provided and are in the specified OU
    #Example:  Get-ADPrincipalGroupMembership dncmatt -server corp.aws-md.com | Where-Object {$_.distinguishedName -Like "*OU=AWS,OU=CORP,OU=LOB,DC=corp,DC=aws-md,DC=com" -And $_.name -Like "AWS-*" } | select name
    $userADGroupMemberships = Get-ADPrincipalGroupMembership $user.SamAccountName -Credential $Credential -server $ADDC | Where-Object {$_.distinguishedName -Like "*" + $searchBase -And $_.name -Like $groupPrefix + "*" } | Select-Object name

    #Now iterate through all IAM IDC groups and add/remove the user as needed
    foreach ($iamGroup in $iamIDCGroups)
    {
        foreach ($userADGroup in $userADGroupMemberships)
        {
            $groupMatchFound = $false
            if ($userADGroup.name -eq $iamGroup.displayName)
            {
                $groupMatchFound = $true
                Write-Output("Building the JSON to ADD the user " + $user.UserPrincipalName + " to the IAM IDC group " + $iamGroup.displayName)
                $subValue = @()
                $subValue += [pscustomobject]@{
                    "value"=$iamidcUserID;
                }
                $subOperations = @()
                $subOperations += [PSCustomObject]@{
                    "op" = "add";
                    "path" = "members"
                    value = $subValue
                }
                $jsonBody = [PSCustomObject]@{
                    Operations = $subOperations
                }
                $uriGroupUpdate = $uriGroups + "/" + $iamGroup.id
                $jsonBody = $jsonBody | ConvertTo-JSON -Depth 4
                Invoke-RestMethod -Uri $uriGroupUpdate -Authentication Bearer -Method Patch -Body $jsonBody -Token $scimToken -Headers @{"Cache-Control"="no-cache"}
                break
            }
        }
        if (!$groupMatchFound)
        {
            #Remove user from the IAM IDC group
            Write-Output("Building the JSON to REMOVE the user " + $user.UserPrincipalName + " from the IAM IDC group " + $iamGroup.displayName)
            $subValue = @()
            $subValue += [pscustomobject]@{
                "value"=$iamidcUserID;
            }
            $subOperations = @()
            $subOperations += [PSCustomObject]@{
                "op" = "remove";
                "path" = "members"
                value = $subValue
            }
            $jsonBody = [PSCustomObject]@{
                Operations = $subOperations
            }
            $uriGroupUpdate = $uriGroups + "/" + $iamGroup.id
            $jsonBody = $jsonBody | ConvertTo-JSON -Depth 4
            Invoke-RestMethod -Uri $uriGroupUpdate -Authentication Bearer -Method Patch -Body $jsonBody -Token $scimToken -Headers @{"Cache-Control"="no-cache"}
        }
    }

    $sidMatchFound = $false
    $iamidcUserID = ""
}
