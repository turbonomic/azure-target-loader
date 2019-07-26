<#
.SYNOPSIS
This script will add Azure targets to your Turbonomic instances using a CSV file with the target information.

.DESCRIPTION
Use this script to add Azure targets into Turbonomic using a CSV file as well as add the Reader role to the Clients specified in the CSV file. If the target already exists inside of Turbonomic, this script will update the credentials to what you specify in the CSV. 

The CSV file must have the following columns:

    - Address
    - Tenant Name
    - Username
    - Client Id
    - Client Secret Key
    - Proxy Host
    - Proxy Port

Make sure that all columns are present in the CSV. Proxy Host and Proxy Host values are not mandatory for individual rows, but the columns must be present in the Csv.

Note: If you are using PowerShell Core, this script supports PowerShell Core Version 6.0 Beta 9 and above.

.EXAMPLE
AzureTargetLoader.ps1 -CsvFilePath ./AzureTargets.Csv

This will add the Azure targets specified in the CSV file to the Turbonomic server. It will also add the Reader and Storage Account Contributor role to the users specified in the CSV to the Azure subscription. The script will prompt for all other values.

.EXAMPLE
AzureTargetLoader.ps1 -TurboInstance turbonomic.mycompany.com -TurboCredential $TurboCred -CsvFilePath ./AzureTargets.Csv

This will add the Azure targets specified in the CSV file to the Turbonomic server turbonomic.mycompany.com using the Turbonomic credentials specified. It will also add the Reader and Storage Account Contributor role to the users specified in the CSV to the Azure subscription.

.EXAMPLE
AzureTargetLoader.ps1 -AddMode TargetsOnly -TurboInstance turbonomic.mycompany.com -TurboCredential $TurboCred -CsvFilePath ./AzureTargets.Csv

This will only add the Azure targets specified in the CSV file to the Turbonomic server turbonomic.mycompany.com using the Turbonomic credentials specified. 

.EXAMPLE
AzureTargetLoader.ps1 -AddMode AzurePermissionsOnly -CsvFilePath ./AzureTargets.Csv

This will only add the Reader and Storage Account Contributor role to the users specified in the CSV to the Azure subscription.

.PARAMETER TurboInstance
Specify the Turbonomic server hostname, FQDN, or IP address where you are adding the targets.

.PARAMETER TurboCredential
Specify the credentials for the Turbonomic server. This must be a PSCredential object. You can use the Get-Credential cmdlet to create a variable to store your credentials and then pass the variable to this parameter.

.PARAMETER CsvFilePath
The path to the CSV file that contains all the Azure Target information.

.PARAMETER AddMode
Choose whether you want to add only Turbonomic targets, add Azure Permissions, or Both. Default is both. Valid data is:

    - Both
    - AzurePermissionsOnly
    - TargetsOnly

.PARAMETER TurboHttps
Boolean value that determines whether to communicate to Turbonomic over https. Default is true.

#>

param (
    [string] $TurboInstance,
    
    [System.Management.Automation.CredentialAttribute()] $TurboCredential,

    [Parameter(Mandatory=$True)]
    [string] $CsvFilePath,

    [ValidateSet("Both","AzurePermissionsOnly", "TargetsOnly")]
    [string] $AddMode = "TargetsOnly",

    [bool] $TurboHttps = $true
)

# Because Turbonomic is normally installed with self-signed certs, we need PowerShell to allow a self-signed cert.
function _SetCertPolicy {
    if ($PSVersionTable.PSEdition -eq 'Core') {
        if ($PSDefaultParameterValues.Contains("Invoke-RestMethod:SkipCertificateCheck")){
            $PSDefaultParameterValues["Invoke-RestMethod:SkipCertificateCheck"] = $true
        } else {
            $PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck", $true)
        }
        if ($PSDefaultParameterValues.Contains("Invoke-WebRequest:SkipCertificateCheck")){
            $PSDefaultParameterValues["Invoke-WebRequest:SkipCertificateCheck"] = $true
        } else {
            $PSDefaultParameterValues.Add("Invoke-WebRequest:SkipCertificateCheck", $true)
        }
    } else {
        Add-Type -TypeDefinition @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy
    }
}


function CheckAzureModule() {
    Write-Information "Checking if the AzureRM PowerShell module is installed"
    if (-Not (Get-command "New-AzureRMRoleAssignment" -ErrorAction SilentlyContinue)){
        Write-Error "AzureRM module not installed. Please install before continuing."
        exit
    }
}

function ReadCsvFile($fileName) {
    $ColumnsExpected = @( 'Address', 'Tenant Name', 'Username', 'Client Id', 'Client Secret Key', 'Proxy Host', 'Proxy Port')
    $csvFile = Import-Csv $fileName
    $columns = $csvFile | get-member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    $columnsOk = $True
    $ColumnsExpected | ForEach-Object {
        if ($columns -notcontains $_) {
            $columnsOk = $False
            "Expected column not found: '$($_)'" | Write-Error
        }
    }
    if (-not $columnsOk) {
        ThrowError "The csv format is incorrect!"
    } else {
        return $csvFile
    }

}

# This creates the Azure Target in Turbonomic using the Turbonomic REST API
function CreateAzureTarget($Address, $TenantName, $Username, $ClientId, $ClientSecretKey, $ProxyHost, $ProxyPort){
    $targetDTO = @{
        "category"="Cloud Management";
        "type"="Azure";
        "inputFields"=@(
            @{"value"=$Address;"name"="address"};
            @{"value"=$TenantName;"name"="tenant"};
            @{"value"=$Username;"name"="username"};
            @{"value"=$ClientId;"name"="client"};
            @{"value"=$ClientSecretKey;"name"="key"},
            @{"value"=$ProxyHost;"name"="proxy"};
            @{"value"=$ProxyPort;"name"="port"});
        "uuid"=$null
    }

    $targetDTOJson = $targetDTO | ConvertTo-Json
    $uri = "{0}://{1}/vmturbo/rest/targets" -f $protocol, $TurboInstance
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-RestMethod -Uri $uri -Method Post -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo); "Content-Type"="application/json"} -Body $targetDTOJson -ErrorAction SilentlyContinue
    $output = "{0} target added." -f $Address
    Write-Information $output
}

function GetAllTargets(){
    $uri = "{0}://{1}/vmturbo/rest/targets" -f $protocol, $TurboInstance
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-RestMethod -Uri $uri -Method Get -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo); "Content-Type"="application/json"} -ErrorAction SilentlyContinue

}

function GetTargetUUID($username) {
    Write-Information "Here"
    $targetUUID = $null
    foreach($existingTarget in $existingTargets){
        $targetUN = $existingTarget | Select-Object -ExpandProperty inputFields | Where-Object {$_.Name -eq "Username"}
        if ($username -eq $targetUN.value){
            $targetUUID = $existingTarget | Select-Object -ExpandProperty uuid            
        }
    }
    $targetUUID
}

function UpdateAzureTargetCredentials($uuid, $Address, $TenantName, $Username, $ClientId, $ClientSecretKey, $ProxyHost, $ProxyPort){        
    $targetDTO = @{
        "category"="Cloud Management";
        "type"="Azure";
        "inputFields"=@(
            @{"value"=$Address;"name"="address"};
            @{"value"=$TenantName;"name"="tenant"};
            @{"value"=$Username;"name"="username"};
            @{"value"=$ClientId;"name"="client"};
            @{"value"=$ClientSecretKey;"name"="key"},
            @{"value"=$ProxyHost;"name"="proxy"};
            @{"value"=$ProxyPort;"name"="port"});
        "uuid"=$uuid
    }

    $targetDTOJson = $targetDTO | ConvertTo-Json
    $uri = "{0}://{1}/vmturbo/rest/targets/{2}" -f $protocol, $TurboInstance, $uuid
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-RestMethod -Uri $uri -Method Put -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo); "Content-Type"="application/json"} -Body $targetDTOJson -ErrorAction SilentlyContinue
    $output = "{0} target update." -f $Address
    Write-Information $output
}






# This function will add the appropriate Azure roles to the Application ID specific for Turbonomic to target it
function SetAzurePermissions ($ApplicationId, $SubscriptionId) {
    $objectId = Get-AzureRmADServicePrincipal | Where-Object {$_.ApplicationId -eq $ApplicationId} | Select-Object -ExpandProperty Id  | select-object -ExpandProperty Guid
    if($objectId -ne $null){
        $scope = "/subscriptions/{0}" -f $subscriptionId
        New-AzureRmRoleAssignment -ObjectId $objectId -Scope $scope -RoleDefinitionName Reader
        New-AzureRmRoleAssignment -ObjectId $objectId -Scope $scope -RoleDefinitionName "Storage Account Contributor"
    } else {
        Write-Error -Message "Invalid ApplicationId: $ApplicationId"
        exit
    }
    
}


# Script starts here
try {
    $targets = ReadCsvFile $CsvFilePath
} catch {
    Write-Error -Message "CSV file at $CsvFilePath could not be read."
    exit
}

_SetCertPolicy

$protocol = "http"
if ($TurboHttps){
    $protocol = "https"
}

if($AddMode -ne "AzurePermissionsOnly") {
    
    if($TurboCredential -eq $null) {
        $TurboCredential = Get-Credential -Message "Enter the credentials used to sign in to the Turbonomic server."
    }

    if(($TurboInstance -eq $null) -or $TurboInstance -eq "") {
        $TurboInstance = Read-Host -Prompt "Enter the IP Address, FQDN, or Hostname of the Turbonomic Server"
    }

    $TurboPassword = $TurboCredential.GetNetworkCredential().password
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $TurboCredential.username,$TurboPassword)))
    $existingTargets = GetAllTargets | Where-Object {$_.type -eq "Azure"}

}





if($AddMode -ne "TargetsOnly") {
    CheckAzureModule
    Read-Host -Prompt "This script will now use your Azure credentials to access Azure PowerShell. The user you use to log in should have the appropriate privelege to add the Reader role to all users in the CSV file provided.
Press Enter to continue"
    Login-AzureRmAccount
}

# Go through each item in the CSV and add the permission to Azure and/or add the Target to Turbo
foreach ($target in $targets) {
    if ($AddMode -ne "TargetsOnly") {
        SetAzurePermissions $target."Client Id" $target."Username"
    }

    if ($AddMode -ne "AzurePermissionsOnly") {
            $existingTargetUUID = GetTargetUUID $target."Username"

            
            if($null -ne $existingTargetUUID){
                UpdateAzureTargetCredentials $existingTargetUUID $target."Address" $target."Tenant Name" $target."Username" $target."Client Id" $target."Client Secret Key" $target."Proxy Host" $target."Proxy Port"
            } else {
                CreateAzureTarget $target."Address" $target."Tenant Name" $target."Username" $target."Client Id" $target."Client Secret Key" $target."Proxy Host" $target."Proxy Port"
            }
    }
}


