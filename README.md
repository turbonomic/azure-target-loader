SYNOPSIS
========
This script will add Azure targets to your Turbonomic instances using a CSV file with the target information.

DESCRIPTION
===========
Use this script to add Azure targets into Turbonomic using a CSV file as well as add the Reader role to the Clients specified in the CSV file. If the target already exists inside of Turbonomic, this script will update the credentials to what you specify in the CSV.

The CSV file must have the following columns:

* Address
* Tenant Name
* Username
* Client Id
* Client Secret Key
* Proxy Host
* Proxy Port

Make sure that all columns are present in the CSV. Proxy Host and Proxy Host values are not mandatory for individual rows, but the columns must be present in the CSV file.


PARAMETER: TurboInstance
------------------------
Specify the Turbonomic server hostname, FQDN, or IP address where you are adding the targets.

PARAMETER: TurboCredential
--------------------------
Specify the credentials for the Turbonomic server. This must be a PSCredential object. You can use the Get-Credential cmdlet to create a variable to store your credentials and then pass the variable to this parameter.

PARAMETER: CsvFilePath
----------------------
The path to the CSV file that contains all the Azure Target information.

PARAMETER: AddMode
------------------
Choose whether you want to add only Turbonomic targets, add Azure Permissions, or Both. Default is both. Valid data is:

* Both
* AzurePermissionsOnly
* TargetsOnly

PARAMETER: TurboHttps
---------------------
Boolean value that determines whether to communicate to Turbonomic over https. Default is true.

EXAMPLE 1
=========
This will add the Azure targets specified in the CSV file to the Turbonomic server. It will also add the Reader and Storage Account Contributor role to the users specified in the CSV to the Azure subscription. The script will prompt for all other values.

    AzureTargetLoader.ps1 -CsvFilePath ./AzureTargets.Csv

EXAMPLE 2
=========
This will add the Azure targets specified in the CSV file to the Turbonomic server turbonomic.mycompany.com using the Turbonomic credentials specified. It will also add the Reader and Storage Account Contributor role to the users specified in the CSV to the Azure subscription.

    AzureTargetLoader.ps1 -TurboInstance turbonomic.mycompany.com -TurboCredential $TurboCred -CsvFilePath ./AzureTargets.Csv



EXAMPLE 3
=========
This will only add the Azure targets specified in the CSV file to the Turbonomic server turbonomic.mycompany.com using the Turbonomic credentials specified. 

    AzureTargetLoader.ps1 -AddMode TargetsOnly -TurboInstance turbonomic.mycompany.com -TurboCredential $TurboCred -CsvFilePath ./AzureTargets.Csv


EXAMPLE 4
=========
This will only add the Reader and Storage Account Contributor role to the users specified in the CSV to the Azure subscription.

    AzureTargetLoader.ps1 -AddMode AzurePermissionsOnly -CsvFilePath ./AzureTargets.Csv

