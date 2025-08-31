<#
.SYNOPSIS
    PowerShell Script to Onboard a GCP Folder to Microsoft Defender for Cloud

.DESCRIPTION
    This script automates the process of creating a security connector for a GCP folder,
    enabling Microsoft Defender for Cloud to monitor resources within that folder.

.PARAMETER SubscriptionId
    The Azure Subscription ID to use.

.PARAMETER TenantId
    The Azure Tenant ID.

.PARAMETER ResourceGroup
    The Azure Resource Group name to create the security connector in.

.PARAMETER GCPFolderId
    The ID of the GCP folder to onboard.

.PARAMETER GCPManagementProjectId
    The GCP project ID that contains the Microsoft Defender service accounts.

.PARAMETER ClientId
    The Azure Client ID (Application ID) for the service principal.

.PARAMETER ClientSecret
    The Azure Client Secret for the service principal.

.PARAMETER WorkloadPoolId
    The workload identity pool ID for the GCP CSPM offering.

.PARAMETER AzureLocation
    The Azure region for the resource group and security connector.

.PARAMETER SecurityConnectorName
    The name of the security connector to be created.

.NOTES
    This script is designed to be called by a CI/CD pipeline (e.g., GitHub Actions)
    that has already installed the necessary Az PowerShell modules.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory=$true)]
    [string]$TenantId,

    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup,

    [Parameter(Mandatory=$true)]
    [string]$GCPFolderId,
    
    [Parameter(Mandatory=$true)]
    [string]$GCPManagementProjectId,

    [Parameter(Mandatory=$true)]
    [string]$ClientId,

    [Parameter(Mandatory=$true)]
    [string]$ClientSecret,

    [Parameter(Mandatory=$true)]
    [string]$WorkloadPoolId,

    [string]$AzureLocation = "eastus",

    [string]$SecurityConnectorName = "gcp-poc-connector"
)

# Logging function for consistent output
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $formattedMessage = "$timestamp [$Level] $Message"
    if ($Level -eq "ERROR") { Write-Host $formattedMessage -ForegroundColor Red }
    elseif ($Level -eq "WARNING") { Write-Host $formattedMessage -ForegroundColor Yellow }
    else { Write-Host $formattedMessage -ForegroundColor Green }
}

function Get-AzureAccessToken {
    param([string]$Resource = "https://management.azure.com")
    
    try {
        # Try using Azure CLI first
        Write-Log "Attempting to get access token using Azure CLI..."
        $tokenResult = az account get-access-token --resource $Resource --tenant $TenantId --output json 2>$null
        if ($tokenResult) {
            $tokenData = $tokenResult | ConvertFrom-Json
            return $tokenData.accessToken
        }
    }
    catch {
        Write-Log "Azure CLI token retrieval failed, trying with service principal..." "WARNING"
    }
    
    # Fallback to service principal authentication
    try {
        Write-Log "Getting access token using service principal..."
        $body = @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $ClientSecret
            resource      = $Resource
            scope         = "https://management.azure.com/.default"
        }
        
        $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        $response = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    }
    catch {
        Write-Log "Failed to get access token using service principal: $($_.Exception.Message)" "ERROR"
        throw
    }
}

Write-Log "=== Script started ==="

# ------------------------------------
# 1. Authenticate to Azure and get an access token
# ------------------------------------
Write-Log "Authenticating to Azure and retrieving access token..."
try {
    $token = Get-AzureAccessToken
    if (-not $token) {
        throw "Failed to retrieve access token"
    }
    Write-Log "✅ Access token retrieved successfully."
}
catch {
    Write-Log "Error during authentication: $($_.Exception.Message)" "ERROR"
    Exit 1
}

# ------------------------------------
# 2. Check if resource group exists, create if not
# ------------------------------------
try {
    Write-Log "Checking if resource group '$ResourceGroup' exists..."
    $rgUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourcegroups/$ResourceGroup`?api-version=2021-04-01"
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }
    
    $rgResponse = Invoke-RestMethod -Uri $rgUri -Method Get -Headers $headers -ErrorAction SilentlyContinue
    Write-Log "✅ Resource group exists."
}
catch {
    if ($_.Exception.Response.StatusCode -eq 404) {
        Write-Log "Resource group not found, creating it..." "WARNING"
        $rgBody = @{
            location = $AzureLocation
            tags     = @{
                "CreatedBy" = "DefenderOnboardingScript"
            }
        } | ConvertTo-Json
        
        $rgCreateUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourcegroups/$ResourceGroup`?api-version=2021-04-01"
        $rgCreateResponse = Invoke-RestMethod -Uri $rgCreateUri -Method Put -Headers $headers -Body $rgBody
        Write-Log "✅ Resource group created successfully."
    }
    else {
        Write-Log "Error checking resource group: $($_.Exception.Message)" "ERROR"
        Exit 1
    }
}

# ------------------------------------
# 3. Make the API Call to create the Security Connector
# ------------------------------------
Write-Log "Constructing API request for security connector..."

$apiVersion = "2023-10-01-preview"
$uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Security/securityConnectors/$SecurityConnectorName`?api-version=$apiVersion"

# Construct the body for GCP Folder with proper formatting
$bodyObj = @{
    location   = $AzureLocation
    properties = @{
        hierarchyIdentifier = "folders/$GCPFolderId"
        environmentName     = "GCP"
        environmentData     = @{
            organizationalData = @{
                organizationMembershipType = "Organization"
                organizationId             = $GCPOrganizationId
                workloadIdentityPoolId     = $WorkloadPoolId
            }
        }
        offerings = @(
            @{
                offeringType = "CspmMonitorGcp"
                nativeCloudConnection = @{
                    serviceAccountEmailAddress = "microsoft-defender-cspm@$GCPManagementProjectId.iam.gserviceaccount.com"
                }
            },
            @{
                offeringType = "DefenderForServersGcp"
                subPlan      = "P2"
                defenderForServers = @{
                    serviceAccountEmailAddress = "microsoft-defender-for-servers@$GCPManagementProjectId.iam.gserviceaccount.com"
                    mdeAutoProvisioning = @{
                        enabled = $true
                    }
                    arcAutoProvisioning = @{
                        enabled = $true
                    }
                    vmScanners = @{
                        enabled = $true
                        configuration = @{
                            scanningMode = "Default"
                        }
                    }
                }
            }
        )
    }
}

$body = $bodyObj | ConvertTo-Json -Depth 10
Write-Log "Request body prepared"

Write-Log "Sending PUT request to create security connector..."
try {
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }

    Write-Log "Making API call to: $uri"
    $response = Invoke-RestMethod -Uri $uri -Method Put -Headers $headers -Body $body -ErrorAction Stop
    
    Write-Log "✅ Security connector created successfully!"
    Write-Log "Provisioning State: $($response.properties.provisioningState)"
    Write-Log "Hierarchy Identifier: $($response.properties.hierarchyIdentifier)"
    
    # Wait for provisioning to complete
    Write-Log "Waiting for provisioning to complete..."
    $maxRetries = 12
    $retryCount = 0
    $waitSeconds = 10
    
    while ($retryCount -lt $maxRetries) {
        $statusResponse = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
        $provisioningState = $statusResponse.properties.provisioningState
        
        if ($provisioningState -eq "Succeeded") {
            Write-Log "✅ Provisioning completed successfully!"
            break
        }
        elseif ($provisioningState -eq "Failed") {
            Write-Log "❌ Provisioning failed" "ERROR"
            Exit 1
        }
        
        Write-Log "Provisioning state: $provisioningState (Waiting $waitSeconds seconds...)"
        Start-Sleep -Seconds $waitSeconds
        $retryCount++
    }
    
    if ($retryCount -eq $maxRetries) {
        Write-Log "⚠️  Provisioning taking longer than expected. Please check Azure portal for status." "WARNING"
    }
}
catch {
    Write-Log "Error creating security connector:" "ERROR"
    Write-Log "Exception Type: $($_.Exception.GetType().FullName)" "ERROR"
    Write-Log "Exception Message: $($_.Exception.Message)" "ERROR"
    
    if ($_.Exception.Response) {
        $statusCode = [int]$_.Exception.Response.StatusCode
        Write-Log "Status Code: $statusCode" "ERROR"
        
        try {
            $errorStream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorStream)
            $errorResponse = $reader.ReadToEnd()
            $reader.Close()
            
            if ($errorResponse) {
                Write-Log "Error Response: $errorResponse" "ERROR"
                try {
                    $errorJson = $errorResponse | ConvertFrom-Json
                    if ($errorJson.error) {
                        Write-Log "Error Code: $($errorJson.error.code)" "ERROR"
                        Write-Log "Error Message: $($errorJson.error.message)" "ERROR"
                    }
                }
                catch {
                    Write-Log "Could not parse error response as JSON" "ERROR"
                }
            }
        }
        catch {
            Write-Log "Could not read error response stream" "ERROR"
        }
    }
    
    Exit 1
}

Write-Log "=== Script completed successfully ==="
Write-Log "Security connector '$SecurityConnectorName' has been created and is provisioning."
Write-Log "GCP Folder ID: $GCPFolderId"
Write-Log "Azure Subscription: $SubscriptionId"
Write-Log "Resource Group: $ResourceGroup"
