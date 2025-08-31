<#
.SYNOPSIS
    PowerShell Script to Onboard a GCP Folder to Microsoft Defender for Cloud
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

    [Parameter(Mandatory=$true)]
    [string]$GCPOrganizationId,

    [string]$AzureLocation = "eastus",

    [string]$SecurityConnectorName = "gcp-poc-connector"
)

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
        Write-Log "Getting access token using service principal..."
        $body = @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $ClientSecret
            resource      = $Resource
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

function Invoke-AzureRequest {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [object]$Body = $null,
        [string]$Token
    )
    
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
    }
    
    $params = @{
        Uri = $Uri
        Method = $Method
        Headers = $headers
        ErrorAction = "Stop"
    }
    
    if ($Body) {
        $params.Body = $Body
    }
    
    try {
        $response = Invoke-RestMethod @params
        return $response
    }
    catch {
        $errorDetails = $_.ErrorDetails.Message
        if ($errorDetails) {
            Write-Log "Error Response: $errorDetails" "ERROR"
            try {
                $errorJson = $errorDetails | ConvertFrom-Json
                if ($errorJson.error) {
                    Write-Log "Error Code: $($errorJson.error.code)" "ERROR"
                    Write-Log "Error Message: $($errorJson.error.message)" "ERROR"
                    if ($errorJson.error.details) {
                        Write-Log "Error Details: $($errorJson.error.details | ConvertTo-Json -Depth 5)" "ERROR"
                    }
                }
            }
            catch {
                Write-Log "Raw Error Response: $errorDetails" "ERROR"
            }
        }
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
# 2. Check if security connector already exists
# ------------------------------------
$apiVersion = "2023-10-01-preview"
$checkUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Security/securityConnectors/$SecurityConnectorName`?api-version=$apiVersion"

try {
    Write-Log "Checking if security connector '$SecurityConnectorName' already exists..."
    $existingConnector = Invoke-AzureRequest -Uri $checkUri -Token $token -ErrorAction SilentlyContinue
    if ($existingConnector) {
        Write-Log "✅ Security connector already exists. Current status: $($existingConnector.properties.provisioningState)" "WARNING"
        Write-Log "Hierarchy Identifier: $($existingConnector.properties.hierarchyIdentifier)"
        Exit 0
    }
}
catch {
    # 404 is expected if connector doesn't exist
    if ($_.Exception.Response.StatusCode -ne 404) {
        Write-Log "Error checking existing connector: $($_.Exception.Message)" "ERROR"
        Exit 1
    }
    Write-Log "Security connector does not exist, proceeding with creation..."
}

# ------------------------------------
# 3. Create the Security Connector
# ------------------------------------
Write-Log "Constructing API request for security connector..."
$uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Security/securityConnectors/$SecurityConnectorName`?api-version=$apiVersion"

# Construct the body with proper formatting for GCP Folder
$bodyObj = @{
    location = $AzureLocation
    properties = @{
        hierarchyIdentifier = "folders/$GCPFolderId"  # Use the correct format with "folders/" prefix
        environmentName = "GCP"
        environmentData = @{
            organizationalData = @{
                organizationMembershipType = "Organization"
                organizationId = $GCPOrganizationId
                workloadIdentityPoolId = $WorkloadPoolId
            }
        }
        offerings = @(
            @{
                offeringType = "CspmMonitorGcp"
                nativeCloudConnection = @{
                    serviceAccountEmailAddress = "microsoft-defender-cspm@$GCPManagementProjectId.iam.gserviceaccount.com"
                }
            }
        )
    }
}

$body = $bodyObj | ConvertTo-Json -Depth 10
Write-Log "Request body:"
Write-Log ($body | Out-String)

Write-Log "Sending PUT request to create security connector..."
try {
    $response = Invoke-AzureRequest -Uri $uri -Method "PUT" -Body $body -Token $token
    Write-Log "✅ Security connector creation initiated successfully!"
    Write-Log "Provisioning State: $($response.properties.provisioningState)"
    Write-Log "Operation ID: $($response.id)"
    
    # Monitor provisioning status
    Write-Log "Monitoring provisioning status..."
    $maxRetries = 30
    $retryCount = 0
    $waitSeconds = 10
    
    while ($retryCount -lt $maxRetries) {
        $statusResponse = Invoke-AzureRequest -Uri $uri -Token $token
        $provisioningState = $statusResponse.properties.provisioningState
        
        Write-Log "Provisioning state: $provisioningState (Attempt $($retryCount + 1)/$maxRetries)"
        
        if ($provisioningState -eq "Succeeded") {
            Write-Log "✅ Provisioning completed successfully!"
            Write-Log "Security Connector ID: $($statusResponse.id)"
            Write-Log "Hierarchy Identifier: $($statusResponse.properties.hierarchyIdentifier)"
            break
        }
        elseif ($provisioningState -eq "Failed") {
            Write-Log "❌ Provisioning failed" "ERROR"
            if ($statusResponse.properties.statusMessage) {
                Write-Log "Status Message: $($statusResponse.properties.statusMessage)" "ERROR"
            }
            Exit 1
        }
        
        Start-Sleep -Seconds $waitSeconds
        $retryCount++
    }
    
    if ($retryCount -eq $maxRetries) {
        Write-Log "⚠️  Provisioning taking longer than expected. Check Azure portal for final status." "WARNING"
    }
}
catch {
    Write-Log "Error creating security connector:" "ERROR"
    Write-Log "Exception Message: $($_.Exception.Message)" "ERROR"
    Exit 1
}

Write-Log "=== Script completed successfully ==="
