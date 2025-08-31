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
# 2. Create the Security Connector using correct API format
# ------------------------------------
Write-Log "Constructing API request for security connector..."
$apiVersion = "2023-10-01-preview"
$uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Security/securityConnectors/$SecurityConnectorName`?api-version=$apiVersion"

# Use the exact format from Microsoft documentation
$bodyObj = @{
    location = $AzureLocation
    properties = @{
        hierarchyIdentifier = $GCPFolderId
        environmentName = "GCP"
        environmentData = @{
            organizationalData = @{
                organizationId = $GCPOrganizationId
            }
        }
        offerings = @(
            @{
                offeringType = "CspmMonitorGcp"
                nativeCloudConnection = @{
                    workloadIdentityProviderId = "cspm"
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
    
    Write-Log "=== Script completed successfully ==="
    Exit 0
}
catch {
    Write-Log "Error creating security connector:" "ERROR"
    Write-Log "Exception Message: $($_.Exception.Message)" "ERROR"
    
    # Try without workloadIdentityProviderId
    Write-Log "Trying alternative format without workloadIdentityProviderId..." "WARNING"
    
    try {
        $altBodyObj = @{
            location = $AzureLocation
            properties = @{
                hierarchyIdentifier = $GCPFolderId
                environmentName = "GCP"
                environmentData = @{
                    organizationalData = @{
                        organizationId = $GCPOrganizationId
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
        
        $altBody = $altBodyObj | ConvertTo-Json -Depth 10
        Write-Log "Trying alternative request body..."
        $response = Invoke-AzureRequest -Uri $uri -Method "PUT" -Body $altBody -Token $token
        Write-Log "✅ Security connector creation initiated with alternative format!"
        Write-Log "Provisioning State: $($response.properties.provisioningState)"
        Exit 0
    }
    catch {
        Write-Log "Alternative approach also failed:" "ERROR"
        Write-Log "Exception Message: $($_.Exception.Message)" "ERROR"
        
        # Try the simplest possible approach
        Write-Log "Trying simplest format..." "WARNING"
        
        try {
            $simpleBodyObj = @{
                location = $AzureLocation
                properties = @{
                    hierarchyIdentifier = $GCPFolderId
                    environmentName = "GCP"
                    offerings = @(
                        @{
                            offeringType = "CspmMonitorGcp"
                        }
                    )
                }
            }
            
            $simpleBody = $simpleBodyObj | ConvertTo-Json -Depth 10
            Write-Log "Trying simplest request body..."
            $response = Invoke-AzureRequest -Uri $uri -Method "PUT" -Body $simpleBody -Token $token
            Write-Log "✅ Security connector creation initiated with simplest format!"
            Write-Log "Provisioning State: $($response.properties.provisioningState)"
            Exit 0
        }
        catch {
            Write-Log "All API attempts failed. Please check:" "ERROR"
            Write-Log "1. Verify GCP Organization ID: $GCPOrganizationId"
            Write-Log "2. Verify GCP Folder ID: $GCPFolderId" 
            Write-Log "3. Check Azure permissions for service principal"
            Write-Log "4. Try creating manually in Azure Portal first"
            Write-Log "Portal URL: https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/EnvironmentSettings"
            Exit 1
        }
    }
}
