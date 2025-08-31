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
# 2. Try different API versions and formats
# ------------------------------------
$apiVersions = @("2023-10-01-preview", "2022-08-01-preview", "2022-05-01-preview", "2021-07-01-preview")
$baseUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Security/securityConnectors/$SecurityConnectorName"

foreach ($apiVersion in $apiVersions) {
    Write-Log "Trying API version: $apiVersion" "WARNING"
    $uri = "$baseUri`?api-version=$apiVersion"
    
    # Format 1: Complete format with all fields
    $body1 = @{
        location = $AzureLocation
        properties = @{
            hierarchyIdentifier = $GCPFolderId
            environmentName = "GCP"
            environmentData = @{
                organizationalData = @{
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
    
    # Format 2: Simplified format
    $body2 = @{
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
    
    # Format 3: Minimal format
    $body3 = @{
        location = $AzureLocation
        properties = @{
            hierarchyIdentifier = $GCPFolderId
            environmentName = "GCP"
        }
    }
    
    $formats = @($body1, $body2, $body3)
    $formatNames = @("Complete", "Simplified", "Minimal")
    
    for ($i = 0; $i -lt $formats.Count; $i++) {
        Write-Log "Trying format: $($formatNames[$i])" "WARNING"
        
        try {
            $bodyJson = $formats[$i] | ConvertTo-Json -Depth 10
            Write-Log "Request body for $($formatNames[$i]):"
            Write-Log ($bodyJson | Out-String)
            
            $headers = @{
                "Authorization" = "Bearer $token"
                "Content-Type"  = "application/json"
            }
            
            $response = Invoke-RestMethod -Uri $uri -Method Put -Headers $headers -Body $bodyJson -ErrorAction Stop
            Write-Log "✅ SUCCESS with API version $apiVersion and $($formatNames[$i]) format!" "INFO"
            Write-Log "Provisioning State: $($response.properties.provisioningState)"
            Write-Log "Connector ID: $($response.id)"
            Exit 0
        }
        catch {
            Write-Log "Failed with $apiVersion and $($formatNames[$i]) format: $($_.Exception.Message)" "ERROR"
            if ($_.ErrorDetails.Message) {
                Write-Log "Error details: $($_.ErrorDetails.Message)" "ERROR"
            }
            # Continue to next format
        }
    }
}

# ------------------------------------
# 3. If all API versions fail, try Azure Resource Manager template
# ------------------------------------
Write-Log "Trying ARM template deployment..." "WARNING"

$armTemplate = @{
    '$schema' = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
    contentVersion = "1.0.0.0"
    parameters = @{}
    resources = @(
        @{
            type = "Microsoft.Security/securityConnectors"
            apiVersion = "2023-10-01-preview"
            name = $SecurityConnectorName
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
                    }
                )
            }
        }
    )
}

$armTemplateJson = $armTemplate | ConvertTo-Json -Depth 10
$armTemplateFile = "arm-template.json"
$armTemplateJson | Out-File $armTemplateFile

try {
    Write-Log "Deploying ARM template..."
    az deployment group create --resource-group $ResourceGroup --template-file $armTemplateFile --parameters @{}
    Write-Log "✅ ARM template deployment initiated!" "INFO"
    Exit 0
}
catch {
    Write-Log "ARM template deployment failed: $($_.Exception.Message)" "ERROR"
}

# ------------------------------------
# 4. Final fallback - use Azure CLI with correct format
# ------------------------------------
Write-Log "Trying Azure CLI with explicit JSON..." "WARNING"

$cliBody = @{
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

$cliBodyJson = $cliBody | ConvertTo-Json -Depth 5
$cliBodyFile = "cli-body.json"
$cliBodyJson | Out-File $cliBodyFile

try {
    Write-Log "Using Azure CLI with JSON file..."
    az rest --method PUT --uri "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Security/securityConnectors/$SecurityConnectorName?api-version=2023-10-01-preview" --body `@$cliBodyFile
    Write-Log "✅ Azure CLI deployment initiated!" "INFO"
    Exit 0
}
catch {
    Write-Log "Azure CLI deployment failed: $($_.Exception.Message)" "ERROR"
}

# ------------------------------------
# 5. All attempts failed - provide diagnostic information
# ------------------------------------
Write-Log "❌ ALL ATTEMPTS FAILED. Diagnostic information:" "ERROR"
Write-Log "Subscription ID: $SubscriptionId"
Write-Log "Resource Group: $ResourceGroup"
Write-Log "GCP Organization ID: $GCPOrganizationId"
Write-Log "GCP Folder ID: $GCPFolderId"
Write-Log "GCP Management Project: $GCPManagementProjectId"
Write-Log "Workload Pool ID: $WorkloadPoolId"

Write-Log "Please verify:" "ERROR"
Write-Log "1. GCP Organization ID is correct and accessible"
Write-Log "2. Service principal has Contributor rights on the subscription"
Write-Log "3. GCP Folder ID format is correct"
Write-Log "4. Try creating manually in Azure Portal first"
Write-Log "5. Check if there are any regional restrictions"

Exit 1
