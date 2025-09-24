param(
  [Parameter(Mandatory = $true)]$SubscriptionId,
  [Parameter(Mandatory = $true)]$TenantId,
  [Parameter(Mandatory = $true)]$ClientId,
  [Parameter(Mandatory = $true)]$ClientSecret,
  [Parameter(Mandatory = $true)]$ResourceGroup,
  [Parameter(Mandatory = $true)]$GCPFolderId,
  [Parameter(Mandatory = $true)]$ManagementProjectId,
  [Parameter(Mandatory = $true)]$ManagementProjectNumber
)

$LogFile = Join-Path $PSScriptRoot "connector-folder.log"
$JsonDumpFile = Join-Path $PSScriptRoot "final-body.json"

function Write-Log {
  param([string]$Message)
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Add-Content -Path $LogFile -Value "$timestamp $Message"
  Write-Host $Message
}

Write-Log "=== Starting minimal GCP Folder Security Connector test ==="

# Authenticate
$securePassword = $ClientSecret | ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($ClientId, $securePassword)
Connect-AzAccount -ServicePrincipal -Credential $credential -TenantId $TenantId -Force | Out-Null
Set-AzContext -Subscription $SubscriptionId

# API setup
$apiVersion = "2024-03-01-preview"
$securityConnectorName = "gcp-folder-test-connector"
$location = "uksouth"
$uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Security/securityConnectors/$securityConnectorName?api-version=$apiVersion"

# Minimal request body (only CSPM offering)
$bodyObj = @{
  location   = $location
  kind       = "Gcp"
  properties = @{
    environmentName     = "GCP"
    hierarchyIdentifier = "folders/$GCPFolderId"
    environmentData     = @{
      environmentType = "GcpFolder"
      folderDetails   = @{
        folderId = "$GCPFolderId"
      }
      projectDetails = @{
        projectId     = "$ManagementProjectId"
        projectNumber = "$ManagementProjectNumber"
      }
      organizationalData = @{
        organizationMembershipType  = "Organization"
        serviceAccountEmailAddress  = "microsoft-defender-cspm@sbx-sentinel-mde-dev.iam.gserviceaccount.com"
        workloadIdentityProviderId  = "projects/$ManagementProjectNumber/locations/global/workloadIdentityPools/117249f6e24734b8bb691a16a81e/providers/cspm"
        excludedProjectNumbers      = @()
      }
    }
    offerings = @(
      @{
        offeringType = "CspmMonitorGcp"
        nativeCloudConnection = @{
          serviceAccountEmailAddress = "microsoft-defender-cspm@sbx-sentinel-mde-dev.iam.gserviceaccount.com"
          workloadIdentityProviderId = "projects/$ManagementProjectNumber/locations/global/workloadIdentityPools/117249f6e24734b8bb691a16a81e/providers/cspm"
        }
      }
    )
  }
}

# Convert and validate JSON
try {
  $body = $bodyObj | ConvertTo-Json -Depth 10 -Compress
  $body | ConvertFrom-Json | Out-Null
  Write-Log "✅ JSON validated successfully."
  $body | Out-File -FilePath $JsonDumpFile -Encoding utf8
  Write-Log "📄 JSON dumped to: $JsonDumpFile"
}
catch {
  Write-Log "❌ JSON validation failed: $($_.Exception.Message)"
  exit 1
}

# Get access token
$token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token

# Headers
$headers = @{
  "Authorization" = "Bearer $token"
  "Content-Type"  = "application/json"
}

# Send request
try {
  Write-Log "🚀 Sending PUT request to create minimal folder-level security connector..."
  $response = Invoke-RestMethod -Uri $uri -Method Put -Headers $headers -Body $body
  Write-Log "✅ Security connector created successfully:"
  $response | ConvertTo-Json -Depth 10 | Write-Log
}
catch {
  Write-Log "❌ Error creating security connector:"
  Write-Log "Exception Type: $($_.Exception.GetType().FullName)"
  Write-Log "Exception Message: $($_.Exception.Message)"

  if ($_.Exception.Response) {
    $statusCode = [int]$_.Exception.Response.StatusCode
    Write-Log "Status Code: $statusCode"

    try {
      $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
      $responseBody = $reader.ReadToEnd()
      Write-Log "Response Body: $responseBody"
    }
    catch {
      Write-Log "⚠️ Could not read response body"
    }
  }

  if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
    Write-Log "ErrorDetails: $($_.ErrorDetails.Message)"
  }
}

Write-Log "=== Script execution completed ==="
