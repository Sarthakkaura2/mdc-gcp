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
$uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Security/securityConnectors/$securityConnectorName`?api-version=$apiVersion"

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

$token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token

Write-Host "Access token retrieved and masked successfully."



if ($token -is [System.Security.SecureString]) {

    $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token))

}



$headers = @{

    "Authorization" = "Bearer $token"

    "Content-Type"  = "application/json"

}

write-host $headers.Authorization



try {

    $response = Invoke-RestMethod -Uri $uri -Method Put -Headers $headers -Body $body

    Write-Host "Security connector created successfully:"

    $response | ConvertTo-Json -Depth 10

}

catch {

    Write-Host "Error creating security connector:"

    Write-Host "Exception Type: $($_.Exception.GetType().FullName)"

    Write-Host "Exception Message: $($_.Exception.Message)"

    if ($_.Exception.Response) {

        $statusCode = [int]$_.Exception.Response.StatusCode

        Write-Host "Status Code: $statusCode"

        $responseBody = $_.ErrorDetails.Message

        if ($responseBody) {

            Write-Host "Response Body: $responseBody"

        }

    }

}



Write-Host "Verifying permissions and access..."

try {

    $resources = Get-AzResource -ResourceGroupName $ResourceGroup

    Write-Host "Successfully listed resources in the resource group. Basic access confirmed."

    $resources | Format-Table Name, ResourceType -AutoSize

}

catch {

    Write-Host "Error listing resources in the resource group:"

    Write-Host $_.Exception.Message

}



Write-Host "Script execution completed."
