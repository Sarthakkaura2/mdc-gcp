param(
    [Parameter(Mandatory = $false)]$Workspace,
    [Parameter(Mandatory = $true)]$SubscriptionId,
    [Parameter(Mandatory = $false)]$TeamName,
    [Parameter(Mandatory = $true)]$TenantId,
    [Parameter(Mandatory = $true)]$GCPFolderId,
    [Parameter(Mandatory = $true)]$ManagementProjectId,
    [Parameter(Mandatory = $true)]$ClientId,
    [Parameter(Mandatory = $true)]$ClientSecret,
    [Parameter(Mandatory = $true)]$ResourceGroup,
    [Parameter(Mandatory = $false)]$WORKLOAD_POOL_ID
)

$LogFile = Join-Path $PSScriptRoot "connector.log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$timestamp $Message"
    Write-Host "$timestamp $Message"
}

Write-Log "=== Script started ==="
Write-Log "Logging to file: $LogFile"
Write-Log "Validating script parameters..."

if (-not $SubscriptionId) { Write-Log "ERROR: SubscriptionId is missing." -ForegroundColor Red; exit }
if (-not $TenantId) { Write-Log "ERROR: TenantId is missing." -ForegroundColor Red; exit }
if (-not $GCPFolderId) { Write-Log "ERROR: GCPFolderId is missing." -ForegroundColor Red; exit }
if (-not $GCPManagementProjectId) { Write-Log "ERROR: GCPManagementProjectId is missing." -ForegroundColor Red; exit }
if (-not $ClientId) { Write-Log "ERROR: ClientId is missing." -ForegroundColor Red; exit }
if (-not $ClientSecret) { Write-Log "ERROR: ClientSecret is missing." -ForegroundColor Red; exit }
if (-not $ResourceGroup) { Write-Log "ERROR: ResourceGroup is missing." -ForegroundColor Red; exit }
if (-not $WORKLOAD_POOL_ID) { Write-Log "ERROR: WORKLOAD_POOL_ID is missing." -ForegroundColor Red; exit }

Write-Log "Parameters validated. Proceeding with authentication."
Write-Log "Importing Az modules..."
Import-Module -Name Az.Resources -Force
Import-Module -Name Az.SecurityInsights -Force
Import-Module -Name Az.OperationalInsights -Force

Write-Log "Authenticating to Azure with service principal..."
Clear-AzContext -Force -ErrorAction SilentlyContinue
$securePassword = $ClientSecret | ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($ClientId, $securePassword)
try {
    $connectResult = Connect-AzAccount -ServicePrincipal -Credential $credential -TenantId $TenantId -Force
    if ($connectResult) {
        Write-Log "✅ Authentication successful"
        Write-Log "    Account: $($connectResult.Context.Account.Id)"
    }
    Set-AzContext -Subscription $SubscriptionId
    Write-Log "Login to Azure is successful and context is set."
    Get-AzContext | Out-String | Write-Log
} catch {
    Write-Log "❌ FATAL ERROR: Failed to authenticate to Azure." -ForegroundColor Red
    Write-Log "Exception Message: $($_.Exception.Message)"
    exit
}

$apiVersion = "2023-10-01-preview"
$securityConnectorName = "gcp-folder-connector-kpmg-uk-$(Get-Date -Format 'yyMMddHHmm')"
$uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Security/securityConnectors/$securityConnectorName`?api-version=$apiVersion"
Write-Log "Constructed URI: $uri"

$bodyObj = @{
    location = "uksouth"
    properties = @{
        hierarchyIdentifier = $GCPManagementProjectId
        environmentName = "GCP"
        environmentData = @{
                environmentType = "GcpProject"
                gcpProjectData = @{
                    projectDetails = @{
                        projectId = $GCPManagementProjectId
                        workloadIdentityPoolId = $WORKLOAD_POOL_ID
                        workloadIdentityProviderId = "gcp-provider-for-cloud-connector"
                    }
                }
        }
        offerings = @(
            @{
                offeringType = "CspmMonitorGcp"
                nativeCloudConnection = @{
                    serviceAccountEmailAddress = "microsoft-defender-cspm@$GCPManagementProjectId.iam.gserviceaccount.com"
                    workloadIdentityProviderId = "cspm"
                }
            },
            @{
                offeringType = "DefenderForServersGcp"
                defenderForServers = @{
                    serviceAccountEmailAddress = "microsoft-defender-for-servers@$GCPManagementProjectId.iam.gserviceaccount.com"
                    workloadIdentityProviderId = "defender-for-servers"
                }
                mdeAutoProvisioning = @{
                    enabled = $true
                    configuration = @{}
                }
                arcAutoProvisioning = @{
                    enabled = $true
                    configuration = @{}
                }
                vmScanners = @{
                    enabled = $true
                    configuration = @{
                        cloudRoleArn = "projects/$GCPProjectNumber/serviceAccounts/microsoft-defender-agentless@$GCPManagementProjectId.iam.gserviceaccount.com"
                        scanningMode = "Default"
                        exclusionTags = @{}
                    }
                }
                subPlan = "P2"
            }
        )
    }
}

$body = $bodyObj | ConvertTo-Json -Depth 10
Write-Log "Generated JSON body for API call:"
Write-Log ($body | Out-String)

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
