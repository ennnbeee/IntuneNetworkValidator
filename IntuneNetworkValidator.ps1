<#PSScriptInfo

.VERSION 0.1.0
.GUID c06924d5-dc8b-4f29-a592-a036d27b50e9
.AUTHOR Nick Benton
.COMPANYNAME
.COPYRIGHT GPL
.TAGS Graph Intune Windows Autopilot Network
.LICENSEURI https://github.com/ennnbeee/IntuneNetworkValidator/blob/main/LICENSE
.PROJECTURI https://github.com/ennnbeee/IntuneNetworkValidator
.ICONURI https://raw.githubusercontent.com/ennnbeee/IntuneNetworkValidator/refs/heads/main/img/inv-icon.png
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
v0.1.0 - Initial release.

.PRIVATEDATA
#>

<#
.SYNOPSIS


.DESCRIPTION

.PARAMETER testType


.PARAMETER testScope


.PARAMETER region


.EXAMPLE
.\IntuneNetworkValidator.ps1 -testType Lite -testScope Autopilot -region 'Europe'

#>

[CmdletBinding(DefaultParameterSetName = 'Default')]

param(
    [Parameter(Mandatory = $false, HelpMessage = 'The type of test to perform. Lite will test the CIDR as a whole, while Full will test each IP in the CIDR range.')]
    [ValidateSet('Lite', 'Full')]
    [String]$testType = 'Lite',

    [Parameter(Mandatory = $false, HelpMessage = 'The scope of the test. Autopilot will only test endpoints relevant to Windows Autopilot, while Full will test all endpoints.')]
    [ValidateSet('Autopilot', 'Full')]
    [String]$testScope = 'Autopilot',

    [Parameter(Mandatory = $false, HelpMessage = 'The region to test endpoints in. Valid values are North America, Europe, and Asia Pacific.')]
    [ValidateSet('North America', 'Europe', 'Asia Pacific')]
    [String]$region
)

#region variables
$timeoutSecs = 3
$networkEndpointsCSV = 'https://raw.githubusercontent.com/ennnbeee/IntuneNetworkValidator/main/IntuneNetworkEndpoints.csv'
$categoriesAutopilot = @('Delivery Optimization Dependencies', 'Windows Autopilot', 'Scripts and Apps', 'Microsoft Store', 'Authentication Dependencies')
#endregion variables

#region functions
function Get-IPRangeFromCIDR() {
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER cidrNotation

    #>

    param
    (
        [parameter(Mandatory = $true)]
        [string]$cidrNotation
    )

    $addr, $maskLength = $cidrNotation -split '/'
    [int]$maskLen = 0
    if (-not [int32]::TryParse($maskLength, [ref] $maskLen)) {
        throw "Cannot parse CIDR mask length string: '$maskLen'"
    }
    if (0 -gt $maskLen -or $maskLen -gt 32) {
        throw 'CIDR mask length must be between 0 and 32'
    }
    $ipAddr = [Net.IPAddress]::Parse($addr)
    if ($ipAddr -eq $null) {
        throw "Cannot parse IP address: $addr"
    }
    if ($ipAddr.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'Can only process CIDR for IPv4'
    }

    $shiftCnt = 32 - $maskLen
    $mask = -bnot ((1 -shl $shiftCnt) - 1)
    $ipNum = [Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($ipAddr.GetAddressBytes(), 0))
    ($ipNum -band $mask)
    ($ipNum -bor (-bnot $mask))

    # return as tuple of strings:
    #([BitConverter]::GetBytes([Net.IPAddress]::HostToNetworkOrder($ipStart)) | ForEach-Object { $_ } ) -join '.'
    #([BitConverter]::GetBytes([Net.IPAddress]::HostToNetworkOrder($ipEnd)) | ForEach-Object { $_ } ) -join '.'
}

function Get-NetworkEndpoint() {
    <#
    .SYNOPSIS


    .DESCRIPTION


    .PARAMETER csvUrl
    The URL of the CSV file containing the network endpoints to validate.

    .PARAMETER region
    The region to filter the network endpoints by. Valid values are 'North America', 'Europe', and 'Asia Pacific'. If not specified, all regions will be included.

    #>

    param
    (
        [parameter(Mandatory = $false)]
        [String]$csvUrl,

        [parameter(Mandatory = $false)]
        [ValidateSet('North America', 'Europe', 'Asia Pacific')]
        [String]$region
    )

    try {
        Write-Host 'Retrieving network endpoints from GitHub...'-ForegroundColor Cyan
        $csvContent = Invoke-WebRequest -Uri $csvUrl -UseBasicParsing
        $networkEndpoints = $csvContent.Content | ConvertFrom-Csv
        Write-Host 'Successfully retrieved network endpoints from GitHub.'-ForegroundColor Green

    }
    catch {
        Write-Host 'Failed to retrieve network endpoints from GitHub.'-ForegroundColor Yellow
        Write-Host 'Retrieving network endpoints from the script...'-ForegroundColor Cyan
        $networkEndpoints = @(
            # ID 163 Intune client and host service
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '*.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = 'manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '*.dm.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = 'EnterpriseEnrollment.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '104.46.162.96/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.67.13.176/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.67.15.128/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.69.231.128/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.69.67.224/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.70.78.128/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.70.79.128/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.74.111.192/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.77.53.176/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.86.221.176/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.89.174.240/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.89.175.192/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.37.153.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.37.192.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.38.81.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.41.1.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.42.1.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.42.130.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.42.224.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.43.129.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.44.19.224/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.119.8.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.67.121.224/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.70.151.32/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.71.14.96/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.74.25.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.78.245.240/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.78.247.128/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.79.197.64/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.79.197.96/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.80.180.208/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.80.180.224/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.80.184.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.82.248.224/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.82.249.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '52.150.137.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '52.162.111.96/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '52.168.116.128/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '52.182.141.192/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '52.236.189.96/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '52.240.244.160/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.204.193.12/30'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.204.193.10/31'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.192.174.216/29'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.192.159.40/29'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '104.208.197.64/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '172.160.217.160/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '172.201.237.160/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '172.202.86.192/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '172.205.63.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '172.212.214.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '172.215.131.0/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.168.189.128/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.199.207.192/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.204.194.128/31'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.208.149.192/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.208.157.128/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.214.131.176/29'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.43.129.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.91.147.72/29'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.145.74.224/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.150.254.64/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.154.145.224/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.200.254.32/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.207.244.0/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.213.25.64/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.213.86.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.216.205.32/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.237.143.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.84.70.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '48.218.252.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '57.151.0.192/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '57.153.235.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '57.154.140.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '57.154.195.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '57.155.45.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '68.218.134.96/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '74.224.214.64/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '74.242.35.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '172.208.170.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '74.241.231.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '74.242.184.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 172 MDM Delivery Optimization
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'MDM Delivery Optimization'; Endpoint = '*.do.dsp.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'MDM Delivery Optimization'; Endpoint = '*.dl.delivery.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 170 MEM - Win32Apps
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swda01-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swda02-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdb01-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdb02-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdc01-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdc02-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdd01-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdd02-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdin01-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdin02-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 97 Consumer Outlook.com, OneDrive, Device authentication, and Microsoft account
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Consumer Devices'; Endpoint = 'swdin01-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Consumer Devices'; Endpoint = 'swdin02-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 190 Endpoint discovery
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Endpoint Discovery'; Endpoint = 'go.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 189 Dependency - Feature Deployment
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Feature Deployment'; Endpoint = 'config.edge.skype.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Feature Deployment'; Endpoint = 'ecs.office.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 192 Organizational messages
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Organizational Messages'; Endpoint = 'fd.api.orgmsg.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Intune Core Service'; Subcategory = 'Organizational Messages'; Endpoint = 'ris.prod.api.personalization.ideas.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 56 Authentication and Identity, includes Microsoft Entra ID and Entra ID related services.
            [PSCustomObject]@{Category = 'Authentication Dependencies'; Subcategory = 'Authentication and Identity'; Endpoint = 'login.microsoftonline.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Authentication Dependencies'; Subcategory = 'Authentication and Identity'; Endpoint = 'graph.windows.net'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 150 Office Customization Service provides Office 365 ProPlus deployment configuration, application settings, and cloud based policy management.
            [PSCustomObject]@{Category = 'Authentication Dependencies'; Subcategory = 'Office Customization'; Endpoint = '*.officeconfig.msocdn.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Authentication Dependencies'; Subcategory = 'Office Customization'; Endpoint = 'config.office.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 59 Identity supporting services & CDNs.
            [PSCustomObject]@{Category = 'Authentication Dependencies'; Subcategory = 'Identity Supporting Services'; Endpoint = 'enterpriseregistration.windows.net'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Authentication Dependencies'; Subcategory = 'Identity Supporting Services'; Endpoint = 'certauth.enterpriseregistration.windows.net'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 172 MDM - Delivery Optimization Dependencies
            [PSCustomObject]@{Category = 'Delivery Optimization Dependencies'; Subcategory = 'Delivery Optimization'; Endpoint = '*.do.dsp.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Delivery Optimization Dependencies'; Subcategory = 'Delivery Optimization'; Endpoint = '*.dl.delivery.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 172 MEM - WNS Dependencies
            [PSCustomObject]@{Category = 'Windows Push Notification Services'; Subcategory = 'WNS Dependencies'; Endpoint = '*.notify.windows.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Push Notification Services'; Subcategory = 'WNS Dependencies'; Endpoint = '*.wns.windows.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Push Notification Services'; Subcategory = 'WNS Dependencies'; Endpoint = 'sinwns1011421.wns.windows.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Push Notification Services'; Subcategory = 'WNS Dependencies'; Endpoint = 'sin.notify.windows.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 181 MEM - Remote Help Feature
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = '*.support.services.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'remoteassistance.support.services.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'teams.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'remoteassistanceprodacs.communication.azure.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'edge.skype.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'aadcdn.msftauth.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'aadcdn.msauth.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = '*.msauth.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = '*.aria.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'browser.pipe.aria.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = '*.events.data.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'v10c.events.data.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = '*.monitor.azure.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'js.monitor.azure.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'go-apac.trouter.communications.svc.cloud.microsoft'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'go-eu.trouter.communications.svc.cloud.microsoft'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'api.flightproxy.skype.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'ecs.communication.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help Web'; Endpoint = 'remotehelp.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Remote Help'; Subcategory = 'Remote Help Web'; Endpoint = 'remoteassistanceprodacseu.communication.azure.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            # ID 164 Windows Autopilot - Windows Update
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'Windows Update'; Endpoint = '*.windowsupdate.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'Windows Update'; Endpoint = '*.dl.delivery.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'Windows Update'; Endpoint = '*.prod.do.dsp.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'Windows Update'; Endpoint = '*.delivery.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'Windows Update'; Endpoint = '*.update.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'Windows Update'; Endpoint = 'tsfe.trafficshaping.dsp.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'Windows Update'; Endpoint = 'adl.windows.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 165 Windows Autopilot - NTP Sync
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'NTP Sync'; Endpoint = 'time.windows.com'; Protocol = 'UDP'; Ports = '123'; Region = 'Global' }
            # ID 169 Windows Autopilot - WNS Dependencies
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'WNS Dependencies'; Endpoint = 'clientconfig.passport.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'WNS Dependencies'; Endpoint = 'windowsphone.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'WNS Dependencies'; Endpoint = '*.s-microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'WNS Dependencies'; Endpoint = 'c.s-microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 173 Windows Autopilot - Third-party deployment dependencies
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'Third-party Deployment Dependencies'; Endpoint = 'ekop.intel.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'Third-party Deployment Dependencies'; Endpoint = 'ekcert.spserv.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'Third-party Deployment Dependencies'; Endpoint = 'ftpm.amd.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 182 Windows Autopilot - Diagnostics upload
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'Diagnostics Upload'; Endpoint = 'lgmsapeweu.blob.core.windows.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'Diagnostics Upload'; Endpoint = 'lgmsapewus2.blob.core.windows.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'Diagnostics Upload'; Endpoint = 'lgmsapesea.blob.core.windows.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'Diagnostics Upload'; Endpoint = 'lgmsapeaus.blob.core.windows.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopilot'; Subcategory = 'Diagnostics Upload'; Endpoint = 'lgmsapeind.blob.core.windows.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID XXX Microsoft Store
            [PSCustomObject]@{Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'displaycatalog.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'purchase.md.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'licensing.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'storeedgefd.dsx.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'img-prod-cms-rt-microsoft-com.akamaized.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'img-s-msn-com.akamaized.net'; Protocol = 'TCP'; Ports = '80'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'livetileedge.dsx.mp.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = '*.wns.windows.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'storecatalogrevocation.storequality.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'manage.devcenter.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'share.microsoft.com'; Protocol = 'TCP'; Ports = '80'; Region = 'Global' }
            # ID XXX Device Health Attestation
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape1.eus.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape2.eus2.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape3.cus.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape4.wus.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape5.scus.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape6.ncus.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape7.neu.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape8.neu.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape9.neu.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape10.weu.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape11.weu.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape12.weu.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape13.jpe.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape17.jpe.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape18.jpe.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape19.jpe.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            # ID XXX PowerShell scripts and Win32 apps
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'naprodimedatapri.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'naprodimedatasec.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'naprodimedatahotfix.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswda-afd-primary.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswda-afd-secondary.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswda-afd-hotfix.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'euprodimedatapri.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'euprodimedatasec.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'euprodimedatahotfix.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswdb-afd-primary.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswdb-afd-secondary.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswdb-afd-hotfix.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'approdimedatapri.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'approdimedatasec.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'approdimedatahotfix.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswdc-afd-primary.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswdc-afd-secondary.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswdc-afd-hotfix.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            # ID XXX Windows Autopatch
            [PSCustomObject]@{Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'mmdcustomer.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'mmdls.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'devicelistenerprod.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'devicelistenprod.eudb.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'login.windows.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'device.autopatch.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'services.autopatch.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'payloadprod*.blob.core.windows.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = '*.webpubsub.azure.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID XXX Windows 11 Enterprise
            [PSCustomObject]@{Category = 'Windows 11'; Subcategory = 'Apps'; Endpoint = 'tile-service.weather.microsoft.com'; Protocol = 'TCP'; Ports = '80'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows 11'; Subcategory = 'Apps'; Endpoint = 'cdn.onenote.net'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows 11'; Subcategory = 'Apps'; Endpoint = 'evoke-windowsservices-tas.msedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows 11'; Subcategory = 'Certificates'; Endpoint = 'ctldl.windowsupdate.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows 11'; Subcategory = 'Certificates'; Endpoint = 'ocsp.digicert.com'; Protocol = 'TCP'; Ports = '80'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows 11'; Subcategory = 'Device Authentication'; Endpoint = 'login.live.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows 11'; Subcategory = 'Licensing'; Endpoint = 'licensing.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows 11'; Subcategory = 'Defender'; Endpoint = 'wdcp.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows 11'; Subcategory = 'Defender'; Endpoint = '*.smartscreen-prod.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows 11'; Subcategory = 'Defender'; Endpoint = 'checkappexec.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows 11'; Subcategory = 'Defender'; Endpoint = 'ping-edge.smartscreen.microsoft.com'; Protocol = 'TCP'; Ports = '80'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows 11'; Subcategory = 'Defender'; Endpoint = 'data-edge.smartscreen.microsoft.com'; Protocol = 'TCP'; Ports = '80'; Region = 'Global' }
            [PSCustomObject]@{Category = 'Windows 11'; Subcategory = 'Defender'; Endpoint = 'nav-edge.smartscreen.microsoft.com'; Protocol = 'TCP'; Ports = '80'; Region = 'Global' }
        )
        Write-Host 'Successfully retrieved network endpoints from the script.'-ForegroundColor Green
    }
    if ($region) {
        $networkEndpoints = $networkEndpoints | Where-Object { $_.Region -eq $region -or $_.Region -eq 'Global' }
    }
    return $networkEndpoints
}

function Test-NetworkEndpoint() {
    <#
    .SYNOPSIS

    .DESCRIPTION

    #>

    param
    (
        [parameter(Mandatory = $false)]
        [String]$category,

        [parameter(Mandatory = $false)]
        [String]$subCategory,

        [parameter(Mandatory = $true)]
        [String]$address,

        [parameter(Mandatory = $true)]
        [ValidateSet('TCP', 'UDP')]
        [String]$protocol,

        [parameter(Mandatory = $true)]
        [String]$ports,

        [Parameter(Mandatory = $false, HelpMessage = 'The type of test to perform. Lite will test the CIDR as a whole, while Full will test each IP in the CIDR range.')]
        [ValidateSet('Lite', 'Full')]
        [String]$testType = 'Lite'


    )

    begin {
        $portSplits = @($ports.Split(',').Trim())
        $testItems = @()
    }
    process {
        foreach ($portSplit in $portSplits) {
            $testItem = [PSCustomObject]@{
                Category    = $category
                SubCategory = $subCategory
                Address     = $address
                Protocol    = $protocol
                Port        = $null
                Status      = $null
            }
            $testItem.Port = $portSplit

            # Wildcard domain
            if ($testItem.Address -match '^\*') {
                $testItem.Status = 'WILD'
                $testItems += @($testItem)
            }
            # IP Address Range
            elseif ($testItem.Address -match '/\d+$') {
                if ($testType -eq 'Lite') {
                    $testItem.Status = 'IP'
                    $ipAddress = ($testItem.address -split '/')[0]
                    $testItem.address = $ipAddress
                    $testItems += @($testItem)
                }
                if ($testType -eq 'Full') {
                    $startIP = (Get-IPRangeFromCIDR -cidrNotation $address)[0]
                    $endIP = (Get-IPRangeFromCIDR -cidrNotation $address)[1]

                    foreach ($ip in $startIP..$endIP) {
                        $ipAddress = ([BitConverter]::GetBytes([Net.IPAddress]::HostToNetworkOrder($ip)) | ForEach-Object { $_ } ) -join '.'

                        $testItem = [PSCustomObject]@{
                            Category    = $category
                            SubCategory = $subCategory
                            Address     = $ipAddress
                            Protocol    = $protocol
                            Port        = $port
                            Status      = 'IP'
                        }
                        $testItems += @($testItem)
                    }
                }
            }
            else {
                $testItem.Status = 'DNS'
                $testItems += @($testItem)
            }

        }
    }
    end {
        try {
            foreach ($testItem in $testItems) {
                switch ($testItem.Protocol) {
                    'TCP' {
                        if ($testItem.Status -eq 'WILD') {
                            $testItem.Status = 'SKIP'
                            Write-Host "`r [" -NoNewline
                            Write-Host "$($testItem.Status)" -ForegroundColor Cyan -NoNewline
                            Write-Host "] $($testItem.Address):$($testItem.Port)"
                        }
                        else {
                            $tcpClient = New-Object System.Net.Sockets.TcpClient
                            $connect = $tcpClient.BeginConnect($($testItem.Address), $($testItem.Port), $null, $null)
                            $waitTime = $connect.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($timeoutSecs), $false)
                            if ($waitTime -and -not $tcpClient.Client.Poll(0, [System.Net.Sockets.SelectMode]::SelectError)) {
                                $tcpClient.EndConnect($connect) 2>$null
                                $testItem.Status = 'OK'
                                Write-Host "`r [" -NoNewline
                                Write-Host " $($testItem.Status) " -ForegroundColor Green -NoNewline
                                Write-Host "] $($testItem.Address):$($testItem.Port)"
                            }
                            else {
                                $testItem.Status = 'FAIL'
                                Write-Host "`r [" -NoNewline
                                Write-Host "$($testItem.Status)" -ForegroundColor Red -NoNewline
                                Write-Host "] $($testItem.Address):$($testItem.Port)"
                            }
                            $tcpClient.Close()
                        }
                    }
                    'UDP' {
                        $testItem.Status = 'INFO'
                        Write-Host "`r [" -NoNewline
                        Write-Host "$($testItem.Status)" -ForegroundColor Yellow -NoNewline
                        Write-Host "] $($testItem.Address):$($testItem.Port)"
                    }
                }
            }
        }
        catch {
            $testItem.Status = 'FAIL'
            Write-Host "`r [" -NoNewline
            Write-Host "$($testItem.Status)" -ForegroundColor Red -NoNewline
            Write-Host "] $($testItem.Address):$($testItem.Port)"
        }

        return $testItems

    }
}

function Test-NetworkEndpointList () {
    <#
    .SYNOPSIS

    .DESCRIPTION

    #>
    param
    (
        [parameter(Mandatory = $true)]
        [array]$networkEndpoints
    )

    begin {
        $allResults = @()

    }
    process {
        $categories = $networkEndpoints | Select-Object -ExpandProperty Category -Unique
    }
    end {
        foreach ($category in $categories) {
            $subCategories = $networkEndpoints | Where-Object { $_.Category -eq $category } | Select-Object -ExpandProperty Subcategory -Unique
            Write-Host "`n[$category]" -ForegroundColor Green
            foreach ($subCategory in $subCategories) {
                Write-Host "[$subCategory]" -ForegroundColor Magenta
                $subCategoryEndpoints = $networkEndpoints | Where-Object { $_.Category -eq $category -and $_.Subcategory -eq $subCategory }
                foreach ($subCategorykEndpoint in $subCategoryEndpoints) {
                    $allResults += Test-NetworkEndpoint -category $subCategorykEndpoint.Category -subCategory $subCategorykEndpoint.Subcategory -address $subCategorykEndpoint.Endpoint -protocol $subCategorykEndpoint.Protocol -ports $subCategorykEndpoint.Ports
                }
            }
        }

        return $allResults
    }





}

function Get-NetworkEndpointSummary () {
    <#
    .SYNOPSIS

    .DESCRIPTION

    #>
    param
    (
        [parameter(Mandatory = $true)]
        [array]$networkEndpointResults
    )
    begin {
        $summary = [PSCustomObject]@{
            'Total'   = $null
            'Passed'  = $null
            'Skipped' = $null
            'Info'    = $null
            'Failed'  = $null
        }
    }
    process {
        $summaryOK = [int]($networkEndpointResults | Where-Object { $_.Status -eq 'OK' } | Measure-Object).Count
        $summaryFail = [int]($networkEndpointResults | Where-Object { $_.Status -eq 'FAIL' } | Measure-Object).Count
        $summarySkip = [int]($networkEndpointResults | Where-Object { $_.Status -eq 'SKIP' } | Measure-Object).Count
        $summaryInfo = [int]($networkEndpointResults | Where-Object { $_.Status -eq 'INFO' } | Measure-Object).Count
        $summaryTotal = [int]($networkEndpointResults | Measure-Object).Count
    }
    end {
        $summary.Total = $summaryTotal
        $summary.Passed = $summaryOK
        $summary.Skipped = $summarySkip
        $summary.Info = $summaryInfo
        $summary.Failed = $summaryFail
        return $summary
    }
}
#$networkEndpoints | Export-Csv -Path '.\IntuneNetworkEndpoints.csv'-NoTypeInformation -Encoding UTF8


#endregion functions

if ($region) {
    Write-Host "Filtering network endpoints for region: $region" -ForegroundColor Magenta
    $networkEndpoints = Get-NetworkEndpoint -csvUrl $networkEndpointsCSV -region $region
}
else {
    Write-Host 'Retrieving all network endpoints without region filtering.' -ForegroundColor Magenta
    $networkEndpoints = Get-NetworkEndpoint -csvUrl $networkEndpointsCSV
}

if ($testScope -eq 'Autopilot') {
    $networkEndpoints = $networkEndpoints | Where-Object { $_.Category -in $categoriesAutopilot }
}

$allResults = @()

$allResults += Test-NetworkEndpointList -networkEndpoints $networkEndpoints

Get-NetworkEndpointSummary -networkEndpointResults $allResults

$networkEndpoints = $networkEndpoints[4]
$category = $networkEndpoints.Category
$subCategory = $networkEndpoints.Subcategory
$address = $networkEndpoints.Endpoint
$protocol = $networkEndpoints.Protocol
$ports = $networkEndpoints.Ports
