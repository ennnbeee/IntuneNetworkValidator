<#PSScriptInfo

.VERSION 0.1.5
.GUID c06924d5-dc8b-4f29-a592-a036d27b50e9
.AUTHOR Nick Benton
.COMPANYNAME
.COPYRIGHT GPL
.TAGS Graph Intune Windows Autopilot Network
.LICENSEURI https://github.com/ennnbeee/IntuneNetworkValidator/blob/main/LICENSE
.PROJECTURI https://github.com/ennnbeee/IntuneNetworkValidator
.ICONURI https://raw.githubusercontent.com/ennnbeee/IntuneNetworkValidator/refs/heads/main/img/inv-icon.png
.EXTERNALMODULEDEPENDENCIES DnsClient
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
v0.1.5 - Updated with AVD endpoints
v0.1.4 - Updated CIDR function, changed testing logic for hostname endpoints
v0.1.3 - Added additional endpoints
v0.1.2 - Included DNS testing and report functions
v0.1.1 - Summary function created
v0.1.0 - Initial release

.PRIVATEDATA
#>

<#
.SYNOPSIS
Script to test network connectivity to Microsoft Intune network endpoints.

.DESCRIPTION
Uses a curated list of network endpoints from Microsoft and alternative sources due to the lack of an official Microsoft endpoint list to test connectivity for Microsoft Intune and related services.
The script tests both network connectivity and DNS resolution for each endpoint and provides a summary report at the end.

.PARAMETER testType
The type of test to perform. 'Lite' will test a single IP address, while 'Full' will test each IP in the CIDR range.

.PARAMETER testScope
Scope of the network endpoints to test specific to the technology required. Leave blank to test all endpoints.
Valid values are 'Autopilot', 'W365' for Windows 365 Cloud PC connectivity, 'W365-Client' for Windows 365 Cloud PC client connectivity, 'W365-CloudPC' for Windows 365 Cloud PC backend connectivity, and 'Full' for all endpoints.

.PARAMETER region
Region specific endpoints in addition to the global network endpoints. Valid values are 'North America', 'Europe', 'Australia', and 'Asia Pacific'.

.EXAMPLE
.\IntuneNetworkValidator.ps1 -testType Lite -testScope Autopilot -region 'Europe'

#>

[CmdletBinding(DefaultParameterSetName = 'Default')]

param(
    [Parameter(Mandatory = $false, HelpMessage = 'The type of test to perform. Lite will test a single IP address, while Full will test each IP in the CIDR range.')]
    [ValidateSet('Lite', 'Full')]
    [String]$testType = 'Lite',

    [Parameter(Mandatory = $false, HelpMessage = 'The scope of the test.')]
    [ValidateSet('Autopilot', 'W365', 'W365-Client', 'W365-CloudPC', 'Full')]
    [String]$testScope = 'Autopilot',

    [Parameter(Mandatory = $false, HelpMessage = 'Valid values are North America, Europe, Australia, and Asia Pacific.')]
    [ValidateSet('North America', 'Europe', 'Australia', 'Asia Pacific')]
    [String]$region
)

#region variables
$timeoutSecs = 2
$networkEndpointsCSV = 'https://raw.githubusercontent.com/ennnbeee/IntuneNetworkValidator/main/IntuneNetworkEndpoints.csv3'
$idsAutopilot = @('170', '172', '56', '164', '201', '203', '204')
$idsW365Client = @('209', '210')
$idsW365CloudPC = @('207', '208', '163', '170', '204', '203', '164')
$idsW365 = $idsW365Client + $idsW365CloudPC
#endregion variables

#region functions
function Get-IPRangeFromCIDR() {
    <#
    .SYNOPSIS
    Converts a CIDR notation to a range of IP addresses.

    .DESCRIPTION
    This function takes a CIDR notation (e.g., 192.168.1.0/24) and returns the start and end IP addresses of the range.

    .PARAMETER cidrNotation
    The CIDR notation to convert (e.g., 192.168.1.0/24).

    #>

    param
    (
        [parameter(Mandatory = $true)]
        [string]$cidrNotation
    )

    if ($cidrNotation -like '*/*') {
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
        $ipStart = ($ipNum -band $mask)
        $ipEnd = ($ipNum -bor (-bnot $mask))

        # return as tuple of strings:
        ([BitConverter]::GetBytes([Net.IPAddress]::HostToNetworkOrder($ipStart)) | ForEach-Object { $_ } ) -join '.'
        ([BitConverter]::GetBytes([Net.IPAddress]::HostToNetworkOrder($ipEnd)) | ForEach-Object { $_ } ) -join '.'
    }
    else {
        $cidrNotation
    }
}
function Test-DNS {
    <#
    .SYNOPSIS
    Verifies that DNS is working for a given URL and that the IP does not resolve a sinkhole (0.0.0.0 or 127.0.0.1 or ::).

    .DESCRIPTION
    This function takes a URL, resolves it to an IP address, and checks that the resolved IP address is not a known sinkhole address

    .PARAMETER dnsTarget
    The IP address or hostname to test DNS resolution for.

    #>
    param(
        [parameter(Mandatory = $true)]
        [string]$dnsTarget
    )

    $dnsResult = $true
    $resolvedDNSRecords = Resolve-DnsName -Name $dnsTarget -ErrorAction SilentlyContinue
    if ($resolvedDNSRecords.count) {
        foreach ($dnsARecord in $resolvedDNSRecords.IP4Address) {
            if ($dnsARecord.IP4Address) {
                if ($dnsARecord -eq '0.0.0.0' -or $dnsARecord -eq '127.0.0.1') {
                    $dnsResult = $false
                    break
                }
            }
        }
        foreach ($dnsAAAARecord in $resolvedDNSRecords.IP6Address) {
            if ($dnsAAAARecord -eq '::') {
                Write-Log -Message "DNS sinkhole detected: Address $dnsTarget resolved to an invalid address" -Component 'TestDNS' -Type 2
                $dnsResult = $false
                break
            }
        }
    }
    else {
        $dnsResult = $false
    }
    return $dnsResult
}
function Get-NetworkEndpoint() {
    <#
    .SYNOPSIS
    Retrieves the list of network endpoints to test from a CSV file hosted on GitHub. If the retrieval fails, it falls back to a hardcoded list of endpoints within the script.

    .DESCRIPTION
    This function attempts to download a CSV file containing the network endpoints to validate from a specified URL. If the download is successful, it parses the CSV content and returns it as a list of objects. If the download fails (e.g., due to network issues or an invalid URL), it logs a warning and uses a predefined list of network endpoints embedded in the script.

    .PARAMETER csvUrl
    The URL of the CSV file containing the network endpoints to validate.

    #>

    param
    (
        [parameter(Mandatory = $false)]
        [String]$csvUrl
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
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '*.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = 'manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '*.dm.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = 'EnterpriseEnrollment.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '104.46.162.96/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.67.13.176/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.67.15.128/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.69.231.128/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.69.67.224/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.70.78.128/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.70.79.128/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.74.111.192/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.77.53.176/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.86.221.176/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.89.174.240/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '13.89.175.192/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.37.153.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.37.192.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.38.81.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.41.1.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.42.1.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.42.130.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.42.224.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.43.129.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.44.19.224/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.119.8.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.67.121.224/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.70.151.32/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.71.14.96/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.74.25.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.78.245.240/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.78.247.128/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.79.197.64/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.79.197.96/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.80.180.208/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.80.180.224/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.80.184.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.82.248.224/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.82.249.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '52.150.137.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '52.162.111.96/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '52.168.116.128/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '52.182.141.192/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '52.236.189.96/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '52.240.244.160/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.204.193.12/30'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.204.193.10/31'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.192.174.216/29'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.192.159.40/29'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '104.208.197.64/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '172.160.217.160/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '172.201.237.160/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '172.202.86.192/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '172.205.63.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '172.212.214.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '172.215.131.0/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.168.189.128/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.199.207.192/28'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.204.194.128/31'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.208.149.192/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.208.157.128/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.214.131.176/29'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.43.129.0/24'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '20.91.147.72/29'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.145.74.224/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.150.254.64/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.154.145.224/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.200.254.32/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.207.244.0/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.213.25.64/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.213.86.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.216.205.32/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '4.237.143.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '40.84.70.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '48.218.252.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '57.151.0.192/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '57.153.235.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '57.154.140.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '57.154.195.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '57.155.45.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '68.218.134.96/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '74.224.214.64/27'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '74.242.35.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '172.208.170.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '74.241.231.0/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '163'; Category = 'Intune Core Service'; Subcategory = 'Intune Client and Host Service'; Endpoint = '74.242.184.128/25'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 172 MDM Delivery Optimization
            [PSCustomObject]@{Id = '172'; Category = 'Intune Core Service'; Subcategory = 'MDM Delivery Optimization'; Endpoint = '*.do.dsp.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '172'; Category = 'Intune Core Service'; Subcategory = 'MDM Delivery Optimization'; Endpoint = '*.dl.delivery.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 170 MEM - Win32Apps
            [PSCustomObject]@{Id = '170'; Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swda01-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '170'; Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swda02-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '170'; Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdb01-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '170'; Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdb02-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '170'; Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdc01-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '170'; Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdc02-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '170'; Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdd01-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '170'; Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdd02-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '170'; Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdin01-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '170'; Category = 'Intune Core Service'; Subcategory = 'Win32Apps'; Endpoint = 'swdin02-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 97 Consumer Outlook.com, OneDrive, Device authentication, and Microsoft account
            [PSCustomObject]@{Id = '97'; Category = 'Intune Core Service'; Subcategory = 'Consumer Devices'; Endpoint = 'swdin01-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '97'; Category = 'Intune Core Service'; Subcategory = 'Consumer Devices'; Endpoint = 'swdin02-mscdn.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 190 Endpoint discovery
            [PSCustomObject]@{Id = '190'; Category = 'Intune Core Service'; Subcategory = 'Endpoint Discovery'; Endpoint = 'go.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 189 Dependency - Feature Deployment
            [PSCustomObject]@{Id = '189'; Category = 'Intune Core Service'; Subcategory = 'Feature Deployment'; Endpoint = 'config.edge.skype.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '189'; Category = 'Intune Core Service'; Subcategory = 'Feature Deployment'; Endpoint = 'ecs.office.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 192 Organizational messages
            [PSCustomObject]@{Id = '192'; Category = 'Intune Core Service'; Subcategory = 'Organizational Messages'; Endpoint = 'fd.api.orgmsg.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '192'; Category = 'Intune Core Service'; Subcategory = 'Organizational Messages'; Endpoint = 'ris.prod.api.personalization.ideas.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 56 Authentication and Identity, includes Microsoft Entra ID and Entra ID related services.
            [PSCustomObject]@{Id = '56'; Category = 'Authentication Dependencies'; Subcategory = 'Authentication and Identity'; Endpoint = 'login.microsoftonline.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '56'; Category = 'Authentication Dependencies'; Subcategory = 'Authentication and Identity'; Endpoint = 'graph.windows.net'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 150 Office Customization Service provides Office 365 ProPlus deployment configuration, application settings, and cloud based policy management.
            [PSCustomObject]@{Id = '150'; Category = 'Authentication Dependencies'; Subcategory = 'Office Customization'; Endpoint = '*.officeconfig.msocdn.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '150'; Category = 'Authentication Dependencies'; Subcategory = 'Office Customization'; Endpoint = 'config.office.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 59 Identity supporting services & CDNs.
            [PSCustomObject]@{Id = '59'; Category = 'Authentication Dependencies'; Subcategory = 'Identity Supporting Services'; Endpoint = 'enterpriseregistration.windows.net'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '59'; Category = 'Authentication Dependencies'; Subcategory = 'Identity Supporting Services'; Endpoint = 'certauth.enterpriseregistration.windows.net'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 172 MDM - Delivery Optimization Dependencies
            [PSCustomObject]@{Id = '172'; Category = 'Delivery Optimization Dependencies'; Subcategory = 'Delivery Optimization'; Endpoint = '*.do.dsp.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '172'; Category = 'Delivery Optimization Dependencies'; Subcategory = 'Delivery Optimization'; Endpoint = '*.dl.delivery.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 172 MEM - WNS Dependencies
            [PSCustomObject]@{Id = '172'; Category = 'Windows Push Notification Services'; Subcategory = 'WNS Dependencies'; Endpoint = '*.notify.windows.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '172'; Category = 'Windows Push Notification Services'; Subcategory = 'WNS Dependencies'; Endpoint = '*.wns.windows.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '172'; Category = 'Windows Push Notification Services'; Subcategory = 'WNS Dependencies'; Endpoint = 'sinwns1011421.wns.windows.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '172'; Category = 'Windows Push Notification Services'; Subcategory = 'WNS Dependencies'; Endpoint = 'sin.notify.windows.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 181 MEM - Remote Help Feature
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = '*.support.services.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'remoteassistance.support.services.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'teams.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'remoteassistanceprodacs.communication.azure.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'edge.skype.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'aadcdn.msftauth.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'aadcdn.msauth.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = '*.msauth.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = '*.aria.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'browser.pipe.aria.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = '*.events.data.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'v10c.events.data.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = '*.monitor.azure.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'js.monitor.azure.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'go-apac.trouter.communications.svc.cloud.microsoft'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'go-eu.trouter.communications.svc.cloud.microsoft'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'api.flightproxy.skype.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help'; Endpoint = 'ecs.communication.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help Web'; Endpoint = 'remotehelp.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '181'; Category = 'Remote Help'; Subcategory = 'Remote Help Web'; Endpoint = 'remoteassistanceprodacseu.communication.azure.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            # ID 164 Windows Autopilot - Windows Update
            [PSCustomObject]@{Id = '164'; Category = 'Windows Autopilot'; Subcategory = 'Windows Update'; Endpoint = '*.windowsupdate.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '164'; Category = 'Windows Autopilot'; Subcategory = 'Windows Update'; Endpoint = '*.dl.delivery.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '164'; Category = 'Windows Autopilot'; Subcategory = 'Windows Update'; Endpoint = '*.prod.do.dsp.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '164'; Category = 'Windows Autopilot'; Subcategory = 'Windows Update'; Endpoint = '*.delivery.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '164'; Category = 'Windows Autopilot'; Subcategory = 'Windows Update'; Endpoint = '*.update.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '164'; Category = 'Windows Autopilot'; Subcategory = 'Windows Update'; Endpoint = 'tsfe.trafficshaping.dsp.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '164'; Category = 'Windows Autopilot'; Subcategory = 'Windows Update'; Endpoint = 'adl.windows.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            # ID 165 Windows Autopilot - NTP Sync
            [PSCustomObject]@{Id = '165'; Category = 'Windows Autopilot'; Subcategory = 'NTP Sync'; Endpoint = 'time.windows.com'; Protocol = 'UDP'; Ports = '123'; Region = 'Global' }
            # ID 169 Windows Autopilot - WNS Dependencies
            [PSCustomObject]@{Id = '169'; Category = 'Windows Autopilot'; Subcategory = 'WNS Dependencies'; Endpoint = 'clientconfig.passport.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '169'; Category = 'Windows Autopilot'; Subcategory = 'WNS Dependencies'; Endpoint = 'windowsphone.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '169'; Category = 'Windows Autopilot'; Subcategory = 'WNS Dependencies'; Endpoint = '*.s-microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '169'; Category = 'Windows Autopilot'; Subcategory = 'WNS Dependencies'; Endpoint = 'c.s-microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 173 Windows Autopilot - Third-party deployment dependencies
            [PSCustomObject]@{Id = '173'; Category = 'Windows Autopilot'; Subcategory = 'Third-party Deployment Dependencies'; Endpoint = 'ekop.intel.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '173'; Category = 'Windows Autopilot'; Subcategory = 'Third-party Deployment Dependencies'; Endpoint = 'ekcert.spserv.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '173'; Category = 'Windows Autopilot'; Subcategory = 'Third-party Deployment Dependencies'; Endpoint = 'ftpm.amd.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 182 Windows Autopilot - Diagnostics upload
            [PSCustomObject]@{Id = '182'; Category = 'Windows Autopilot'; Subcategory = 'Diagnostics Upload'; Endpoint = 'lgmsapeweu.blob.core.windows.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '182'; Category = 'Windows Autopilot'; Subcategory = 'Diagnostics Upload'; Endpoint = 'lgmsapewus2.blob.core.windows.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '182'; Category = 'Windows Autopilot'; Subcategory = 'Diagnostics Upload'; Endpoint = 'lgmsapesea.blob.core.windows.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '182'; Category = 'Windows Autopilot'; Subcategory = 'Diagnostics Upload'; Endpoint = 'lgmsapeaus.blob.core.windows.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '182'; Category = 'Windows Autopilot'; Subcategory = 'Diagnostics Upload'; Endpoint = 'lgmsapeind.blob.core.windows.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 201 Microsoft Store
            [PSCustomObject]@{Id = '201'; Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'displaycatalog.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '201'; Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'purchase.md.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '201'; Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'licensing.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '201'; Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'storeedgefd.dsx.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '201'; Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'img-prod-cms-rt-microsoft-com.akamaized.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '201'; Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'img-s-msn-com.akamaized.net'; Protocol = 'TCP'; Ports = '80'; Region = 'Global' }
            [PSCustomObject]@{Id = '201'; Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'livetileedge.dsx.mp.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '201'; Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = '*.wns.windows.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '201'; Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'storecatalogrevocation.storequality.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '201'; Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'manage.devcenter.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '201'; Category = 'Microsoft Store'; Subcategory = 'Microsoft Store API'; Endpoint = 'share.microsoft.com'; Protocol = 'TCP'; Ports = '80'; Region = 'Global' }
            # ID 202 Device Health Attestation
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape1.eus.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape2.eus2.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape3.cus.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape4.wus.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape5.scus.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape6.ncus.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape7.neu.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape8.neu.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape9.neu.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape10.weu.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape11.weu.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape12.weu.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape13.jpe.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape17.jpe.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape18.jpe.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Id = '202'; Category = 'Device Health Attestation'; Subcategory = 'Microsoft Azure Attestation'; Endpoint = 'intunemaape19.jpe.attest.azure.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            # ID 203 PowerShell scripts and Win32 apps
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'naprodimedatapri.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'naprodimedatasec.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'naprodimedatahotfix.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswda-afd-primary.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswda-afd-secondary.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswda-afd-hotfix.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'North America' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'euprodimedatapri.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'euprodimedatasec.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'euprodimedatahotfix.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswdb-afd-primary.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswdb-afd-secondary.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswdb-afd-hotfix.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'approdimedatapri.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'approdimedatasec.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'approdimedatahotfix.azureedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswdc-afd-primary.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswdc-afd-secondary.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Id = '203'; Category = 'Scripts and Apps'; Subcategory = 'Win32 Apps'; Endpoint = 'imeswdc-afd-hotfix.manage.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Asia Pacific' }
            # ID 204 Windows Autopatch
            [PSCustomObject]@{Id = '204'; Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'mmdcustomer.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '204'; Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'mmdls.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '204'; Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'devicelistenerprod.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '204'; Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'devicelistenprod.eudb.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Europe' }
            [PSCustomObject]@{Id = '204'; Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'login.windows.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '204'; Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'device.autopatch.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '204'; Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'services.autopatch.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '204'; Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = 'payloadprod*.blob.core.windows.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '204'; Category = 'Windows Autopatch'; Subcategory = 'Windows Autopatch'; Endpoint = '*.webpubsub.azure.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 205 Windows 11 Enterprise
            [PSCustomObject]@{Id = '205'; Category = 'Windows 11'; Subcategory = 'Apps'; Endpoint = 'tile-service.weather.microsoft.com'; Protocol = 'TCP'; Ports = '80'; Region = 'Global' }
            [PSCustomObject]@{Id = '205'; Category = 'Windows 11'; Subcategory = 'Apps'; Endpoint = 'cdn.onenote.net'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '205'; Category = 'Windows 11'; Subcategory = 'Apps'; Endpoint = 'evoke-windowsservices-tas.msedge.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '205'; Category = 'Windows 11'; Subcategory = 'Certificates'; Endpoint = 'ctldl.windowsupdate.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '205'; Category = 'Windows 11'; Subcategory = 'Certificates'; Endpoint = 'ocsp.digicert.com'; Protocol = 'TCP'; Ports = '80'; Region = 'Global' }
            [PSCustomObject]@{Id = '205'; Category = 'Windows 11'; Subcategory = 'Device Authentication'; Endpoint = 'login.live.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '205'; Category = 'Windows 11'; Subcategory = 'Licensing'; Endpoint = 'licensing.mp.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '205'; Category = 'Windows 11'; Subcategory = 'Defender'; Endpoint = 'wdcp.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '205'; Category = 'Windows 11'; Subcategory = 'Defender'; Endpoint = '*.smartscreen-prod.microsoft.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '205'; Category = 'Windows 11'; Subcategory = 'Defender'; Endpoint = 'checkappexec.microsoft.com'; Protocol = 'TCP'; Ports = '80, 443'; Region = 'Global' }
            [PSCustomObject]@{Id = '205'; Category = 'Windows 11'; Subcategory = 'Defender'; Endpoint = 'ping-edge.smartscreen.microsoft.com'; Protocol = 'TCP'; Ports = '80'; Region = 'Global' }
            [PSCustomObject]@{Id = '205'; Category = 'Windows 11'; Subcategory = 'Defender'; Endpoint = 'data-edge.smartscreen.microsoft.com'; Protocol = 'TCP'; Ports = '80'; Region = 'Global' }
            [PSCustomObject]@{Id = '205'; Category = 'Windows 11'; Subcategory = 'Defender'; Endpoint = 'nav-edge.smartscreen.microsoft.com'; Protocol = 'TCP'; Ports = '80'; Region = 'Global' }
            # ID 206 Windows 365
            [PSCustomObject]@{Id = '206'; Category = 'W365-CloudPC'; Subcategory = 'Registration'; Endpoint = 'login.microsoftonline.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '206'; Category = 'W365-CloudPC'; Subcategory = 'Registration'; Endpoint = 'login.live.com'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            [PSCustomObject]@{Id = '206'; Category = 'W365-CloudPC'; Subcategory = 'Registration'; Endpoint = 'enterpriseregistration.windows.net'; Protocol = 'TCP'; Ports = '443'; Region = 'Global' }
            # ID 207 Windows 365 Cloid PC
            [PSCustomObject]@{Id = '207'; Category = 'W365-CloudPC'; Subcategory = 'IoT Provisioning'; Endpoint = 'global.azure-devices-provisioning.net'; Protocol = 'TCP'; Ports = '443, 5671'; Region = 'Global' }
            [PSCustomObject]@{Id = '207'; Category = 'W365-CloudPC'; Subcategory = 'IoT Hubs'; Endpoint = 'hm-iot-in-prod-prap01.azure-devices.net'; Protocol = 'TCP'; Ports = '443,5671'; Region = 'Asia Pacific' }
            [PSCustomObject]@{Id = '207'; Category = 'W365-CloudPC'; Subcategory = 'IoT Hubs'; Endpoint = 'hm-iot-in-prod-prau01.azure-devices.net'; Protocol = 'TCP'; Ports = '443,5671'; Region = 'Australia' }
            [PSCustomObject]@{Id = '207'; Category = 'W365-CloudPC'; Subcategory = 'IoT Hubs'; Endpoint = 'hm-iot-in-prod-preu01.azure-devices.net'; Protocol = 'TCP'; Ports = '443,5671'; Region = 'Europe' }
            [PSCustomObject]@{Id = '207'; Category = 'W365-CloudPC'; Subcategory = 'IoT Hubs'; Endpoint = 'hm-iot-in-prod-prna01.azure-devices.net'; Protocol = 'TCP'; Ports = '443,5671'; Region = 'North America' }
            [PSCustomObject]@{Id = '207'; Category = 'W365-CloudPC'; Subcategory = 'IoT Hubs'; Endpoint = 'hm-iot-in-prod-prna02.azure-devices.net'; Protocol = 'TCP'; Ports = '443,5671'; Region = 'North America' }
            [PSCustomObject]@{Id = '207'; Category = 'W365-CloudPC'; Subcategory = 'IoT Hubs'; Endpoint = 'hm-iot-in-2-prod-preu01.azure-devices.net'; Protocol = 'TCP'; Ports = '443,5671'; Region = 'Europe' }
            [PSCustomObject]@{Id = '207'; Category = 'W365-CloudPC'; Subcategory = 'IoT Hubs'; Endpoint = 'hm-iot-in-2-prod-prna01.azure-devices.net'; Protocol = 'TCP'; Ports = '443,5671'; Region = 'North America' }
            [PSCustomObject]@{Id = '207'; Category = 'W365-CloudPC'; Subcategory = 'IoT Hubs'; Endpoint = 'hm-iot-in-3-prod-preu01.azure-devices.net'; Protocol = 'TCP'; Ports = '443,5671'; Region = 'Europe' }
            [PSCustomObject]@{Id = '207'; Category = 'W365-CloudPC'; Subcategory = 'IoT Hubs'; Endpoint = 'hm-iot-in-3-prod-prna01.azure-devices.net'; Protocol = 'TCP'; Ports = '443,5671'; Region = 'North America' }
            [PSCustomObject]@{Id = '207'; Category = 'W365-CloudPC'; Subcategory = 'IoT Hubs'; Endpoint = 'hm-iot-in-4-prod-prna01.azure-devices.net'; Protocol = 'TCP'; Ports = '443,5671'; Region = 'North America' }
            # ID 208 AVD Session Host
            [PSCustomObject]@{Id = '208'; Category = 'AVD-SessionHost'; Subcategory = 'Core'; Endpoint = 'login.microsoftonline.com'; Protocol = 'TCP'; Ports = 443; Region = 'Global'; Notes = 'Authentication to Microsoft Online Services' }
            [PSCustomObject]@{Id = '208'; Category = 'AVD-SessionHost'; Subcategory = 'Core'; Endpoint = '51.5.0.0/16'; Protocol = 'TCP'; Ports = 3478; Region = 'Global'; Notes = 'RDP Shortpath relayed connectivity (TURN/STUN). Service tag: WindowsVirtualDesktop' }
            [PSCustomObject]@{Id = '208'; Category = 'AVD-SessionHost'; Subcategory = 'Core'; Endpoint = 'catalogartifact.azureedge.net'; Protocol = 'TCP'; Ports = 443; Region = 'Global'; Notes = 'Azure Marketplace. Service tag: AzureFrontDoor.Frontend' }
            [PSCustomObject]@{Id = '208'; Category = 'AVD-SessionHost'; Subcategory = 'Core'; Endpoint = 'aka.ms'; Protocol = 'TCP'; Ports = 443; Region = 'Global'; Notes = 'Microsoft URL shortener' }
            [PSCustomObject]@{Id = '208'; Category = 'AVD-SessionHost'; Subcategory = 'Monitoring'; Endpoint = 'gcs.prod.monitoring.core.windows.net'; Protocol = 'TCP'; Ports = 443; Region = 'Global'; Notes = 'AVD agent traffic. Service tag: AzureMonitor' }
            [PSCustomObject]@{Id = '208'; Category = 'AVD-SessionHost'; Subcategory = 'Activation'; Endpoint = 'azkms.core.windows.net'; Protocol = 'TCP'; Ports = 1688; Region = 'Global'; Notes = 'Windows KMS activation' }
            [PSCustomObject]@{Id = '208'; Category = 'AVD-SessionHost'; Subcategory = 'Updates'; Endpoint = 'mrsglobalsteus2prod.blob.core.windows.net'; Protocol = 'TCP'; Ports = 443; Region = 'Global'; Notes = 'AVD agent and SXS stack updates' }
            [PSCustomObject]@{Id = '208'; Category = 'AVD-SessionHost'; Subcategory = 'Portal'; Endpoint = 'wvdportalstorageblob.blob.core.windows.net'; Protocol = 'TCP'; Ports = 443; Region = 'Global'; Notes = 'Azure portal support' }
            [PSCustomObject]@{Id = '208'; Category = 'AVD-SessionHost'; Subcategory = 'Azure'; Endpoint = '169.254.169.254/32'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'Azure Instance Metadata Service (IMDS)' }
            [PSCustomObject]@{Id = '208'; Category = 'AVD-SessionHost'; Subcategory = 'Azure'; Endpoint = '168.63.129.16/32'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'Session host health monitoring' }
            [PSCustomObject]@{Id = '208'; Category = 'AVD-SessionHost'; Subcategory = 'Certificates'; Endpoint = 'oneocsp.microsoft.com'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'OCSP certificate validation' }
            [PSCustomObject]@{Id = '208'; Category = 'AVD-SessionHost'; Subcategory = 'Certificates'; Endpoint = 'www.microsoft.com'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'Certificate chain' }
            [PSCustomObject]@{Id = '208'; Category = 'AVD-SessionHost'; Subcategory = 'Certificates'; Endpoint = 'azcsprodeusaikpublish.blob.core.windows.net'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'AIK certificate publishing' }
            [PSCustomObject]@{Id = '208'; Category = 'AVD-SessionHost'; Subcategory = 'Certificates'; Endpoint = 'ctldl.windowsupdate.com'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'Certificate Trust List download' }
            # ID 209 Client AVD
            [PSCustomObject]@{Id = '209'; Category = 'Client-AVD'; Subcategory = 'Auth'; Endpoint = 'login.microsoftonline.com'; Protocol = 'TCP'; Ports = 443; Region = 'Global'; Notes = 'Authentication to Microsoft Online Services' }
            [PSCustomObject]@{Id = '209'; Category = 'Client-AVD'; Subcategory = 'Navigation'; Endpoint = 'go.microsoft.com'; Protocol = 'TCP'; Ports = 443; Region = 'Global'; Notes = 'Microsoft FWLinks' }
            [PSCustomObject]@{Id = '209'; Category = 'Client-AVD'; Subcategory = 'Navigation'; Endpoint = 'aka.ms'; Protocol = 'TCP'; Ports = 443; Region = 'Global'; Notes = 'Microsoft URL shortener' }
            [PSCustomObject]@{Id = '209'; Category = 'Client-AVD'; Subcategory = 'Docs'; Endpoint = 'learn.microsoft.com'; Protocol = 'TCP'; Ports = 443; Region = 'Global'; Notes = 'Microsoft documentation' }
            [PSCustomObject]@{Id = '209'; Category = 'Client-AVD'; Subcategory = 'Legal'; Endpoint = 'privacy.microsoft.com'; Protocol = 'TCP'; Ports = 443; Region = 'Global'; Notes = 'Microsoft privacy statement' }
            [PSCustomObject]@{Id = '209'; Category = 'Client-AVD'; Subcategory = 'Service'; Endpoint = 'graph.microsoft.com'; Protocol = 'TCP'; Ports = 443; Region = 'Global'; Notes = 'Microsoft Graph API' }
            [PSCustomObject]@{Id = '209'; Category = 'Client-AVD'; Subcategory = 'Portal'; Endpoint = 'windows.cloud.microsoft'; Protocol = 'TCP'; Ports = 443; Region = 'Global'; Notes = 'Connection center' }
            [PSCustomObject]@{Id = '209'; Category = 'Client-AVD'; Subcategory = 'Portal'; Endpoint = 'windows365.microsoft.com'; Protocol = 'TCP'; Ports = 443; Region = 'Global'; Notes = 'Windows 365 service traffic' }
            [PSCustomObject]@{Id = '209'; Category = 'Client-AVD'; Subcategory = 'Portal'; Endpoint = 'ecs.office.com'; Protocol = 'TCP'; Ports = 443; Region = 'Global'; Notes = 'Connection center configuration' }
            [PSCustomObject]@{Id = '209'; Category = 'Client-AVD'; Subcategory = 'Certificates'; Endpoint = 'www.microsoft.com'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'Certificate chain' }
            [PSCustomObject]@{Id = '209'; Category = 'Client-AVD'; Subcategory = 'Certificates'; Endpoint = 'azcsprodeusaikpublish.blob.core.windows.net'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'AIK certificate publishing' }
            # ID 210 Client - Azure CA Certificate checks (closed network)
            # Source: https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-certificate-authority-details
            # Note: oneocsp.microsoft.com and www.microsoft.com already covered above in Client-AVD certs
            [PSCustomObject]@{Id = '210'; Category = 'Client-AVD-CertCA'; Subcategory = 'Certificate Authority'; Endpoint = 'cacerts.digicert.com'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'AIA - DigiCert CA certificate downloads' }
            [PSCustomObject]@{Id = '210'; Category = 'Client-AVD-CertCA'; Subcategory = 'Certificate Authority'; Endpoint = 'cacerts.digicert.cn'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'AIA - DigiCert CA certificate downloads (CN)' }
            [PSCustomObject]@{Id = '210'; Category = 'Client-AVD-CertCA'; Subcategory = 'Certificate Authority'; Endpoint = 'cacerts.geotrust.com'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'AIA - GeoTrust CA certificate downloads' }
            [PSCustomObject]@{Id = '210'; Category = 'Client-AVD-CertCA'; Subcategory = 'Certificate Authority'; Endpoint = 'caissuers.microsoft.com'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'AIA - Microsoft CA certificate downloads' }
            [PSCustomObject]@{Id = '210'; Category = 'Client-AVD-CertCA'; Subcategory = 'Certificate Authority'; Endpoint = 'www.microsoft.com'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'AIA and CRL - Microsoft certificate downloads' }
            [PSCustomObject]@{Id = '210'; Category = 'Client-AVD-CertCA'; Subcategory = 'Certificate Authority'; Endpoint = 'crl3.digicert.com'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'CRL - DigiCert CRL distribution point' }
            [PSCustomObject]@{Id = '210'; Category = 'Client-AVD-CertCA'; Subcategory = 'Certificate Authority'; Endpoint = 'crl4.digicert.com'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'CRL - DigiCert CRL distribution point' }
            [PSCustomObject]@{Id = '210'; Category = 'Client-AVD-CertCA'; Subcategory = 'Certificate Authority'; Endpoint = 'crl.digicert.cn'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'CRL - DigiCert CRL distribution point (CN)' }
            [PSCustomObject]@{Id = '210'; Category = 'Client-AVD-CertCA'; Subcategory = 'Certificate Authority'; Endpoint = 'ocsp.digicert.com'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'OCSP - DigiCert OCSP responder' }
            [PSCustomObject]@{Id = '210'; Category = 'Client-AVD-CertCA'; Subcategory = 'Certificate Authority'; Endpoint = 'ocsp.digicert.cn'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'OCSP - DigiCert OCSP responder (CN)' }
            [PSCustomObject]@{Id = '210'; Category = 'Client-AVD-CertCA'; Subcategory = 'Certificate Authority'; Endpoint = 'oneocsp.microsoft.com'; Protocol = 'TCP'; Ports = 80; Region = 'Global'; Notes = 'OCSP - Microsoft OCSP responder' }
        )
        Write-Host 'Successfully retrieved network endpoints from the script.'-ForegroundColor Green
    }
    if ($region) {
        $networkEndpoints = $networkEndpoints | Where-Object { $_.Region -eq $region -or $_.Region -eq 'Global' }
    }
    return $networkEndpoints
    $networkEndpoints | Select-Object -Property Id, Category, Subcategory
}
function Test-NetworkEndpoint() {
    <#
    .SYNOPSIS
    Tests connectivity to a specified network endpoint.

    .DESCRIPTION
    This function tests the connectivity to a specified network endpoint by attempting to establish a connection using the specified protocol and port(s).
    It supports TCP  protocols and can test individual ports or a range of ports.

    .PARAMETER category
    The category of the network endpoint, such as 'Windows Autopilot' or 'Microsoft Store'.

    .PARAMETER subCategory
    The subcategory of the network endpoint, such as 'WNS Dependencies' or 'Microsoft Store API'.

    .PARAMETER address
    The address of the network endpoint, which can be a hostname, an IP address, a CIDR range, or a wildcard domain.

    .PARAMETER protocol
    The protocol to use for testing connectivity, either 'TCP' or 'UDP'.

    .PARAMETER ports
    The port or ports to test, specified as a comma-separated string (e.g., '80, 443').

    .PARAMETER testType
    The type of test to perform when the address is a CIDR range. 'Lite' will test the CIDR as a whole, while 'Full' will test each IP in the CIDR range. Default is 'Lite'.
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
        $testItems = @()
        $portSplits = @($ports.Split(',').Trim())
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
            $testItem.Ports = $portSplit

            # Wildcard domain
            if ($testItem.Address -match '^\*') {
                $testItem.Status = 'WILD'
                $testItems += @($testItem)
            }
            # IP Address Range
            elseif ($testItem.Address -match '/\d+$') {

                if ($testItem.Address -match ':') {
                    $testItem.Status = 'IPV6'
                    $testItems += @($testItem)
                }
                else {
                    switch ($testType) {
                        'Lite' {
                            $testItem.Status = 'IP'
                            $ipAddress = ($testItem.address -split '/')[0]
                            $testItem.address = $ipAddress
                            $testItems += @($testItem)
                        }
                        'Full' {
                            $startIP = (Get-IPRangeFromCIDR -cidrNotation $address)[0]
                            $endIP = (Get-IPRangeFromCIDR -cidrNotation $address)[1]
                            $startIPAddr = [Net.IPAddress]::Parse($startIP)
                            $startIPNum = [Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($startIPAddr.GetAddressBytes(), 0))
                            $endIPAddr = [Net.IPAddress]::Parse($endIP)
                            $endIPNum = [Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($endIPAddr.GetAddressBytes(), 0))

                            foreach ($ip in $startIPNum..$endIPNum) {
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
                            default {}

                        }
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
        foreach ($testItem in $testItems) {
            $tcpTest = $false
            switch ($testItem.Status) {
                'UDP' {
                    $testItem.Status = 'INFO'
                    Write-Host "`r [" -NoNewline
                    Write-Host "$($testItem.Status)" -ForegroundColor Cyan -NoNewline
                    Write-Host "] $($testItem.Address):$($testItem.Port)"
                }
                'WILD' {
                    Write-Host "`r [" -NoNewline
                    Write-Host 'SKIP' -ForegroundColor Yellow -NoNewline
                    Write-Host "] $($testItem.Address):$($testItem.Port)"
                }
                'IPV6' {
                    Write-Host "`r [" -NoNewline
                    Write-Host 'SKIP' -ForegroundColor Magenta -NoNewline
                    Write-Host "] $($testItem.Address):$($testItem.Port)"
                }
                'DNS' {
                    $dnsOK = Test-DNS -dnsTarget $testItem.Address
                    if ($dnsOK -eq $true) {
                        try {
                            switch ($testItem.Port) {
                                '80' {
                                    $iwrResult = (Invoke-WebRequest -Uri "http://$($testItem.Address)" -UseBasicParsing).StatusCode
                                }
                                '443' {
                                    $iwrResult = (Invoke-WebRequest -Uri "https://$($testItem.Address)" -UseBasicParsing).StatusCode
                                }
                                default {
                                    $iwrResult = (Invoke-WebRequest -Uri "http://$($testItem.Address):$($testItem.Port)" -UseBasicParsing).StatusCode
                                }
                            }
                            if ($iwrResult -eq 200) {
                                $testItem.Status = 'OK'
                                Write-Host "`r [" -NoNewline
                                Write-Host ' OK ' -ForegroundColor Green -NoNewline
                                Write-Host "] $($testItem.Address):$($testItem.Port)"
                            }
                            else {
                                $tcpTest = $true
                            }
                        }
                        catch {
                            $tcpTest = $true
                        }
                    }
                    else {
                        $testItem.Status = 'DNS'
                        Write-Host "`r [" -NoNewline
                        Write-Host 'FAIL' -ForegroundColor Red -NoNewline
                        Write-Host "] $($testItem.Address):$($testItem.Port)"
                    }
                }
                'IP' { $tcpTest = $true }
                default { tcpTest = $true }
            }

            if ($tcpTest -eq $true) {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $connect = $tcpClient.BeginConnect($($testItem.Address), $($testItem.Port), $null, $null)
                $waitTime = $connect.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($timeoutSecs), $false)
                if ($waitTime -and -not $tcpClient.Client.Poll(0, [System.Net.Sockets.SelectMode]::SelectError)) {
                    $tcpClient.EndConnect($connect) 2>$null
                    $testItem.Status = 'OK'
                    Write-Host "`r [" -NoNewline
                    Write-Host ' OK ' -ForegroundColor Green -NoNewline
                    Write-Host "] $($testItem.Address):$($testItem.Port)"
                }
                else {
                    $testItem.Status = 'FAIL'
                    Write-Host "`r [" -NoNewline
                    Write-Host 'FAIL' -ForegroundColor Red -NoNewline
                    Write-Host "] $($testItem.Address):$($testItem.Port)"
                }
                $tcpClient.Close()
            }
        }
        return $testItems
    }
}
function Test-NetworkEndpointList () {
    <#
    .SYNOPSIS
    Tests a list of network endpoints for connectivity.

    .DESCRIPTION
    This function takes an array of network endpoints, tests connectivity to each endpoint using the Test-NetworkEndpoint function, and returns a consolidated list of results.

    .PARAMETER networkEndpoints
    An array of network endpoints to test, where each endpoint is a custom object with properties for Category, Subcategory, Endpoint, Protocol, and Ports.

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
            foreach ($subCategory in $subCategories) {
                Write-Host "`n$category" -ForegroundColor Green -NoNewline
                Write-Host " > $subCategory" -ForegroundColor Green
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
    Generates a summary of network endpoint test results.

    .DESCRIPTION
    This function takes an array of network endpoint test results, categorizes them by their status (OK, FAIL, WILD, INFO, IPV6, DNS), and generates a summary report that includes the total number of endpoints tested, the number of endpoints that passed, failed, were skipped due to wildcard domains, had informational status due to UDP protocol, had IPv6 addresses, or had DNS issues.

    .PARAMETER networkEndpointResults
    An array of network endpoint test results, where each result is a custom object with properties for Status, Address, Port, Protocol, Category, and Subcategory.

    #>
    param
    (
        [parameter(Mandatory = $true)]
        [array]$networkEndpointResults
    )
    begin {
        $export = [System.Collections.ArrayList]::new()
        $summary = [PSCustomObject]@{
            'Total'   = $null
            'Passed'  = $null
            'Failed'  = $null
            'Skipped' = $null
            'Info'    = $null
            'IPv6'    = $null
            'DNS'     = $null
        }
    }
    process {
        $summaryOK = $networkEndpointResults | Where-Object { $_.Status -eq 'OK' }
        $summaryFail = $networkEndpointResults | Where-Object { $_.Status -eq 'FAIL' }
        $summaryWild = $networkEndpointResults | Where-Object { $_.Status -eq 'WILD' }
        $summaryIPv6 = $networkEndpointResults | Where-Object { $_.Status -eq 'IPV6' }
        $summaryInfo = $networkEndpointResults | Where-Object { $_.Status -eq 'INFO' }
        $summaryDNS = $networkEndpointResults | Where-Object { $_.Status -eq 'DNS' }
    }
    end {
        $summary.Total = [int]($networkEndpointResults | Measure-Object).Count
        $summary.Passed = [int]($summaryOK | Measure-Object).Count
        $summary.Failed = [int]($summaryFail | Measure-Object).Count
        $summary.Skipped = [int]($summaryWild | Measure-Object).Count
        $summary.Info = [int]($summaryInfo | Measure-Object).Count
        $summary.IPv6 = [int]($summaryIPv6 | Measure-Object).Count
        $summary.DNS = [int]($summaryDNS | Measure-Object).Count

        Write-Host "`n$($summary.Total) Endpoint(s) tested" -ForegroundColor White
        Write-Host "`n$($summary.Passed) Endpoint(s) passed" -ForegroundColor Green
        Write-Host "`n$($summary.Failed) Endpoint(s) failed due to connectivity issues:" -ForegroundColor Red
        $summaryFail | ForEach-Object {
            $padding = [string]::new(' ', [Math]::Max(0, 60 - ($($($_.Address + ':' + $_.Port)).Length)))
            Write-Host "$($_.Address + ':' + $_.Port)" -ForegroundColor White -NoNewline
            Write-Host "$padding($($_.Category) > $($_.Subcategory))" -ForegroundColor DarkCyan

            $export += [PSCustomObject]@{
                Status   = $_.Status
                Address  = $_.Address
                Port     = $_.Port
                Protocol = $_.Protocol
                Category = $_.Category
                Subcat   = $_.Subcategory
            }
        }
        Write-Host "`n$($summary.DNS) Endpoint(s) failed due to DNS issues:" -ForegroundColor DarkYellow
        $summaryDNS | ForEach-Object {
            $padding = [string]::new(' ', [Math]::Max(0, 60 - ($($($_.Address + ':' + $_.Port)).Length)))
            Write-Host "$($_.Address + ':' + $_.Port)" -ForegroundColor White -NoNewline
            Write-Host "$padding($($_.Category) > $($_.Subcategory))" -ForegroundColor DarkCyan

            $export += [PSCustomObject]@{
                Status   = $_.Status
                Address  = $_.Address
                Port     = $_.Port
                Protocol = $_.Protocol
                Category = $_.Category
                Subcat   = $_.Subcategory
            }
        }
        Write-Host "`n$($summary.Skipped) Endpoint(s) skipped due to wildcard domain:" -ForegroundColor Yellow
        $summaryWild | ForEach-Object {
            $padding = [string]::new(' ', [Math]::Max(0, 60 - ($($($_.Address + ':' + $_.Port)).Length)))
            Write-Host "$($_.Address + ':' + $_.Port)" -ForegroundColor White -NoNewline
            Write-Host "$padding($($_.Category) > $($_.Subcategory))" -ForegroundColor DarkCyan

            $export += [PSCustomObject]@{
                Status   = $_.Status
                Address  = $_.Address
                Port     = $_.Port
                Protocol = $_.Protocol
                Category = $_.Category
                Subcat   = $_.Subcategory
            }
        }
        Write-Host "`n$($summary.Info) Endpoint(s) for information due to UDP protocol:" -ForegroundColor Cyan
        $summaryInfo | ForEach-Object {
            $padding = [string]::new(' ', [Math]::Max(0, 60 - ($($($_.Address + ':' + $_.Port)).Length)))
            Write-Host "$($_.Address + ':' + $_.Port)" -ForegroundColor White -NoNewline
            Write-Host "$padding($($_.Category) > $($_.Subcategory))" -ForegroundColor DarkCyan

            $export += [PSCustomObject]@{
                Status   = $_.Status
                Address  = $_.Address
                Port     = $_.Port
                Protocol = $_.Protocol
                Category = $_.Category
                Subcat   = $_.Subcategory
            }
        }
        Write-Host "`n$($summary.IPv6) Endpoint(s) for information due to IPv6 protocol:" -ForegroundColor Magenta
        $summaryIPv6 | ForEach-Object {
            $padding = [string]::new(' ', [Math]::Max(0, 60 - ($($($_.Address + ':' + $_.Port)).Length)))
            Write-Host "$($_.Address + ':' + $_.Port)" -ForegroundColor White -NoNewline
            Write-Host "$padding($($_.Category) > $($_.Subcategory))" -ForegroundColor DarkCyan

            $export += [PSCustomObject]@{
                Status   = $_.Status
                Address  = $_.Address
                Port     = $_.Port
                Protocol = $_.Protocol
                Category = $_.Category
                Subcat   = $_.Subcategory
            }
        }
        return $export
    }
}
function Get-NetworkEndpointSummaryReport () {
    <#
    .SYNOPSIS
    Generates CSV exports of summary report of network endpoint test results.

    .DESCRIPTION
    This function takes an array of network endpoint summary results, where each result includes the status, address, port, protocol, category, and subcategory of the endpoint.
    It generates a detailed report that lists the endpoints that failed connectivity tests.

    .PARAMETER summaryResults
    An array of network endpoint summary results, where each result is a custom object with properties for Status, Address, Port, Protocol, Category, and Subcategory.

    #>
    param
    (
        [parameter(Mandatory = $true)]
        [array]$summaryResults
    )

    begin {
        $statusCategories = $summaryResults | Select-Object -ExpandProperty Status -Unique

    }
    process {
        foreach ($statusCategory in $statusCategories) {
            ($summaryResults | Where-Object { $_.Status -eq $statusCategory }) | Export-Csv -Path ".\INVreport-$statusCategory.csv" -NoTypeInformation -Encoding UTF8 -Force
        }
    }
    end {

    }
}
#endregion functions

if ($region) {
    Write-Host "Getting all Global and $region-specific network endpoints." -ForegroundColor Cyan
    $networkEndpoints = Get-NetworkEndpoint -csvUrl $networkEndpointsCSV | Where-Object { $_.Region -eq 'Global' -or $_.Region -eq $region }
}
else {
    Write-Host 'Getting all Global network endpoints and all region network endpoints.' -ForegroundColor Cyan
    $networkEndpoints = Get-NetworkEndpoint -csvUrl $networkEndpointsCSV
}

#$networkEndpoints | Export-Csv -Path '.\IntuneNetworkEndpoints.csv'-NoTypeInformation -Encoding UTF8 -Force

switch ($testScope) {
    'Autopilot' { $networkEndpoints = $networkEndpoints | Where-Object { $_.Id -in $idsAutopilot } }
    'W365' { $networkEndpoints = $networkEndpoints | Where-Object { $_.Id -in $idsW365 } }
    'W365-CloudPC' { $networkEndpoints = $networkEndpoints | Where-Object { $_.Id -in $idsW365CloudPC } }
    'W365-Client' { $networkEndpoints = $networkEndpoints | Where-Object { $_.Id -in $idsW365Client } }
}

Write-Host "`nTesting connectivity to $($networkEndpoints.Count) global" -ForegroundColor Green -NoNewline
if ($region) {
    Write-Host " and $region-specific" -ForegroundColor Green -NoNewline
}
Write-Host ' network endpoints.' -ForegroundColor Green
Write-Host "Test type: $testType" -ForegroundColor white
Write-Host "Test scope: $testScope" -ForegroundColor White

$allResults = Test-NetworkEndpointList -networkEndpoints $networkEndpoints
$summaryResults = Get-NetworkEndpointSummary -networkEndpointResults $allResults
if ($null -ne $summaryResults) {
    Get-NetworkEndpointSummaryReport -summaryResults $summaryResults
}
