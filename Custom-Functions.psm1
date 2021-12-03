#Version 1.0


#Global Variables
#$env:AzureAdTenant = "navneettsgmail.onmicrosoft.com"
$env:AzureAdTenant = "<enter_ad_tenant_id_here>"
$env:SubscriptionId = "<enter_subscription_id_here>"
$env:GITPROXY = "http.proxy=<proxy_details_here>"
$env:AWS_ACCESS_KEY_ID = "<AWS_ACCESS_KEY_ID_PLACEHOLDER>"
$env:AWS_SECRET_ACCESS_KEY = "<AWS_ACCESS_KEY_SECRET_PLACEHOLDER>"
$env:AWS_DEFAULT_REGION  = "us-east-1"
$env:AWS_DEFAULT_OUTPUT = "json"


$tenants = @"
[
    {
        "SubscriptionFriendlyName":"MSDN",
        "SubscriptionId":"<enter_subscription_id_here>",
        "AzureAdTenantId":"<enter_ad_tenant_id_here>",
        "AzureAdDomain":"navneettsgmail.onmicrosoft.com"
    },
    {
        "SubscriptionFriendlyName":"DeeDee",
        "SubscriptionId":"N/A",
        "AzureAdTenantId":"<enter_ad_tenant_id_here>",
        "AzureAdDomain":"deedee.onmicrosoft.com"
    } # Extend as needed
]
"@

#Version 1.0
Function New-Passwords
{
[cmdletbinding()]
	param
    (
        [int] $Length = 8 ,
        [int] $Count = 10
    )

	$rand = New-Object System.Random
	for($j=1;$j -le $Count; $j++)
	{

		for($i=1;$i -le $Length;$i++)
		{
			$NewPassword = $NewPassword + [char]$rand.Next(33,127)
		}
		Write-Host "$j : $NewPassword"
		Remove-Variable NewPassword
	}
}

Function New-RandomComplexPasswords
{
    [cmdletbinding()]
	param
    (
        [int] $Length = 8 ,
        [int] $Count = 10
    )
    #$test = [System.Reflection.Assembly]::LoadFrom("C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.6.1\System.Web.dll")
    [void] [System.Reflection.Assembly]::LoadFrom("C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Web.dll")
    $Assembly = Add-Type -AssemblyName System.Web
    for($j=1;$j -le $Count; $j++)
	{
        $password = [System.Web.Security.Membership]::GeneratePassword($Length,2)
        Write-Host "$j : $password"
    }
}


Function Restart-AzureVM
{
	param([string]$ServiceName, [string]$Name)
	Stop-AzureVM -ServiceName $ServiceName -Name $Name
	Start-AzureVM -ServiceName $ServiceName -Name $Name
}

Function Get-WhoIsDetails
{
    <#
        .SYNOPSIS
            Lookup the whois details of a specific domain name

        .EXAMPLE
            Get-WhoIsDetails -Url http://www.google.com

        .PARAMETER
            Url
    #>
	param([string] $url)
	$web = New-WebServiceProxy ‘http://www.webservicex.net/whois.asmx?WSDL’
	$web.GetWhoIs($url)
}

function Open-CSVFile
{
[cmdletbinding()]
    <#
        .SYNOPSIS
          This functions provides a wrapper around Import-CSV and Out-GridView functions to view a CSV file. Currently, only comma-separated files are supported.

        .EXAMPLE
          Open-CSVFile <filename>

        .PARAMETER
          Filename
    #>
    param([string] $filename)
       $file = Import-Csv -Path $filename
       $file | Out-GridView -Title ("Viewing: "+$filename.Replace('.\',''))
}

function Get-Proxy
{
    <#
        .SYNOPSIS
            Get the details of the Proxy settings
        .EXAMPLE
            Get-Proxy
        .PARAMETER
            None
    #>
    Get-ItemProperty 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object *Proxy*
}


function Set-Proxy
{
[cmdletbinding()]
    <#
        .SYNOPSIS
            This function sets the system HTTP and HTTPS proxy to the value passed by the user. Both HTTP and HTTPS values have to be passed.
        .EXAMPLE
            Set-Proxy -HTTP localhost:8080
        .PARAMETER
            Proxy
    #>
    param([string] $Proxy = "localhost:8080")

    $value = "http=" + $Proxy + ";https=" + $Proxy
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyServer -Value $value
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'-Name ProxyEnable -Value 1


$source = @"
    [DllImport("wininet.dll")]
    public static extern bool InternetSetOption(int hInternet, int dwOption, int lpBuffer, int dwBufferLength);
"@

    #Create type from source

    $wininet = Add-Type -memberDefinition $source -passthru -name InternetSettings

    #INTERNET_OPTION_PROXY_SETTINGS_CHANGED

    $wininet::InternetSetOption([IntPtr]::Zero, 95, [IntPtr]::Zero, 0)|out-null

    #INTERNET_OPTION_REFRESH

    $wininet::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)|out-null

}

function Enable-Proxy
{
[cmdletbinding()]
    <#
        .SYNOPSIS
            Enable/disable the system proxy by setting the flag to true or false.
        .EXAMPLE
            Enable-Proxy [-Status $false/$true]
		.PARAMETER
			Status [True/False]
    #>
    param([bool] $Status = $true)
    if($Status -eq $true)
    {
        Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'-Name ProxyEnable -Value 1
    }
    else
    {
        Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'-Name ProxyEnable -Value 0
    }

$source=@"
    [DllImport("wininet.dll")]
    public static extern bool InternetSetOption(int hInternet, int dwOption, int lpBuffer, int dwBufferLength);
"@

    #Create type from source

    $wininet = Add-Type -memberDefinition $source -passthru -name InternetSettings

    #INTERNET_OPTION_PROXY_SETTINGS_CHANGED

    $wininet::InternetSetOption([IntPtr]::Zero, 95, [IntPtr]::Zero, 0)|Out-Null

    #INTERNET_OPTION_REFRESH

    $wininet::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)|Out-Null

}

Function Set-IEProxy
{
 [cmdletbinding()]

    $webclient=New-Object System.Net.WebClient
    #$creds=Get-Credential
    #$webclient.Proxy.Credentials=$creds
    $webclient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
}

Function Get-DomainObject
{
 [cmdletbinding()]
	<#
		.SYNOPSIS
			This function gets LDAP properties of an object from AD

		.EXAMPLE
			Get-DomainObject -ObjectType User/Group/Computer -SamAccountName username -Domain FAREAST/REDMOND

		.PARAMETER
			ObjectType
			SamAccountName
			Domain

	#>
	param([string] $objectType = "User", [string] $samAccountName, [string] $domain)
	$server = $domain+ ".corpdir.net" #".corp.microsoft.com"
	Get-ADObject -LDAPFilter "(&(samAccountName=$samAccountName)(objectClass=$objectType))" -Properties * -Server $server
}

<#Function Get-AzureAdAccessToken ## Subsumed by an azure cli command 4
{
[cmdletbinding()]exit
    param( [string] $resource = "https://management.core.windows.net/", [string] $TenantId = $env:AzureAdTenant)

    [System.Reflection.Assembly]::LoadFile("c:\Program Files (x86)\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.dll")
    # Set well-known client ID for AzurePowerShell
    $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"
    # Set redirect URI for Azure PowerShell
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $TenantId
    $accessToken = $authContext.AcquireTokenAsync($resource,$clientId,$redirectUri,"Auto").Wait()
}
#>

Function ConvertTo-Base64String
{
[cmdletbinding()]
    param( [string] $Text)
    [System.Convert]::ToBase64String(([System.Text.Encoding]::UTF8).GetBytes($Text))
}

Function ConvertFrom-Base64String
{
[cmdletbinding()]
    param( [string] $B64String)
    ([System.Text.Encoding]::UTF8).GetString([System.Convert]::FromBase64String($B64String))
}

Function ConvertTo-TimeStamp
{
[cmdletbinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][DateTime] $UTCDate
    )

    $dateObject = (New-Object System.Datetime -ArgumentList (1970,01,01,0,0,0,[System.DateTimeKind]::Utc))
    $timestamp = [System.Math]::Round(($UTCDate - $dateObject).Ticks/10000000) #10Million ticks in a second.

    Write-host $timestamp
}

Function ConvertFrom-TimeStamp
{
[cmdletbinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][int64] $Timestamp
    )

    #Write-host ("UTC: "+[datetime]::new(1970,1,1,0,0,0,[System.DateTimeKind]::Utc).AddSeconds($Timestamp).ToString())
    #Write-host ("Local: "+[datetime]::new(1970,1,1,0,0,0,[System.DateTimeKind]::Local).AddSeconds($Timestamp).ToLocalTime().ToString())

    $dateObject = (New-Object System.Datetime -ArgumentList (1970,01,01,0,0,0,[System.DateTimeKind]::Utc)).AddSeconds($Timestamp)

    Write-host ("UTC: "+$dateObject.ToString())
    Write-host ("Local: "+$dateObject.ToLocalTime().ToString())

}

Function Get-AzureADAccessToken
{
[cmdletbinding()]
    param(
        [Parameter(Mandatory=$false, ValuefromPipeline=$true)][Alias("TenantID","TenantName")] [string] $Authority = $env:AzureAdTenant,
        [Parameter(Mandatory=$false)] [string] $Resource = "https://management.core.windows.net/",
        [Parameter(Mandatory=$false)] [string] $ClientId = "1950a258-227b-4e31-a9cf-717495945fc2",
        [Parameter(Mandatory=$false)] [string] $RedirectUri,
        [Parameter(Mandatory=$false)] [switch] $Prompt
    )

    Write-Verbose $Resource
    Write-Verbose $ClientId
    Write-Verbose $RedirectUri


    [void] [System.Reflection.Assembly]::LoadFile("C:\Program Files (x86)\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Automation\Microsoft.IdentityModel.Clients.ActiveDirectory.dll");
    [void] [System.Reflection.Assembly]::LoadFile("C:\Program Files (x86)\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Automation\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll");
    if ($ClientId -eq "1950a258-227b-4e31-a9cf-717495945fc2" ) #-and ($RedirectUri -eq $null -or $RedirectUri -eq $false)
    {
        $RedirectUri = New-Object System.Uri -ArgumentList "urn:ietf:wg:oauth:2.0:oob"
        Write-Verbose "Client ID set to Powershell."
        Write-Verbose "Redirect URI set to PowerShell's URI."
    }
    elseif ($RedirectUri -eq $null -or $RedirectUri -eq $false)
    {
        Write-Error "Redirect URI not specified. Mention an appropriate redirect URI for the application."
        break
    }

    if ($Prompt)
    {
        $PromptBehaviour = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Always
        Write-Verbose "Prompt mode set to Always"
    }
    else
    {
        $PromptBehaviour = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
        Write-Verbose "Prompt mode set to Auto"
    }

    $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext -ArgumentList ("https://login.microsoftonline.com/" + $Authority)
    try
    {
        $authResult = $authContext.AcquireToken($resource,$clientId,$redirectUri,$PromptBehaviour)
        Write-Verbose $authResult
    }
    catch
    {
        Write-Error "Error acquiring token."
        return
    }

    Write-Output $authResult.CreateAuthorizationHeader().Trim() | clip
    Write-Host -ForegroundColor Yellow "Authorization Header copied to clipboard. Use Ctrl + V (paste) to use the token. Printing only for reference."
    Write-Output "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
    Write-Output $authResult.CreateAuthorizationHeader()
    Write-Output "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
}

Function ConvertTo-Table
{
[cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)][string] $SplitField,
        [Parameter(Mandatory=$true)][string] $TieField,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][object] $InputObject,
        [Parameter(Mandatory=$true)][string] $Delimiter
    )
    $outputs = @()
    Write-Verbose "`$InputObject: $($InputObject.Gettype())"
    foreach ($field in $InputObject)
    {
        Write-Verbose "`$field: $field"
        $title1 = $field.$TieField
        Write-Verbose "`$title1: $title1"
        $title2 = $field.$SplitField.Split($Delimiter)
        Write-Verbose "`$title2: $title2"
        foreach ($title in $title2)
        {
            $line = New-Object -TypeName psobject
            $line | Add-Member -MemberType NoteProperty -Name $TieField -Value $title1
            $line | Add-Member -MemberType NoteProperty -Name $SplitField -Value $title
            $outputs += $line
            Write-Verbose $line
        }
    }
    #Write-Output ($outputs)
    #return $outputs
}

Function Get-AdObjectCustom
{
[cmdletbinding()]
    param(
    # Use parameter sets to select one of the many search parameters
    [Parameter(Mandatory=$true, Position=0)] [Alias("Domain","DomainFQDN")] [string] $Server,
    [Parameter(Mandatory=$true, Position=1)] [string] $LDAPFilter,
    [Parameter(Position=2)] [string] $Properties = "sAMAccountName,mail",
    [Parameter(Mandatory=$false)] [switch] $ConnectLDAP
    )

    if($PSBoundParameters.ContainsKey('ConnectLDAP'))
    {
        $LDAPServerEndpoint = "LDAP"
    }
    else {
        $LDAPServerEndpoint = "GC"
    }

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    #Bind to GC instead of the LDAP server to search across enterprise
    $searcher.SearchRoot = "$($LDAPServerEndpoint)://$Server"

    $searcher.Filter = $LDAPFilter
    #Default search scope is Subtree
    # $searcher.SearchScope.ToString()
    $object = ($searcher.FindAll()).Path

    $results = @()
    foreach($obj in $object)
    {
        $result = New-Object -TypeName psobject
        $objectProperties = [adsi]$obj
        #$output = @{}
        if($Properties -eq "*")
        {
            $Properties = ($objectProperties| Get-Member | where {$_.MemberType -eq "Property"}).Name -join ","
        }

        ForEach($Property in $Properties.Split(","))
        {
            Add-Member -InputObject $result -MemberType NoteProperty -Name $Property -Value $objectProperties.$Property.ToString()
            #$output[$Property]= $objectProperties.$Property.ToString()
        }
        $results += $result
        Remove-Variable result
    }
    Write-Output $results
}

Function Resolve-ServerNames
{
    <#
        .SYNOPSIS
          Look up the IP addresses of a list of server names.

        .DESCRIPTION
          Input can be either be a seed file passed on to the InputFile parameter or a string containing server names in conjunction with the Delimiter parameter

        .PARAMETER ServersList
            A list of server names using any delmiters of your choice

        .PARAMETER Demiliter
            The delimiter that ServersList must be split with

        .PARAMETER InputFile
            The file that contains the servernames. One servername per line.

        .OUTPUTS
          Custom object with servername and corresponding IP addrresses. Pipe to Convertto-CSV or other cmdlets as desired for file output

        .NOTES
          Version:        1.0
          Author:         Navneet Thillaisthanam
          Creation Date:  22 Feb 2017
          Purpose/Change: Initial script development

        .EXAMPLE
          Resolve-ServerNames -ServerNames "String:containing:server:names" -Delimiter ": - servername delimiter in the string"

        .EXAMPLE
          Resolve-ServerNames -InputFile "<input filename>"

    #>

    [cmdletbinding(DefaultParameterSetName='CLIInput')]
    param(
        [Parameter(ParameterSetName='File',Mandatory=$true)][string] $InputFile,
        [Parameter(ParameterSetName='CLIInput',Mandatory=$true)][string] $ServerNames,
        [Parameter(ParameterSetName='CLIInput',Mandatory=$false)][Alias('Separator')][string] $Delimiter = ";"
    )

    $initialErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    #Servers list seed file. Must be one server per line
    if($PSCmdlet.ParameterSetName -eq "File")
    {
        $serversList = Get-Content -Encoding Ascii -Path $InputFile
    }
    else
    {
        Write-Verbose $ServerNames
        $serversList = $ServerNames.Split($Delimiter)
        Write-Verbose $Delimiter
        Write-Verbose $ServersList
    }

    Write-Verbose  "Finished reading servers list. Beginning iterating through each one for IP Address."
    $result = @()

    foreach ($server in $serversList)
    {

        try{
            $ipAdd = [System.Net.Dns]::GetHostAddresses($server).IPAddressToString
            $finalIpList = $ipAdd -join ";" #concatenating the ip address object to a list. In most cases only one IP address will be returned and you will not need this but this is just error checking. :)
            $finalOutput = New-Object -TypeName psobject
            $finalOutput | Add-Member -Type NoteProperty -Name Hostname -Value $server
            $finalOutput | Add-Member -Type NoteProperty -Name AddressList -Value $finalIpList
        }
        catch
        {
            $finalOutput = New-Object -TypeName psobject
            $finalOutput | Add-Member -Type NoteProperty -Name Hostname -Value $server
            $finalOutput | Add-Member -Type NoteProperty -Name AddressList -Value "Error in resolving server name"
            continue
        }
        finally
        {
            $result += $finalOutput
        }
    }
    Write-Output $result
    $ErrorActionPreference = $initialErrorActionPreference

}

Function New-Base64EncryptionKey
{
    <#
        .SYNOPSIS
          Generate new keys of specified key length (bits).

        .DESCRIPTION
          The only parameter is the key length in bits

        .PARAMETER KeySize
            The key size in bits. Defaults to 256 bit keys.

        .OUTPUTS
          Base64 encoded key

        .NOTES
          Version:        1.0
          Author:         Navneet Thillaisthanam
          Creation Date:  22 Aug 2017
          Purpose/Change: Initial script development

        .EXAMPLE
          New-Base64EncryptionKeys -KeySize <int Length>

    #>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$false)][Alias("KeyLength")][int] $KeySize = 256
    )

    $key = New-Object Byte[] ($KeySize/8)
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    $rng.GetBytes($key)
    Write-Output ([System.Convert]::ToBase64String($key))
}

Function Merge-ISCFiles
{
    <#
        .SYNOPSIS
          Merges multiple ISC files into one file.

        .DESCRIPTION
          Merges a list of ISC files into one ICS for easier import to Gmail or other calendar application.

        .PARAMETER Fileslist
            The list of .ics files to merge

        .OUTPUTS
          A merged .ics file in the same directory

        .NOTES
          Version:        1.0
          Author:         Navneet Thillaisthanam
          Creation Date:  10 Jan 2018
          Purpose/Change: Initial script development

        .EXAMPLE
          Merge-ISCFiles -FileNames file1.ics,file2.ics
          Merge-ISCFiles -FileNames @(file1.ics,file2.ics)

    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$false)][Alias("ICSFiles")][array] $FileNames,
        [Parameter(Mandatory=$false, ValueFromPipeline=$false)][Alias("OutFile")][string]$OutputFileName = "events.ics"
    )

    $CURRENT_DIRECTORY = (Get-Location).Path
    $outFileName = $CURRENT_DIRECTORY + "\" + $OutputFileName

    $fileHeader = @()
    $fileFooter = @()
    $vEvents = @()
    $filesToMerge = $FileNames.Split(",");
    foreach ($file in $filesToMerge)
    {
        $fileLines = (Get-Content -Raw -Path ($CURRENT_DIRECTORY + "\" + $file)).Split("`n");
        $eventBeginning = $fileLines.IndexOf("BEGIN:VEVENT")
        $eventEnding = $fileLines.IndexOf("END:VEVENT")
        if($filesToMerge.IndexOf($file) -eq 0)
        {
            $fileHeader = $fileLines[0..($eventBeginning-1)]
            $fileFooter = $fileLines[($eventEnding+1)..$fileLines.Length]
        }

        $vEvents += $fileLines[$eventBeginning..$eventEnding]
    }

    $finalEventFileLines = $fileHeader+$vEvents+$fileFooter

    $finalEventFileLines | Out-File -FilePath $outFileName
}

Function Prompt
{
    Write-Host ("PS " + $(Get-Location | Split-Path -Leaf) +">") -nonewline -foregroundcolor White
    return " "
}

Function Start-MongoD
{
    <#
        The minimalistic config file must exist and MondoDB must be installed for this function to work.
        File: location C:\MongoDB\config\minimalistic.conf
        storage:
            dbPath: "C:\\MongoDB\\data\\db"

        systemLog:
            logAppend: true
            destination: file
            path: "C:\\MongoDB\\log\\mongod.log"

        storage:
            journal:
                enabled: true

        net:
            bindIp: 127.0.0.1
            port: 27017

        setParameter:
            enableLocalhostAuthBypass: false
    #>
    [cmdletbinding()]
    param
    (
        #[Parameter(Mandatory=$false)][string] $ConfigFile = "C:\MongoDB\config\minimalistic.conf",
        [Parameter(Mandatory=$false)][string] $JobName = "MongoD"
    )
    #Write-Verbose "Configuration set to: $ConfigFIle"
    Write-Verbose "JobName: $JobName"
    Start-Job -ScriptBlock {mongod --config "C:\MongoDB\config\minimalistic.conf"} -Name $JobName
}

Function Stop-MongoD
{
    [cmdletbinding()]
    param
    (
        # Parameter help description
        [Parameter(Mandatory=$false)] [string] $JobName = "MongoD"
    )
    Stop-Job -Name $JobName
    Remove-Job -Name $JobName
}

Function Get-RedirectChain
{
[cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)] [Alias("DomainName","Domain")] [string] $Url
    )

    $body = '{"urls":["' + $Url +'"],"userAgent":"browser","userName":"","passWord":"","headerName":"","headerValue":"","strictSSL":true,"canonicalDomain":false,"additionalSubdomains":["www"],"followRedirect":true,"throttleRequests":100,"escapeCharacters":false}'

    $headers = @{
        "Pragma"="no-cache"
        "Cache-Control"="no-cache"
        "Access-Control-Request-Method"="POST"
        "Access-Control-Request-Headers" = "content-type"
        "Accept"="application/json, text/plain, */*"
        "User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
        "Origin"="https://httpstatus.io"
        "Sec-Fetch-Site"="cross-site"
        "Sec-Fetch-Mode"="cors"
        "Sec-Fetch-Dest"="empty"
        "Referer"="https://httpstatus.io/"
        "Accept-Encoding"="gzip, deflate, br"
        "Accept-Language"="en-US,en;q=0.9"
        }

    return (Invoke-RestMethod -Method POST -ContentType "application/json`;charset=UTF-8" -UseBasicParsing -Uri "https://httpstatus-backend-production.herokuapp.com/api" -Headers $headers -Body $body)

}
