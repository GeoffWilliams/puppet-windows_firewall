param(
    [String] $Target,
    [String] $Name,
    [String] $DisplayName,
    [String] $Description,
    $Enabled,
    $Action,
    [String] $Protocol,
    $IcmpType,
    $Profile,
    [String] $Program,
    $Direction,
    [String] $LocalAddress,
    [String] $RemoteAddress,
    [String] $ProtocolType,
    [Int]    $ProtocolCode,
    [String]    $LocalPort,
    [String]    $RemotePort,
    $EdgeTraversalPolicy,
    $InterfaceType
)

Import-Module NetSecurity


# =====

# Lookup select firewall rules using powershell. This is needed to resolve names that are missing
# from netsh output
function Get-PSFirewallRules {
    param($filter)

    $rules = New-Object System.Collections.ArrayList
    Show-NetFirewallRule | Where-Object { $_.DisplayName  -in $filter} | ForEach-Object {

        $af = (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_)[0]
        $appf = (Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $_)[0]
        $pf = (Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_)[0]
        $if = (Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $_)[0]

        $rules.Add(@{
            Name = $_.Name
            DisplayName = $_.DisplayName
            Description = $_.Description
            Enabled = $_.Enabled.toString()
            Action = $_.Action.toString()
            Direction = $_.Direction.toString()
            EdgeTraversalPolicy = $_.EdgeTraversalPolicy.toString()
            Profile = $_.Profile.toString()
            DisplayGroup = $_.DisplayGroup
            # Address Filter
            LocalAddress = $af.LocalAddress.toString()
            RemoteAddress = $af.RemoteAddress.toString()
            # Port Filter
            LocalPort = $pf.LocalPort
            RemotePort = $pf.RemotePort
            Protocol = $pf.Protocol
            IcmpType = $pf.IcmpType
            # Application Filter
            Program = $appf.Program
            # Interface Filter
            InterfaceType = $if.InterfaceType.toString()
        }) > $null
    }
    return $rules
}

# resolve references like
# *  @{Microsoft.Todos_1.41.12842.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.Todos/Resources/app_name_ms_todo}
# to
# * Microsoft To-Do
# by resolving in registry
function Get-ResolveRefs {
    param($refs)
    $resolved = @()
    $searchPath = 'HKCR:\Local Settings\MrtCache'
    # http://powershelleverydayfaq.blogspot.com/2012/06/how-to-query-hkeyclassesroot.html
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

    $RegKey = Get-ChildItem $searchPath -rec -ea SilentlyContinue

    foreach ($ref in $refs) {
        $found = $false


        #$RegKey | foreach {
        :inner
        foreach ($r in $RegKey) {
            #$CurrentKey = (Get-ItemProperty -Path $_.PsPath)
            $CurrentKey = (Get-ItemProperty -Path $r.PsPath)
            if ($currentKey.$ref -ne $null) {
                $found = $currentKey.$ref
                break inner
            }
        }
        if (! $found) {
            throw "could not resolve $($ref) in registry under $($searchPath)"
        } else {
            $resolved += $found
        }
    }
    return $resolved
}

# Local/Remote Address comes back as either a range or /32 address depending
# how it was created. Both of these mean the same (AFAICT) and both of these
# are coalesced to a regular IP address when using pure powershell...
function Get-NormalizedIpAddressRange {
    param ($rawIpAddress)


    # any /32 can just be removed...

    if ($rawIpAddress -match "/32") {
        $fixedIpAddress = $rawIpAddress -replace "/32", ""
    } else {
        # see if we are are a zero-length range, eg `192.168.1.1-192.168.1.1`
        $ipAddressSplit = $rawIpAddress -split "-"
        if ($ipAddressSplit.length -eq 2 -and ($ipAddressSplit[0] -eq $ipAddressSplit[1])) {
            $fixedIpAddress = $ipAddressSplit[0]
        }
    }
    $ipAddress = if ($fixedIpAddress) {$fixedIpAddress} else {$rawIpAddress}
    return $ipAddress
}

# Convert netsh value to powershell value
function Get-NormalizedValue {
    param(
        $keyName,
        $rawValue
    )

    # Local/Remote Address comes back as either a range or /32 address depending
    # how it was created. Both of these mean the same (AFAICT) and both of these
    # are coalesced to a regular IP address when using pure powershell...
    $normalize = @{
        "Enabled" = { param($x); if ($x -eq "Yes") {"True"} else {"False"}}
        "Direction" = { param($x) ; if ($x -eq "In") {"Inbound"} elseif ($x -eq "Out") {"Outbound"}}
        "EdgeTraversalPolicy" = { param($x);  if ($x -eq "No") { "Block"} elseif ($x -eq "Yes") {"Allow"} elseif ($x -eq "Defer to application") { "DeferToApp" } elseif ($x -eq "Defer to user") { "DeferToUser" }}
        "InterfaceType" = {param($x); $x -replace "RAS", "RemoteAccess" -replace "LAN", "Wired" }
        "Program" = { param($x); $x -replace '\\', '\\' }
        "RemoteAddress" = { param($x); Get-NormalizedIpAddressRange $x}
        "LocalAddress" = { param($x); Get-NormalizedIpAddressRange $x}
    }

    if ($normalize.containsKey($keyName)) {
        $value = $normalize[$keyName].invoke($rawValue)
    } else {
        $value = $rawValue
    }
    return $value

}

# Normalize ICMP type from netsh to match that from powershell
function Get-NormalizedIcmpType {
    param(
        $type,
        $code
    )
    # Output from netsh will match one of:
    # * Any Any
    # * x Any
    # * x x
    # Output from powershell will match one of:
    # * Any
    # * x
    # * x:x

    if ($type -eq "Any") {
        $icmpType = "Any"
    } elseif ($code -eq "Any") {
        $icmpType = $type
    } else {
        $icmpType = "$($type):$($code)"
    }

    return $icmpType
}

# convert netsh keyname to powershell keyname
function Get-NormalizedKey {
    param($keyName)
    $keyNames = @{
        "InterfaceTypes" = "InterfaceType"
        "Description"= "Description"
        "Direction" = "Direction"
        "Edge traversal" = "EdgeTraversalPolicy"
        "Profiles" =  "Profile"
        "RemotePort" = "RemotePort"
        "Grouping" = "DisplayGroup"
        "Action" = "Action"
        "LocalIP" = "LocalAddress"
        "Rule Name" = "Name"
        "Protocol" = "Protocol"
        "LocalPort" = "LocalPort"
        "Service" = "Unused_Service"
        "Security" = "Unused_Security"
        "RemoteIP" = "RemoteAddress"
        "Program" =  "Program"
        "Enabled" = "Enabled"
        "Rule Source" = "Unused_RuleSource"
    }
    $resolved = $keyNames[$keyName]
    if (! $resolved) {
        throw "Unable to resolve `netsh` key '$($keyName)' to a valid key"
    }
    return $resolved
}

# Parse a chunk of netsh output. Netsh uses a double blank line between output to new record
function Get-ParseChunk {
    param([String] $chunk)
    $rule = @{}
    $icmpType = $null
    $validParse = $false

    ForEach ($line in $($chunk -split "`r`n")) {
        if ($line -notmatch "---" -and $line -notmatch '^\s*$' -and $line -notmatch 'No rules match') {
            $validParse = $true
            # split at most twice - there will be more then one colon if we have path to a program here
            # eg:
            #   Program: C:\foo.exe
            $lineSplit = $line -split(":",2)


            if ($lineSplit.length -eq 2) {
                $key = Get-NormalizedKey $lineSplit[0].Trim()
                $value = Get-NormalizedValue $key $lineSplit[1].Trim()

                $rule[$key] = $value
            } else {
                # probably looking at the protocol type/code - we only support ONE of these per rule
                # since the CLI only lets us set one (although the GUI has no limit). Because of looping
                # this will return the _last_ item in the list. This lets us gracefully skip over the
                # header row "Type Code"
                $lineSplit = $line.Trim() -split("\s+")
                if ($lineSplit.length -eq 2) {
                    $icmpType = Get-NormalizedIcmpType $lineSplit[0] $lineSplit[1]
                }
            }
        }
    }

    if ($validParse) {
        # There is no _different_ displayname for rules from netsh but its
        # mandatory so copy it
        $rule["DisplayName"] = $rule["Name"]
        $rule["IcmpType"] = $icmpType
    }
    return $rule
}


# =====

function show {
    # step 1 - list all rules using `netsh` - the easiest and fastest way to resolve
    # 99% of values
    $netshOutput = netsh advfirewall firewall show rule all verbose | out-string
    $missingNames = New-Object System.Collections.ArrayList
    $rules = New-Object System.Collections.ArrayList
    $s0 = $(get-date)

    ForEach ($chunk in $($netshOutput -split "`r`n`r`n"))
    {
        $rule = Get-ParseChunk $chunk
        if ($rule.get_count() -gt 0) {

            if ($rule["Name"].contains("@")) {
                # additional lookup using powershell required to fully resolve one
                # or more rules
                $missingNames.Add($rule["Name"]) > $null
            } else {
                $rules.Add($rule) > $null
            }
        }
    }
    $s1 = $(get-date)

    if ($missingNames.length) {
        # we have unresolved names that require a secondary powershell lookup to resolve

        # First translate the resource-reef names to their real names
        $resolved = Get-ResolveRefs $missingNames

        $s2 = $(get-date)

        # then use the powershell API on a very limited subset to find them
        $rules = $rules + (Get-PSFirewallRules $resolved)
        $s3 = $(get-date)
    }

    convertto-json $rules

}

function delete{
    write-host "Deleting $($Name)..."

    # rules containing square brackets need to be escaped or nothing will match
    # eg: "Ruby interpreter (CUI) 2.4.3p205 [x64-mingw32]"
    $Name = $name.replace(']', '`]').replace('[', '`[')

    # Depending how rule was parsed (netsh vs ps) `$Name` will contain either
    # `DisplayName` or rule ID. Therefore, delete by Displayname first, if this
    # fails, fallback to `Name` and if this also fails, error the script
    # (`-ErrorAction Stop`)
    if (Get-NetFirewallRule -DisplayName $name -erroraction 'silentlycontinue') {
        remove-netfirewallrule -DisplayName $Name
    } elseif (Get-NetFirewallRule -Name $name -erroraction 'silentlycontinue') {
        remove-netfirewallrule -Name $Name -ErrorAction Stop
    } else {
        throw "We were told to delete firewall rule '$($name)' but it does not exist"
    }

}


function create {

    $params = @{
        Name = $Name;
        Enabled = $Enabled;
        DisplayName = $DisplayName;
        Description = $Description;
        Action = $Action;
    }

    #
    # general optional params
    #
    if ($Direction) {
        $params.Add("Direction", $Direction)
    }
    if ($EdgeTraversalPolicy) {
        $params.Add("EdgeTraversalPolicy", $EdgeTraversalPolicy)
    }
    if ($Profile) {
        $params.Add("Profile", $Profile)
    }

    #
    # port filter
    #
    if ($Protocol) {
        $params.Add("Protocol", $Protocol)
    }
    if ($ProtocolType) {
        $params.Add("ProtocolType", $ProtocolType)
    }
    if ($ProtocolCode) {
        $params.Add("ProtocolCode", $ProtocolCode)
    }
    if ($IcmpType) {
        $params.Add("IcmpType", $IcmpType)
    }
    if ($LocalPort) {
        $params.Add("LocalPort", $LocalPort)
    }
    if ($RemotePort) {
        $params.Add("RemotePort", $RemotePort)
    }

    #
    # Program filter
    #
    if ($Program) {
        $params.Add("Program", $Program)
    }
    
    #
    # Interface filter
    #
    if ($InterfaceType) {
        $params.Add("InterfaceType", $InterfaceType)
    }

    # Host filter
    if ($LocalAddress) {
        $params.Add("LocalAddress", $LocalAddress)
    }
    if ($RemoteAddress) {
        $params.Add("remoteAddress", $RemoteAddress)
    }

    New-NetFirewallRule @params -ErrorAction Stop
}

switch ($Target) {
    "show" {
        show
    }
    "delete" {
        delete
    }
    "create" {
        create
    }
    default {
        throw "invalid target: $($Target)"
    }
}
