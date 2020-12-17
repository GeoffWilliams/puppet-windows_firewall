param(
    [String] $Target,
    [String] $Name,
    [String] $DisplayName,
    [String] $Description,
    $Enabled,
    [String] $Protocol,
    [String] $Mode,
    $Profile,
    [String] $LocalAddress,
    [String] $RemoteAddress,
    [String]    $LocalPort,
    [String]    $RemotePort,
    $InterfaceType,
    $Phase1AuthSet,
    $Phase2AuthSet,
    $InboundSecurity,
    $OutboundSecurity
)

Import-Module NetSecurity

function Convert-IpAddressToMaskLength([string] $Address)
{
  if ($Address -like '*/*') {
  $Network=$Address.Split('/')[0]
  $SubnetMask=$Address.Split('/')[1]
  $result = 0; 
  # ensure we have a valid IP address
  [IPAddress] $ip = $SubnetMask;
  $octets = $ip.IPAddressToString.Split('.');
  foreach($octet in $octets)
  {
    while(0 -ne $octet) 
    {
      $octet = ($octet -shl 1) -band [byte]::MaxValue
      $result++; 
    }
  }
  return $Network+'/'+$result;
  }
  else {
      return $Address;
  }   
}

function show {

    $rules = New-Object System.Collections.ArrayList
    Get-NetIPsecRule | ForEach-Object {

        $af = (Get-NetFirewallAddressFilter -AssociatedNetIPsecRule $_)[0]
        $if = (Get-NetFirewallInterfaceTypeFilter -AssociatedNetIPsecRule $_)[0]
        $pf = (Get-NetFirewallPortFilter -AssociatedNetIPsecRule $_)[0]
        
        # TO BE IMPLEMENTED
        #$Phase1AuthSet = (Get-NetIPsecPhase1AuthSet -AssociatedNetIPsecRule $_)[0]
        #$Phase2AuthSet = (Get-NetIPsecPhase2AuthSet -AssociatedNetIPsecRule $_)[0]

        $rules.Add(@{
                Name                = $_.Name
                DisplayName         = $_.DisplayName
                Description         = $_.Description
                Enabled             = $_.Enabled.toString()
                Profile             = $_.Profile.toString()
                DisplayGroup        = $_.DisplayGroup
                Mode                = $_.Mode.toString()
                # Address Filter
                LocalAddress        = if ($af.LocalAddress -is [object]) { ($af.LocalAddress | ForEach-Object {Convert-IpAddressToMaskLength $_}) -join ","  } else { Convert-IpAddressToMaskLength $af.LocalAddress }
                RemoteAddress       = if ($af.RemoteAddress -is [object]) { ($af.RemoteAddress | ForEach-Object {Convert-IpAddressToMaskLength $_}) -join ","  } else { Convert-IpAddressToMaskLength $af.RemoteAddress }
                # Port Filter (Newer powershell versions return a hash)
                LocalPort           = if ($pf.LocalPort -is [object]) { $pf.LocalPort -join "," } else { $pf.LocalPort }
                RemotePort          = if ($pf.RemotePort -is [object]) { $pf.RemotePort -join "," } else { $pf.RemotePort }
                Protocol            = $pf.Protocol
                # Interface Filter
                InterfaceType       = $if.InterfaceType.toString()
                InboundSecurity     = $_.InboundSecurity.toString()
                OutboundSecurity    = $_.OutboundSecurity.toString()
                Phase1AuthSet       = $_.Phase1AuthSet
                Phase2AuthSet       = $_.Phase2AuthSet
            }) > $null
    }

    convertto-json $rules

}

function create {

    $params = @{
        Name        = $Name;
        Enabled     = $Enabled;
        DisplayName = $DisplayName;
        Description = $Description;
    }

    #
    # general optional params
    #

    if ($Profile) {
        $params.Add("Profile", $Profile)
    }

    #
    # port filter
    #
    if ($Protocol) {
        $params.Add("Protocol", $Protocol)
    }
    if ($Mode) {
        $params.Add("Mode", $Mode)
    }

    # `$LocalPort` and `$RemotePort` will always be strings since we were
    # invoked with `powershell -File`, rather then refactor the loader to use
    # `-Command`, just do a simple string split. The firewall GUI will sort any
    # passed port ranges but the PS API does not
    if ($LocalPort) {
        $params.Add("LocalPort", ($LocalPort -split ','))
    }
    if ($RemotePort) {
        $params.Add("RemotePort", ($RemotePort -split ','))
    }

    #
    # Interface filter
    #
    if ($InterfaceType) {
        $params.Add("InterfaceType", $InterfaceType)
    }

    # Host filter
    if ($LocalAddress) {
        $params.Add("LocalAddress", ($LocalAddress -split ','))
    }
    if ($RemoteAddress) {
        $params.Add("remoteAddress", ($RemoteAddress -split ','))
    }
    if ($InboundSecurity) {
        $params.Add("InboundSecurity", $InboundSecurity)
    }
    if ($OutboundSecurity) {
        $params.Add("OutboundSecurity", $OutboundSecurity)
    }
    #PhaseAuthSet is case sensitive
    if ($Phase1AuthSet -eq 'Computerkerberos') {
        $params.Add("Phase1AuthSet", 'ComputerKerberos')
    }
    elseif ($Phase1AuthSet) {
        $params.Add("Phase1AuthSet", $Phase1AuthSet)
    }
    if ($Phase2AuthSet -eq 'Userkerberos') {
        $params.Add("Phase2AuthSet", 'UserKerberos')
    }
    elseif ($Phase2AuthSet) {
        $params.Add("Phase2AuthSet", $Phase2AuthSet)
    }

    #Create PhaseAuthSet if doesn't exist (Exist by default on GUI but not on CORE)
    if ($Phase1AuthSet -eq 'Computerkerberos') {
        if (!(Get-NetIPsecPhase1AuthSet -Name 'ComputerKerberos' -erroraction 'silentlycontinue')) {
            $mkerbauthprop = New-NetIPsecAuthProposal -Machine -Kerberos
            New-NetIPsecPhase1AuthSet -Name 'ComputerKerberos' -DisplayName 'ComputerKerberos' -Proposal $mkerbauthprop
        }
    }
    elseif ($Phase1AuthSet -eq 'Anonymous') {
        if (!(Get-NetIPsecPhase1AuthSet -Name 'Anonymous' -erroraction 'silentlycontinue')) {
            $anonyauthprop = New-NetIPsecAuthProposal -Anonymous
            New-NetIPsecPhase1AuthSet -Name 'Anonymous' -DisplayName 'Anonymous' -Proposal $anonyauthprop
        }
    }
    if ($Phase2AuthSet -eq 'Userkerberos') {
        #Create Phase1AuthSet if doesn't exist (Exist by default on GUI but not on CORE)
        if (!(Get-NetIPsecPhase2AuthSet -Name 'Userkerberos' -erroraction 'silentlycontinue')) {
            $ukerbauthprop = New-NetIPsecAuthProposal -User -Kerberos
            New-NetIPsecPhase2AuthSet -Name 'Userkerberos' -DisplayName 'Userkerberos' -Proposal $ukerbauthprop
        }
    }

    New-NetIPSecRule @params -ErrorAction Stop
}

function delete {
    write-host "Deleting $($Name)..."

    # rules containing square brackets need to be escaped or nothing will match
    # eg: "Ruby interpreter (CUI) 2.4.3p205 [x64-mingw32]"
    $Name = $name.replace(']', '`]').replace('[', '`[')

    # Depending how rule was parsed (netsh vs ps) `$Name` will contain either
    # `DisplayName` or rule ID. Therefore, delete by Displayname first, if this
    # fails, fallback to `Name` and if this also fails, error the script
    # (`-ErrorAction Stop`)
    if (Get-NetIPSecRule -DisplayName $name -erroraction 'silentlycontinue') {
        remove-NetIPSecRule -DisplayName $Name
    }
    elseif (Get-NetIPSecRule -Name $name -erroraction 'silentlycontinue') {
        remove-NetIPSecRule -Name $Name -ErrorAction Stop
    }
    else {
        throw "We were told to delete firewall rule '$($name)' but it does not exist"
    }

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