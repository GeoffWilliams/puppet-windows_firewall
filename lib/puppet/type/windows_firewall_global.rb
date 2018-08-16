require 'puppet/parameter/boolean'

Puppet::Type.newtype(:windows_firewall_global) do
  @doc = "Manage windows global firewall settings"

  # you can't "ensure" a rule group - you can only enable or disable it this is a different
  # concept to puppet view of existence so removed for clarity

  newparam(:name) do
    desc "Not used (reference only)"
    isnamevar
  end

  newproperty(:strongcrlcheck) do
    desc "Strong CRL check"
  end

  newproperty(:saidletimemin) do
    desc "SA idle time in minutes"
  end

  newproperty(:defaultexemptions) do
    desc "default exemptions"
  end

  newproperty(:ipsecthroughnat) do
    desc "IPSec through NAT"
  end

  newproperty(:authzusergrp) do
    desc "Authz user group"
  end

  newproperty(:authzcomputergrp) do
    desc "Authz computer group"
  end

  newproperty(:authzusergrptransport) do
    desc "Authz user group transport"
  end

  newproperty(:authzcomputergrptransport) do
    desc "Authz computer transport"
  end

  newproperty(:statefulftp) do
    desc "Stateful FTP"
  end

  newproperty(:statefulpptp) do
    desc "Stateful PPTP"
  end

  newproperty(:keylifetime) do
    desc "Key lifetime"
  end

  newproperty(:secmethods) do
    desc "Sec methods"
  end

  newproperty(:forcedh) do
    desc "Force DH"
  end

  # Categories:
  newproperty(:boottimerulecategory) do
    desc "Boot time rule category"
  end

  newproperty(:firewallrulecategory) do
    desc "Firewall rule category"
  end

  newproperty(:stealthrulecategory) do
    desc "Stealth rule category"
  end

  newproperty(:consecrulecategory) do
    desc "con sec rule category"
  end


  # C:\vagrant>netsh advfirewall show global

  # Global Settings:
  #            ----------------------------------------------------------------------
  #            IPsec:
  #     StrongCRLCheck                        0:Disabled
  # SAIdleTimeMin                         5min
  # DefaultExemptions                     NeighborDiscovery,DHCP
  # IPsecThroughNAT                       Never
  # AuthzUserGrp                          None
  # AuthzComputerGrp                      None
  # AuthzUserGrpTransport                 None
  # AuthzComputerGrpTransport             None
  #
  # StatefulFTP                           Disable
  # StatefulPPTP                          Disable
  #
  # Main Mode:
  #          KeyLifetime                           480min,0sess
  # SecMethods                            DHGroup2-AES128-SHA1,DHGroup2-3DES-SHA1
  # ForceDH                               No
  #
  # Categories:
  #     BootTimeRuleCategory                  Windows Firewall
  # FirewallRuleCategory                  Windows Firewall
  # StealthRuleCategory                   Windows Firewall
  # ConSecRuleCategory                    Windows Firewall
  #
  # Ok.

end