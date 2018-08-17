require 'puppet/parameter/boolean'

Puppet::Type.newtype(:windows_firewall_global) do
  @doc = "Manage windows global firewall settings"

  # you can't "ensure" a rule group - you can only enable or disable it this is a different
  # concept to puppet view of existence so removed for clarity

  newparam(:name) do
    desc "Not used (reference only)"
    isnamevar
  end




  #       strongcrlcheck    - Configures how CRL checking is enforced.
  #                           0: Disable CRL checking (default)
  #                           1: Fail if cert is revoked
  #                           2: Fail on any error
  #                           notconfigured: Returns the value to its not
  #                           configured state.
  newproperty(:strongcrlcheck) do
    desc "Strong CRL check"
    validate do |value|
      if ! [0,1,2].include? value.to_i
        raise("Invalid value, allowed: 0,1,2")
      end
    end
  end

  #       saidletimemin     - Configures the security association idle time in
  #                           minutes.
  #                         - Usage: 5-60|notconfigured (default=5)
  newproperty(:saidletimemin) do
    desc "SA idle time in minutes"

    validate do |value|
      value = value.to_i
      if ! (value >= 5 && value <= 60)
        raise("Invalid value, allowed: 0,1,2")
      end
    end
  end

  #       defaultexemptions - Configures the default IPsec exemptions. Default is
  #                           to exempt IPv6 neighbordiscovery protocol and
  #                           DHCP from IPsec.
  #                         - Usage: none|neighbordiscovery|icmp|dhcp|notconfigured
  newproperty(:defaultexemptions, :array_matching => :all) do
    desc "default exemptions"
    newvalues(:none, :neighbordiscovery, :icmp, :dhcp, :notconfigured)

    # thanks again Gary! - http://garylarizza.com/blog/2013/11/25/fun-with-providers/
    def insync?(is)
      # incoming `should` is an array of symbols not strings...
      # Element-wise comparison - http://ruby-doc.org/core-2.5.1/Array.html
      (should.map { |e| e.to_s }.sort <=> is.sort) == 0
    end

  end

  #       ipsecthroughnat   - Configures when security associations can be
  #                           established with a computer behind a network
  #                           address translator.
  #                         - Usage: never|serverbehindnat|
  #                                  serverandclientbehindnat|
  #                                  notconfigured(default=never)
  newproperty(:ipsecthroughnat) do
    desc "IPSec through NAT"
    newvalues(:never, :serverbehindnat, :serverandclientbehindnat, :notconfigured)
  end

  #       authzusergrp      - Configures the users that are authorized to establish
  #                           tunnel mode connections.
  #                         - Usage: none|<SDDL string>|notconfigured
  newproperty(:authzusergrp) do
    desc "Authz user group"
  end


  #       authzcomputergrp  - Configures the computers that are authorized to
  #                           establish tunnel mode connections.
  #                         - Usage: none|<SDDL string>|notconfigured
  newproperty(:authzcomputergrp) do
    desc "Authz computer group"
  end

  newproperty(:authzusergrptransport) do
    desc "Authz user group transport"
    validate do |value|
      raise("property is read-only")
    end
  end

  newproperty(:authzcomputergrptransport) do
    desc "Authz computer transport"
    validate do |value|
      raise("property is read-only")
    end
  end

  newproperty(:statefulftp) do
    desc "Stateful FTP"
    newvalues(:enable, :disable, :notconfigured)
  end

  newproperty(:statefulpptp) do
    desc "Stateful PPTP"
    newvalues(:enable, :disable, :notconfigured)
  end

  #       mmkeylifetime     - Sets main mode key lifetime in minutes
  #                           or sessions, or both.
  #                         - Usage: <num>min,<num>sess
  #                           minlifetime: <1> min,
  #                           maxlifetime: <2880> min
  #                           minsessions: <0> sessions,
  #                           maxsessions: <2,147,483,647> sessions
  newproperty(:keylifetime) do
    desc "Key lifetime"
  end

  #       mmsecmethods      - configures the main mode list of proposals
  #                         - Usage:
  #                           keyexch:enc-integrity,keyexch:enc-integrity[,...]|default
  #                         - keyexch=dhgroup1|dhgroup2|dhgroup14|dhgroup24|
  #                           ecdhp256|ecdhp384
  #                         - enc=3des|des|aes128|aes192|aes256
  #                         - integrity=md5|sha1|sha256|sha384
  newproperty(:secmethods) do
    desc "Sec methods"
  end

  #       mmforcedh         - configures the option to use DH to secure key exchange.
  #                         - Usage:
  #                           yes|no (default=no)
  newproperty(:forcedh) do
    desc "Force DH"
    newvalues(:yes, :no)
  end

  # Categories:
  newproperty(:boottimerulecategory) do
    desc "Boot time rule category"
    validate do |value|
      raise("property is read-only")
    end
  end

  newproperty(:firewallrulecategory) do
    desc "Firewall rule category"
    validate do |value|
      raise("property is read-only")
    end
  end

  newproperty(:stealthrulecategory) do
    desc "Stealth rule category"
    validate do |value|
      raise("property is read-only")
    end
  end

  newproperty(:consecrulecategory) do
    desc "con sec rule category"
    validate do |value|
      raise("property is read-only")
    end
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