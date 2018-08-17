require 'puppet_x'
require 'puppet_x/windows_firewall'

Puppet::Type.type(:windows_firewall_global).provide(:windows_firewall_global, :parent => Puppet::Provider) do
  confine :osfamily => :windows
  mk_resource_methods
  desc "Windows Firewall global settings"

  commands :cmd => "netsh"

  def self.prefetch(resources)
    instances.each do |prov|
      if resource = resources[prov.name]
        resource.provider = prov
      end
    end
  end

  # global settings always exist
  def exists?
    true
  end

  # all work done in `flush()` method
  def create()
  end

  # all work done in `flush()` method
  def destroy()
  end


  def self.instances
    PuppetX::WindowsFirewall.globals(command(:cmd)).collect { |hash| new(hash) }
  end

  # Usage: set global statefulftp|statefulpptp enable|disable|notconfigured
  #       set global ipsec (parameter) (value)
  #       set global mainmode (parameter) (value) | notconfigured
  #
  # IPsec Parameters:
  #
  #       strongcrlcheck    - Configures how CRL checking is enforced.
  #                           0: Disable CRL checking (default)
  #                           1: Fail if cert is revoked
  #                           2: Fail on any error
  #                           notconfigured: Returns the value to its not
  #                           configured state.
  #       saidletimemin     - Configures the security association idle time in
  #                           minutes.
  #                         - Usage: 5-60|notconfigured (default=5)
  #       defaultexemptions - Configures the default IPsec exemptions. Default is
  #                           to exempt IPv6 neighbordiscovery protocol and
  #                           DHCP from IPsec.
  #                         - Usage: none|neighbordiscovery|icmp|dhcp|notconfigured
  #       ipsecthroughnat   - Configures when security associations can be
  #                           established with a computer behind a network
  #                           address translator.
  #                         - Usage: never|serverbehindnat|
  #                                  serverandclientbehindnat|
  #                                  notconfigured(default=never)
  #       authzcomputergrp  - Configures the computers that are authorized to
  #                           establish tunnel mode connections.
  #                         - Usage: none|<SDDL string>|notconfigured
  #       authzusergrp      - Configures the users that are authorized to establish
  #                           tunnel mode connections.
  #                         - Usage: none|<SDDL string>|notconfigured
  #
  # Main Mode Parameters:
  #
  #       mmkeylifetime     - Sets main mode key lifetime in minutes
  #                           or sessions, or both.
  #                         - Usage: <num>min,<num>sess
  #                           minlifetime: <1> min,
  #                           maxlifetime: <2880> min
  #                           minsessions: <0> sessions,
  #                           maxsessions: <2,147,483,647> sessions
  #       mmsecmethods      - configures the main mode list of proposals
  #                         - Usage:
  #                           keyexch:enc-integrity,keyexch:enc-integrity[,...]|defa
  # ult
  #                         - keyexch=dhgroup1|dhgroup2|dhgroup14|dhgroup24|
  #                           ecdhp256|ecdhp384
  #                         - enc=3des|des|aes128|aes192|aes256
  #                         - integrity=md5|sha1|sha256|sha384
  #       mmforcedh         - configures the option to use DH to secure key exchange
  # .
  #                         - Usage:
  #                           yes|no (default=no)
  #
  #
  # Remarks:
  #
  #       - Configures global settings, including advanced IPsec options.
  #       - The use of DES, MD5 and DHGroup1 is not recommended. These
  #         cryptographic algorithms are provided for backward compatibility
  #         only.
  #       - The mmsecmethods keyword default sets the policy to:
  #         dhgroup2-aes128-sha1,dhgroup2-3des-sha1
  #
  # Examples:
  #
  #       Disable CRL checking:
  #       netsh advfirewall set global ipsec strongcrlcheck 0
  #
  #       Turn on the Firewall support for stateful FTP:
  #       netsh advfirewall set global statefulftp enable
  #
  #       Set global main mode proposals to the default value:
  #       netsh advfirewall set global mainmode mmsecmethods default
  #
  #       Set global main mode proposals to a customer list:
  #       netsh advfirewall set global mainmode mmsecmethods
  #       dhgroup1:des-md5,dhgroup1:3des-sha1

  def flush
    # @property_hash contains the `IS` values (thanks Gary!)... For new rules there is no `IS`, there is only the
    # `SHOULD`. The setter methods from `mk_resource_methods` (or manually created) won't be called either. You have
    # to inspect @resource instead
    @resource.properties.reject { |property|
      [ :ensure,
        :authzusergrptransport,
        :authzcomputergrptransport,
        :boottimerulecategory,
        :firewallrulecategory,
        :stealthrulecategory,
        :consecrulecategory
      ].include?(property.name)
    }.each { |property|
      property_name = PuppetX::WindowsFirewall.global_argument_lookup(property.name)
      property_value = property.value.instance_of?(Array) ? property.value.join(",") : property.value


      # global settings are space delimited and we must run one command per setting
      arg = "#{property_name} \"#{property_value}\""
      # Puppet.notice("(windows_firewall) global settings '#{@resource[:name]}' enabled: #{@resource[:enabled]}")
      cmd = "#{command(:cmd)} advfirewall set global #{arg}"
      output = execute(cmd).to_s
      Puppet.debug("...#{output}")

    }
  end

end
