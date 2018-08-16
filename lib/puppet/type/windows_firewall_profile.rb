require 'puppet/parameter/boolean'

Puppet::Type.newtype(:windows_firewall_profile) do
  @doc = "Enable/Disable windows firewall profile"

  # you can't "ensure" a profile - 3 exist at all times, we just let user set their policies

  newparam(:name) do
    desc "Name of the profile to work on"
    isnamevar
    munge do |value|
      value.downcase
    end
  end

  newproperty(:state) do
    desc "State of this firewall profile"
    newvalues(:on, :off)
  end

  newproperty(:firewall_policy) do
    desc "State of this firewall profile"
  end

  newproperty(:localfirewallrules) do
    desc "???"
  end

  newproperty(:localconsecrules) do
    desc "???"
  end

  newproperty(:inboundusernotification) do
    desc "???"
  end

  newproperty(:remotemanagement) do
    desc "allow remote management"
  end

  newproperty(:unicastresponsetomulticast) do
    desc "respond in unicast to multicast"
  end

  newproperty(:logallowedconnections) do
    desc "log allowed connections"
  end

  newproperty(:logdroppedconnections) do
    desc "log dropped connections"
  end

  newproperty(:maxfilesize) do
    desc "maximum size of log file"
  end

end