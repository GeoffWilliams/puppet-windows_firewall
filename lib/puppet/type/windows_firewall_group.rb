require 'puppet/parameter/boolean'

Puppet::Type.newtype(:windows_firewall_group) do
  @doc = "Enable/Disable windows firewall group"

  # you can't "ensure" a rule group - you can only enable or disable it this is a different
  # concept to puppet view of existence so removed for clarity

  newparam(:name) do
    desc "Name of the rule group to enable/disable"
    isnamevar
    munge do |value|
      value.downcase
    end
  end

  newproperty(:enabled) do
    desc "Whether the rule group is enabled (Yes or No)"
    newvalues(:yes, :no)
  end

end