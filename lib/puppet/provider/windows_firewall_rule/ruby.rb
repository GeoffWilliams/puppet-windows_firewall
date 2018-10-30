require 'puppet_x'
require 'puppet_x/windows_firewall'

Puppet::Type.type(:windows_firewall_rule).provide(:windows_firewall_rule, :parent => Puppet::Provider) do
  confine :osfamily => :windows
  mk_resource_methods
  desc "Windows Firewall"


  def self.prefetch(resources)
    instances.each do |prov|
      if resource = resources[prov.name]
        resource.provider = prov
      end
    end
  end
  
  def exists?
    @property_hash[:ensure] == :present
  end

  # all work done in `flush()` method
  def create()
  end

  # all work done in `flush()` method
  def destroy()
  end

  def self.instances
    PuppetX::WindowsFirewall.rules.collect { |hash| new(hash) }
  end

  def flush
    # @property_hash contains the `IS` values (thanks Gary!)... For new rules there is no `IS`, there is only the
    # `SHOULD`. The setter methods from `mk_resource_methods` (or manually created) won't be called either. You have
    # to inspect @resource instead

    # we are flushing an existing resource to either update it or ensure=>absent it
    # therefore, delete this rule now and create a new one if needed
    if @property_hash[:ensure] == :present
      PuppetX::WindowsFirewall.delete_rule @resource[:name]
    end

    if @resource[:ensure] == :present
      PuppetX::WindowsFirewall.create_rule @resource
    end
  end

end
