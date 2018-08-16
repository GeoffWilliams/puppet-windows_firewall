require 'puppet_x'
require 'puppet_x/windows_firewall'

Puppet::Type.type(:windows_firewall_group).provide(:windows_firewall_group, :parent => Puppet::Provider) do
  confine :osfamily => :windows
  mk_resource_methods
  desc "Windows Firewall group"

  commands :cmd => "netsh"

  def self.prefetch(resources)
    instances.each do |prov|
      if resource = resources[prov.name]
        resource.provider = prov
      end
    end
  end


  # def initialize(value={})
  #   super(value)
  #   @property_flush = {}
  # end


  # firewall groups always exist we can only enable/disable them
  def exists?
    #@property_hash[:ensure] == :present
    true
  end

  # all work done in `flush()` method
  def create()
  end

  # all work done in `flush()` method
  def destroy()
  end


  def self.instances
    PuppetX::WindowsFirewall.groups(command(:cmd)).collect { |hash| new(hash) }
  end
    #==== begin
    #
    # rules = rules.select {|e| e.has_key? :grouping}
    #
    # rules = rules.map { |e|
    #   { e[:grouping] => e[:enabled] }
    # }
    #
    # x = {}
    # rules.each { |e|
    #   puts e.values[0]
    #   value = (x.fetch(e.keys[0], "yes") && e.values[0] == "yes") ? "yes" : "no"
    #   x[e.keys[0]] = value
    # }
    #
    # z = x.map { |k,v|
    #   {:name => k, :enabled => v}
    # }
    #
    # # ==== end
    #


  def flush
    # @property_hash contains the `IS` values (thanks Gary!)... For new rules there is no `IS`, there is only the
    # `SHOULD`. The setter methods from `mk_resource_methods` (or manually created) won't be called either. You have
    # to inspect @resource instead

    # we are flushing an existing resource to either update it or ensure=>absent it
    # therefore, delete this rule now and create a new one if needed
    if @property_hash[:ensure] == :present
      Puppet.notice("(windows_firewall) deleting rule '#{@resource[:name]}'")
      cmd = "#{command(:cmd)} advfirewall firewall delete rule name=\"#{@resource[:name]}\""
      output = execute(cmd).to_s
    end

    if @resource[:ensure] == :present
      Puppet.notice("(windows_firewall) adding rule '#{@resource[:name]}'")
      args = []
      @resource.properties.reject { |property|
        [:ensure, :protocol_type, :protocol_code].include?(property.name)
      }.each { |property|
        # netsh uses `profiles` when listing but the setter argument for cli is `profile`, all
        # other setter/getter names are symmetrical
        property_name = (property.name == :profiles)? "profile" : property.name.to_s

        # flatten any arrays to comma deliminted lists (usually for `profile`)
        property_value = (property.value.instance_of?(Array)) ? property.value.join(",") : property.value

        # protocol can optionally specify type and code, other properties are set very simply
        args <<
            if property_name == "protocol" && @resource[:protocol_type] && resource[:protocol_code]
              "protocol=\"#{property_value}:#{@resource[:protocol_type]},#{@resource[:protocol_code]}\""
            else
              "#{property_name}=\"#{property_value}\""
            end
      }
      cmd = "#{command(:cmd)} advfirewall firewall add rule name=\"#{@resource[:name]}\" #{args.join(' ')}"
      output = execute(cmd).to_s
      Puppet.debug("...#{output}")
    end
  end

end
