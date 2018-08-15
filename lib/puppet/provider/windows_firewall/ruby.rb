Puppet::Type.type(:windows_firewall).provide(:windows_firewall, :parent => Puppet::Provider) do
  confine :osfamily => :windows
  mk_resource_methods
  desc "Windows Firewall"

  commands :cmd => "netsh"

  def self.prefetch(resources)
    instances.each do |prov|
      if resource = resources[prov.name]
        resource.provider = prov
      end
    end
  end


  def initialize(value={})
    super(value)
    @property_flush = {}
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


  # create a normalised key name by:
  # 1. lowercasing input
  # 2. converting spaces to underscores
  # 3. convert to symbol
  def self.key_name(input)
    input.downcase.gsub(/\s/, "_").to_sym
  end

  # Each rule is se
  def self.parse_rule(input)
    rule = {}
    input.split("\n").reject { |line|
      line =~ /---/
    }.each { |line|
      # split at most twice - there will be more then one colon if we have path to a program here
      # eg:
      #   Program: C:\foo.exe
      line_split = line.split(":", 2)

      if line_split.size == 2
        key = key_name(line_split[0].strip)

        # downcase all values for comparison purposes
        value = line_split[1].strip.downcase

        #rule[key_name(key)] = value

        # puppet blows up if the namevar isn't called `name` despite what you choose to expose this
        # to the user as in the type definition...
        safe_key = (key == :rule_name) ? :name : key

        case safe_key
        when :profiles
          munged_value = value.split(",")
        else
          munged_value = value
        end

        rule[safe_key] = munged_value
      end
    }

    # if we see the rule then it must exist...
    rule[:ensure] = :present

    Puppet.debug "Parsed windows firewall rule: #{rule}"
    rule
  end

  def self.instances
    rules = []

    # each rule is separated by a double newline, we can that parse each one individually
    execute([command(:cmd), "advfirewall", "firewall", "show", "rule", "all", "verbose"]).to_s.split("\n\n").each do |line|
      rules << parse_rule(line)
    end

    rules.collect { |hash| new(hash) }
  end

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
        property.to_s == "ensure"
      }.each { |property|
        property_name = property.to_s
        args << "#{property_name}=\"#{@resource[property_name.to_sym]}\""
      }
      cmd = "#{command(:cmd)} advfirewall firewall add rule name=\"#{@resource[:name]}\" #{args.join(' ')}"
      output = execute(cmd).to_s
      Puppet.notice("...#{output}")
    end
  end

end
