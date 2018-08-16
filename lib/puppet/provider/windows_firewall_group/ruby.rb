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
    last_key = nil
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
        last_key = safe_key

      else
        # probably looking at the protocol type/code - we only support ONE of these per rule
        # since the CLI only lets us set one (although the GUI has no limit). Because of looping
        # this will return the _last_ item in the list
        if last_key == :protocol
          line_split = line.strip.split(/\s+/, 2)
          if line_split.size == 2
            rule[:protocol_type] = line_split[0].downcase
            rule[:protocol_code] = line_split[1].downcase
          end
        end
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
    begin
      execute([command(:cmd), "advfirewall", "firewall", "show", "rule", "all", "verbose"]).to_s.split("\n\n").each do |line|
        rules << parse_rule(line)
      end
    rescue Puppet::ExecutionFailure => e
      # if there are no rules (maybe someone purged them...) then the command will fail with
      # the message below. In this case we can ignore the error and just zero the list of rules
      # parsed
      if e.message =~ /No rules match the specified criteria/
        rules = []
      end
    end

    # to find the status of a rule group we must pick through each member of the hash
    # and re-group them by `grouping`

    #==== begin

    rules = rules.select {|e| e.has_key? :grouping}

    rules = rules.map { |e|
      { e[:grouping] => e[:enabled] }
    }

    x = {}
    rules.each { |e|
      puts e.values[0]
      value = (x.fetch(e.keys[0], "yes") && e.values[0] == "yes") ? "yes" : "no"
      x[e.keys[0]] = value
    }

    z = x.map { |k,v|
      {:name => k, :enabled => v}
    }

    # ==== end


    z.collect { |hash| new(hash) }
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
