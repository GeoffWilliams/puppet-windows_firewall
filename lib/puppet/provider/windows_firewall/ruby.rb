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

  def create()
    puts @property_hash
    #netsh advfirewall firewall add rule name="Open SQL Server Port 1433" dir=in action=allow protocol=TCP localport=1433
    #execute([command(:cmd), "advfirewall", "firewall", "delete", "rule", "name=\"#{@resource[:name]}\""])


    puts "CREATE!"
    #
    # # sysctl -w
    # execute([command(:cmd), "-w", "#{@resource[:name]}=#{@resource[:value]}"])
    #
    # remove_definitions()
    #
    # # save setting to 80-puppet-*.conf file
    # File.open(self.get_filename(@resource[:name]), 'w') { |file| file.write(to_file(@resource[:name], @resource[:value])) }
    #
    # if @resource[:autoflush_ipv4] and @resource[:name] =~ /ipv4/
    #   Puppet.notice("Flusihing IPV4 rules")
    #   execute([command(:cmd), "-w", "net.ipv4.route.flush=1"])
    # end
    #
    # if @resource[:autoflush_ipv6] and @resource[:name] =~ /ipv6/
    #   Puppet.notice("Flusihing IPV6 rules")
    #   execute([command(:cmd), "-w", "net.ipv6.route.flush=1"])
    # end
    #
    # # Disabled due to https://github.com/GeoffWilliams/puppet-sysctl/issues/1
    # #rebuild_initrd
  end

  def destroy()
    # delete the existing rule...
    puts "destroy"
    execute([command(:cmd), "advfirewall", "firewall", "delete", "rule", "name=#{@resource[:name]}"])

    # ...and mark all properties as flushed
    @property_hash = {}
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
      line_split = line.split(":")

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
    execute([command(:cmd), "advfirewall", "firewall", "show", "rule", "all"]).to_s.split("\n\n").each do |line|
      rules << parse_rule(line)
    end

    rules.collect { |hash| new(hash) }




    # # for a systemctl setting to be "managed" we need an entry in a file and also
    # # a matching directive
    #
    # active = {}
    # sysctl_values = {}
    #
    # # corresponding entries from sysctl -a that are managed by puppet
    # execute([command(:cmd), "-a" ]).to_s.split("\n").reject { |line|
    #   line =~ /^\s*$/ or line !~ /=/
    # }.each { |line|
    #   split = line.split('=')
    #   if split.count == 2
    #     name = split[0].strip
    #     value = split[1].strip
    #     sysctl_values[name] = value
    #
    #     file = self.get_filename(name)
    #     if File.exist?(file)
    #       s = File.read(file).split("=")
    #       value_saved =
    #           if s.count == 2
    #             s[1].strip.gsub(/\n/,"")
    #           else
    #             nil
    #           end
    #
    #       active[name] = {:ensure => :present, :value => value, :value_saved => value_saved, :defined_in => [file]}
    #     end
    #   end
    # }
    #
    # # scan every place we are allowed to define entries
    # Dir.glob([
    #              "/run/sysctl.d/*.conf",
    #              "/etc/sysctl.d/*.conf",
    #              "/usr/local/lib/sysctl.d/*.conf",
    #              "/usr/lib/sysctl.d/*.conf",
    #              "/lib/sysctl.d/*.conf",
    #              "/etc/sysctl.conf"
    #          ]
    # ).reject { |file|
    #   # reject our own files. There is a link 99-sysctl.conf -> /etc/sysctl.conf so we are scanning that too
    #   file =~ /#{PUPPET_PREFIX}/
    # }.each { |file|
    #   File.readlines(file).reject {|line|
    #     # skip entirely whitespace or comment lines
    #     line =~ /^(s*|\s*#.*)$/
    #   }.each { |line|
    #     split = line.split("=")
    #     if split.count == 2
    #       key = split[0].strip
    #       value_saved = split[1].strip
    #
    #       # it's possible for same setting to be defined in multiple files - we need to capture this so that all of them
    #       # can be moved out of the way
    #       if active.key?(key)
    #         active[key][:defined_in] << file
    #         active[key][:value_saved] = value_saved
    #       else
    #         active[key] = {:ensure => :present, :value => sysctl_values[key], :value_saved => value_saved, :defined_in => [file]}
    #       end
    #     end
    #
    #   }
    # }
    #
    # active.collect { |k,v|
    #   new({
    #           :name => k,
    #           :ensure => v[:ensure],
    #           :value => v[:value],
    #           :value_saved => v[:value_saved],
    #           :defined_in => v[:defined_in]
    #       })
    # }

  end

  # When does flush fire?
  # 1. When there are changes to a resource that exists
  # 2. When a resource is ensured=>absent
  # It does NOT run when a resource does not yet exist (but `create()` does...)
  def flush
    # @property_hash contains the `IS` values (thanks Gary!)... For new rules there is no `IS`, there is only the
    # `SHOULD`. The setter methods from `mk_resource_methods` (or manually created) won't be called either. You have
    # to inspect @resource instead
    if @resource[:ensure] == :present
      puts ">>>>>>>> commit rule"
      args = []
      @resource.properties.reject { |property|
        property.to_s == "ensure"
      }.each { |property|
        property_name = property.to_s
        args << "#{property_name}=\"#{@resource[property_name.to_sym]}\""
      }

      Puppet.notice("(windows_firewall) adding rule '#{@resource[:name]}'")
      #cmd = [command(:cmd), "advfirewall", "firewall", "add", "rule", "name=\"#{@resource[:name]}\""] + args

      cmd = "#{command(:cmd)} advfirewall firewall add rule name=\"#{@resource[:name]}\" #{args.join(' ')}"
      puts cmd
      output = execute(cmd).to_s
      Puppet.notice("...#{output}")
    end
  end

end
