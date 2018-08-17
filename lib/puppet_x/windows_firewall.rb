require 'puppet_x'
module PuppetX
  module WindowsFirewall

    # convert a puppet type key name to the argument to use for `netsh` command
    def self.global_argument_lookup(key)
      {
          :keylifetime       => "mainmode mmkeylifetime",
          :secmethods        => "mainmode mmsecmethods",
          :forcedh           => "mainmode mmforcedh",
          :strongcrlcheck    => "ipsec strongcrlcheck",
          :saidletimemin     => "ipsec saidletimemin",
          :defaultexemptions => "ipsec defaultexemptions",
          :ipsecthroughnat   => "ipsec ipsecthroughnat",
          :authzcomputergrp  => "ipsec authzcomputergrp",
          :authzusergrp      => "ipsec authzusergrp",
      }.fetch(key, key.to_s)
    end

    # create a normalised key name by:
    # 1. lowercasing input
    # 2. converting spaces to underscores
    # 3. convert to symbol
    def self.key_name(input)
      input.downcase.gsub(/\s/, "_").to_sym
    end

    def self.rules(cmd)
      rules = []
      # each rule is separated by a double newline, we can that parse each one individually
      begin
        Puppet::Util::Execution.execute([cmd, "advfirewall", "firewall", "show", "rule", "all", "verbose"]).to_s.split("\n\n").each do |line|
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

      rules
    end

    def self.groups(cmd)
      # get all individual firewall rules, then create a new hash containing the overall group
      # status for each group of rules
      groups = {}
      rules(cmd).select { |e|
        # we are only interested in firewall rules that provide grouping information so bounce
        # anything that doesn't have it from the list
        e.has_key? :grouping
      }.each { |e|
        # extract the group information for each rule, use the value of :enabled to
        # build up an overall status for the whole group
        groups[e[:grouping]] = (groups.fetch(e[:grouping], "yes") && e[:enabled] == "yes") ? "yes" : "no"
      }

      # convert into puppet's preferred hash format which is an array of hashes
      # with each hash representing a distinct resource
      transformed = groups.map { |k,v|
        {:name => k, :enabled => v}
      }

      transformed
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


    # Each rule is se
    def self.parse_profile(input)
      profile = {}
      first_line = true
      profile_name = "__error__"
      input.split("\n").reject { |line|
        line =~ /---/ || line =~ /^\s*$/
      }.each { |line|
        if first_line
          # take the first word in the line - eg "public profile settings" -> "public"
          profile_name = line.split(" ")[0].downcase
          first_line = false
        else

          # split each line at most twice by first glob of whitespace
          line_split = line.split(/\s+/, 2)

          if line_split.size == 2
            key = key_name(line_split[0].strip)

            # downcase all values for comparison purposes
            value = line_split[1].strip.downcase

            profile[key] = value
          end
        end
      }

      # if we see the rule then it must exist...
      profile[:name] = profile_name

      Puppet.debug "Parsed windows firewall profile: #{profile}"
      profile
    end

    # Each rule is se
    def self.parse_global(input)
      globals = {}
      input.split("\n").reject { |line|
        line =~ /---/ || line =~ /^\s*$/
      }.each { |line|

        # split each line at most twice by first glob of whitespace
        line_split = line.split(/\s+/, 2)

        if line_split.size == 2
          key = key_name(line_split[0].strip)

          # downcase all values for comparison purposes
          value = line_split[1].strip.downcase

          case key
          when :secmethods
            # secmethods are output with a hypen like this:
            #   DHGroup2-AES128-SHA1,DHGroup2-3DES-SHA1
            # but must be input with a colon like this:
            #   DHGroup2:AES128-SHA1,DHGroup2:3DES-SHA1
            safe_value = value.split(",").map { |e|
              e.sub("-", ":")
            }.join(",")
          when :strongcrlcheck
            safe_value = value.split(":")[0]
          when :defaultexemptions
            safe_value = value.split(",").sort
          else
            safe_value = value.gsub(/min/,"")
          end

          globals[key] = safe_value
        end
      }

      globals[:name] = "global"

      Puppet.debug "Parsed windows firewall globals: #{globals}"
      globals
    end

    # parse firewall profiles
    def self.profiles(cmd)
      profiles = []
      # the output of `show allprofiles` contains several blank lines that make parsing somewhat
      # harder so just run it for each of the three profiles to make life easy...
      ["publicprofile", "domainprofile", "privateprofile"].each { |profile|
        profiles <<  parse_profile(Puppet::Util::Execution.execute([cmd, "advfirewall", "show", profile]).to_s)
      }
      profiles
    end


    # parse firewall profiles
    def self.globals(cmd)
      profiles = []
      # the output of `show allprofiles` contains several blank lines that make parsing somewhat
      # harder so just run it for each of the three profiles to make life easy...
      ["publicprofile", "domainprofile", "privateprofile"].each { |profile|
        profiles <<  parse_global(Puppet::Util::Execution.execute([cmd, "advfirewall", "show", "global"]).to_s)
      }
      profiles
    end
  end
end


