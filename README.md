[![Build Status](https://travis-ci.org/GeoffWilliams/puppet-windows_firewall.svg?branch=master)](https://travis-ci.org/GeoffWilliams/puppet-windows_firewall)
# windows_firewall

#### Table of Contents

1. [Description](#description)
1. [Usage - Configuration options and additional functionality](#usage)
1. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
1. [Limitations - OS compatibility, etc.](#limitations)
1. [Development - Guide for contributing to the module](#development)

## Description

Manage the windows firewall with Puppet (netsh).

## Features
* Create/edit/delete individual firewall rules (`windows_firewall_rule`)
* Enable/disable firewall groups (`windows_firewall_group`)
* Adjust global settings (`windows_firewall_global`)
* Adjust per-profile settings (`windows_firewall_profile`)

## Usage

### windows_firewall_rule
Manage individual firewall rules

#### Listing firewall rules

The type and provider is able to enumerate the firewall rules existing on the system:

```shell
C:\>puppet resource windows_firewall_rule
windows_firewall_rule { 'branchcache content retrieval (http-in)':
  ensure         => 'present',
  action         => 'allow',
  direction      => 'in',
  edge_traversal => 'no',
  enabled        => 'no',
  grouping       => 'branchcache - content retrieval (uses http)',
  localip        => 'any',
  localport      => '80',
  profiles       => ['domain', 'private', 'public'],
  protocol       => 'tcp',
  remoteip       => 'any',
  remoteport     => 'any',
}
windows_firewall_rule { 'branchcache content retrieval (http-out)':
  ensure         => 'present',
  action         => 'allow',
  direction      => 'out',
  ... 
```

You can limit output to a single rule by passing its name as an argument, eg:

```shell
C:\>puppet resource windows_firewall_rule 'puppet - rule'
```

#### Ensuring a rule

The basic syntax for ensuring rules is: 

```puppet
windows_firewall_rule { "name of rule":
  ensure => present,
  ...
}
```

If a rule with the same name but different properties already exists, it will be deleted and re-created to
ensure it is defined correctly. To delete a rule, set `ensure => absent`.

#### Managing ICMP
```puppet
windows_firewall_rule { "puppet - all icmpv4":
  ensure    => present,
  direction => "in",
  action    => "allow",
  protocol  => "icmpv4",
}
```

You can also create a rule that only allows a specific ICMP type and code:
```puppet
windows_firewall_rule { "puppet - allow icmp echo":
  ensure        => present,
  direction     => "in",
  action        => "allow",
  protocol      => "icmpv4",
  protocol_type => "8",
  protocol_code => "any",
}
```
You need to create one rule for each `protocol_type` `protocol_code` combination (see limitations).

#### Managing Ports

Use the `localport` and `remoteport` properties to set the ports a rule refers to. You can set an
individual port or a range.

```puppet
windows_firewall_rule { "puppet - allow ports 1000-2000":
  ensure    => present,
  direction => "in",
  action    => "allow",
  protocol  => "tcp",
  localport => "1000-2000",
}
```

#### Managing Programs

```puppet
windows_firewall_rule { "puppet - allow messenger":
  ensure    => present,
  direction => "in",
  action    => "allow",
  program   => "C:\\programfiles\\messenger\\msnmsgr.exe",
}
```

#### Creating rules in specific profiles
```puppet
windows_firewall_rule { "puppet - open port in specific profiles":
  ensure    => present,
  direction => "in",
  action    => "allow",
  protocol  => "tcp",
  profiles  => ["private", "domain"],
  localport => "666",
}
```

#### Purging rules

You can choose to purge unmanaged rules from the system (be careful! - this will remove _any_ rule that is not manged by
Puppet including those created by Windows itself):

```puppet
resources { "windows_firewall_rule":
  purge => true,
}

windows_firewall_rule { "puppet - allow all":
  ensure    => present,
  direction => "in",
  action    => "allow",
  protocol  => "tcp",
  localport => "any",
}
```

### windows_firewall_group
Enable/Disable named groups of firewall rules

#### Enabling a group of rules

```puppet
windows_firewall_group { "file and printer sharing":
  enabled => "yes",
}
```

#### Disabling a group of rules

```puppet
windows_firewall_group { "file and printer sharing":
  enabled => "no",
}
```

### windows_firewall_global
Global settings always exist (there is no `ensure`). 

#### Displaying settings
You can use `puppet resource windows_firewall_global` to check what Puppet thinks the current values are:

```shell
C:\vagrant>puppet resource windows_firewall_global
windows_firewall_global { 'global':
  authzcomputergrp          => 'none',
  authzcomputergrptransport => 'none',
  authzusergrp              => 'none',
  authzusergrptransport     => 'none',
  boottimerulecategory      => 'windows firewall',
  consecrulecategory        => 'windows firewall',
  defaultexemptions         => ['dhcp', 'neighbordiscovery'],
  firewallrulecategory      => 'windows firewall',
  forcedh                   => 'yes',
  ipsecthroughnat           => 'serverbehindnat',
  keylifetime               => '485min,0sess',
  saidletimemin             => '6',
  secmethods                => 'dhgroup2:aes128-sha1,dhgroup2:3des-sha1',
  statefulftp               => 'disable',
  statefulpptp              => 'disable',
  stealthrulecategory       => 'windows firewall',
  strongcrlcheck            => '1',
}
```

Note: some properties are read-only.

#### Managing global settings

A single resource with an arbitrary title should be used to manage the desired settings, eg:

```puppet
windows_firewall_global { 'global':
  authzcomputergrp          => 'none',
  authzusergrp              => 'none',
  defaultexemptions         => ['neighbordiscovery','dhcp'],
  forcedh                   => 'yes',
  ipsecthroughnat           => 'serverbehindnat',
  keylifetime               => '485min,0sess',
  saidletimemin             => '6',
  secmethods                => 'dhgroup2:aes128-sha1,dhgroup2:3des-sha1',
  statefulftp               => 'disable',
  statefulpptp              => 'disable',
  strongcrlcheck            => '1',
}
```

### windows_firewall_profile

There are three firewall profiles that the module supports:

* private
* domain
* public

Depending on the network the node is connected to, one of these profiles will be active. They map to
three Puppet resources which cannot be _ensured_:

* `Windows_firewall_profile[private]`
* `Windows_firewall_profile[domain]`
* `Windows_firewall_profile[public]`

#### Displaying settings

Use `puppet resource windows_firewall_profile` to see what puppet thinks the settings are:

```shell
C:\vagrant>puppet resource windows_firewall_profile
windows_firewall_profile { 'domain':
  filename                   => '%systemroot%\system32\logfiles\firewall\pfirewa
ll.log',
  firewallpolicy             => 'blockinbound,allowoutbound',
  inboundusernotification    => 'disable',
  localconsecrules           => 'n/a (gpo-store only)',
  localfirewallrules         => 'n/a (gpo-store only)',
  logallowedconnections      => 'disable',
  logdroppedconnections      => 'disable',
  maxfilesize                => '4096',
  remotemanagement           => 'disable',
  state                      => 'on',
  unicastresponsetomulticast => 'enable',
}
windows_firewall_profile { 'private':
  filename                   => '%systemroot%\system32\logfiles\firewall\pfirewa
ll.log',
  firewallpolicy             => 'blockinbound,allowoutbound',
  inboundusernotification    => 'disable',
  localconsecrules           => 'n/a (gpo-store only)',
  ...
```

Note that some settings are read-only

#### Turning profile firewalls on/off

Use the `state` property on some or all of the profiles:

```puppet
windows_firewall_profile { 'private':
  state => 'off',
}

windows_firewall_profile { ['public', 'domain']:
  state => 'on',
}
```

#### Managing settings

Manage the settings for each of the three profiles you want to manage. To set 
everything to the same value, use an array for `title`:

```puppet
windows_firewall_profile { ['domain', 'private']:
  inboundusernotification    => 'enable',
  firewallpolicy             => 'allowinbound,allowoutbound',
  logallowedconnections      => 'enable',
  logdroppedconnections      => 'enable',
  maxfilesize                => '4000',
  remotemanagement           => 'enable',
  state                      => 'on',
  unicastresponsetomulticast => 'disable',
}
```

## Troubleshooting
* Try running puppet in debug mode (`--debug`)
* To reset firewall to default rules: `netsh advfirewall reset`
* Print all firewall rules `netsh advfirewall firewall show rule all verbose`
* Print firewall global settings `netsh advfirewall show global`
* Print firewall profile settings `netsh advfirewall show allprofiles`
* Use the "Windows Firewall with advanced security" program if you would like a GUI to view/edit firewall status
* Help on how to [create firewall rules](doc/netsh_firewall_rule.txt) (obtained from: `netsh advfirewall firewall set rule`)
* Help on how to [change global settings](doc/netsh_global_settings.txt) (obtained from: `netsh advfirewall set global`)
* Help on how to [change profile settings](doc/netsh_profile_settings.txt) (obtained from: `netsh advfirewall set private`)

## Reference
...todo

## Limitations
* Requires the `netsh advfirewall` command
* Rule names are lowercased for comparison purposes
* Some global firewall settings present differently in `puppet resource windows_firewall_globals` to 
  `netsh advfirewall show global` - this is because `netsh` command uses different values to set/get settings
* Property names match those used by netsh so there is inconsistency in the equivalent puppet
  property names (some names are run-together, others separated by underscores). This is
  deliberate and makes the module code much simpler as names map exactly
* It is not possible to edit the `grouping` for rules (netsh does not support this)
* It is not possible to edit the `localfirewallrules` or `localconsecrules` for profiles (this needs
  corresponding group policy)
* The Windows Advanced Firewall GUI allows multiple individual types to be set for ICMPv4 and ICMPv6
  however this does not seem to be possible through the `netsh` CLI. Therefore you must create 
  individual rules if for each type you wish to allow if you want to limit a rule in this way, eg:
  
  ```puppet
  windows_firewall { "allow icmp echo":
    ensure        => present,
    protocol      => "icmpv4",
    protocol_type => "8",
    protocol_code => "any",
    action        => "allow",
  }

  windows_firewall_rule { "allow icmp time exceeded":
    ensure        => present,
    protocol      => "icmpv4",
    protocol_type => "11",
    protocol_code => "any",
    action        => "allow",
  }
  ```   

## Development

PRs accepted :)

## Testing
Manual testing for now 🤮 ... PDQTest needs to support windows