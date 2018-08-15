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

## Usage

### Listing firewall rules

The type and provider is able to enumerate the firewall rules existing on the system:

```shell
C:\>puppet resource windows_firewall
windows_firewall { 'branchcache content retrieval (http-in)':
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
windows_firewall { 'branchcache content retrieval (http-out)':
  ensure         => 'present',
  action         => 'allow',
  direction      => 'out',
  ... 
```

You can limit output to a single rule by passing its name as an argument, eg:

```shell
C:\>puppet resource windows_firewall 'my cool rule'
```

### Ensuring a rule

The basic syntax for ensuring rules is: 

```puppet
windows_firewall { "my cool rule":
  ensure => present,
  ...
}
```

If a rule with the same name but different properties already exists, it will be deleted and re-created to
ensure it is defined correctly. To delete a rule, set `ensure => absent`.

### Managing ICMP
```puppet
windows_firewall { "Puppet - All ICMP V4":
  direction => "in",
  action    => "allow",
  protocol  => "icmpv4",
}
```

### Managing Ports

```puppet
windows_firewall { "Puppet - Open a range of ports":
  direction => "in",
  action    => "allow",
  protocol  => "tcp",
  localport => "1000-2000",
}
```

### Managing Programs

```puppet
windows_firewall { "Puppet - Allow Messenger":
  direction => "in",
  action    => "allow",
  program   => "C:\\programfiles\\messenger\\msnmsgr.exe",
}
```

### Creating rules in specific profiles
```shy
windows_firewall { "Puppet - Open a port in specific profiles":
  direction => "in",
  action    => "allow",
  protocol  => "tcp",
  profiles  => ["private", "domain"],
  localport => "666",
}
```

## Reference
[generated documentation](https://rawgit.com/GeoffWilliams/puppet-windows_firewall/master/doc/index.html).

Reference documentation is generated directly from source code using [puppet-strings](https://github.com/puppetlabs/puppet-strings).  You may regenerate the documentation by running:

```shell
bundle exec puppet strings
```

## Limitations
* Requires the `netsh advfirewall` command
* The Windows Advanced Firewall GUI allows multiple individual types to be set for ICMPv4 and ICMPv6
  however this does not seem to be possible through the `netsh` CLI. Therefore you must create 
  individual rules if for each type you wish to allow if you want to limit a rule in this way, eg:
  
  ```puppet
  windows_firewall { "Allow ICMP echo":
    ensure        => present,
    protocol      => "ICMPv4",
    protocol_type => "8",
    protocol_code => "any",
    action        => "allow",
  }

  windows_firewall { "Allow ICMP time exceeded":
    ensure        => present,
    protocol      => "ICMPv4",
    protocol_type => "11",
    protocol_code => "any",
    action        => "allow",
  }
  ```   

## Development

PRs accepted :)

## Testing
Manual testing for now 🤮 ... PDQTest needs to support windows