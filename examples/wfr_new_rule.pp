# @PDQTestWin

# basic firewall rule
windows_firewall_rule { "puppet - rule":
  ensure     => present,
  local_port => 9999,
  direction  => "inbound",
  action     => "allow",
  protocol   => "tcp",
}

# program
windows_firewall_rule { "puppet - allow messenger":
  ensure    => present,
  direction => "inbound",
  action    => "allow",
  program   => "C:\\programfiles\\messenger\\msnmsgr.exe",
}

# service
windows_firewall_rule { "puppet - allow lmhosts":
  ensure    => present,
  direction => "inbound",
  action    => "allow",
  service   => "lmhosts",
}

# port range
windows_firewall_rule { "puppet - allow ports 1000-2000":
  ensure     => present,
  direction  => "inbound",
  action     => "allow",
  protocol   => "tcp",
  local_port => "1000-2000",
}

# rpc
windows_firewall_rule { "puppet - allow port rpc":
  ensure     => present,
  direction  => "inbound",
  action     => "allow",
  protocol   => "tcp",
  local_port => "RPC",
}

# rcpemap
windows_firewall_rule { "puppet - allow port rpcemap":
  ensure     => present,
  direction  => "inbound",
  action     => "allow",
  protocol   => "tcp",
  local_port => "RPCEPMap",
}

# inbound port
windows_firewall_rule { "puppet - allow port iphttps - in":
  ensure     => present,
  direction  => "inbound",
  action     => "allow",
  protocol   => "tcp",
  local_port => "IPHTTPSIn",
}

# outbound port
windows_firewall_rule { "puppet - allow port iphttps - out":
  ensure      => present,
  direction   => "outbound",
  action      => "allow",
  protocol    => "tcp",
  remote_port => "IPHTTPSOut",
}

# port in specific profiles
windows_firewall_rule { "puppet - open port in specific profiles":
  ensure         => present,
  direction      => "inbound",
  action         => "allow",
  protocol       => "tcp",
  profile        => ["private", "domain"],
  local_port     => 666,
  remote_port    => 6661,
  local_address  => "192.168.1.1",
  remote_address => "192.168.1.2",
  interface_type => ["wireless", "wired"],
}

# multiple ports
windows_firewall_rule { "puppet - multiple ports":
  direction      => "inbound",
  action         => "allow",
  protocol       => "tcp",
  local_port     => "443,80,4243,5000-5010",
  remote_address => "any",
  remote_port    => "444,81,4244,6000-6010"
}

# numeric protocol (ICMP)
windows_firewall_rule { "puppet - test numeric protocol IGMP":
  direction   => 'inbound',
  action      => 'allow',
  protocol    => '2',
  program     => 'System',
  description => 'Core Networking - Internet Group Management Protocol (IGMP-In)',
}

# ICMP single type
windows_firewall_rule { "puppet - allow icmp 1":
  ensure    => present,
  direction => "inbound",
  action    => "allow",
  protocol  => "icmpv4",
  icmp_type => "1",
}

# ICMP multiple types
windows_firewall_rule { "puppet - allow icmp 2":
  ensure    => present,
  direction => "inbound",
  action    => "allow",
  protocol  => "icmpv4",
  icmp_type => "2:1",
}

# ICMP (all)
windows_firewall_rule { "puppet - allow icmp 3":
  ensure    => present,
  direction => "inbound",
  action    => "allow",
  protocol  => "icmpv4",
  icmp_type => "any",
}

# multiple local & remote addresses
windows_firewall_rule { "puppet - multiple remote and local addresses":
  ensure         => present,
  direction      => "inbound",
  action         => "allow",
  protocol       => "tcp",
  profile        => ["private", "domain"],
  local_port     => 7777,
  remote_port    => 7777,
  local_address  => sort("192.168.1.1,10.10.10.10"),
  remote_address => sort("192.168.1.2,192.168.2.11"),
}