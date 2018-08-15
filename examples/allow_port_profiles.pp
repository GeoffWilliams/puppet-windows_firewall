# @PDQTest
windows_firewall { "Puppet - Open a port in specific profiles":
  direction => "in",
  action    => "allow",
  protocol  => "tcp",
  profiles  => ["private", "domain"],
  localport => "666",
}