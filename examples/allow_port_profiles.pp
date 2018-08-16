# @PDQTest
windows_firewall { "puppet - open port in specific profiles":
  ensure    => present,
  direction => "in",
  action    => "allow",
  protocol  => "tcp",
  profiles  => ["private", "domain"],
  localport => "666",
}