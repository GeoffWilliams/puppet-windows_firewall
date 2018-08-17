# @PDQTest
windows_firewall_rule { "puppet - rule":
  ensure    => present,
  localport => 1111,
  direction => "in",
  action    => "allow",
  protocol  => "tcp",
}