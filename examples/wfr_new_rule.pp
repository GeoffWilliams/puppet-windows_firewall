# @PDQTest
windows_firewall_rule { "puppet - rule":
  ensure    => present,
  localport => 9999,
  direction => "in",
  action    => "allow",
  protocol  => "tcp",
}