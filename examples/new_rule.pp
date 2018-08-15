# @PDQTest
windows_firewall { "my cool rule":
  ensure => present,
  localport => 9999,
  direction => "in",
  action => "allow",
  protocol => "tcp",
}