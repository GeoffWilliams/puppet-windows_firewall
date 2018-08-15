# @PDQTest
windows_firewall { "my cool rule":
  ensure => present,
  localport => 1111,
  direction => "in",
  action => "allow",
  protocol => "tcp",
}