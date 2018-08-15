#@PDQTest
windows_firewall { "Puppet - Open a range of ports":
  direction => "in",
  action    => "allow",
  protocol  => "tcp",
  localport => "1000-2000",
}