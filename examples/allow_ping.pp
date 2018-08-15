#@PDQTest
windows_firewall { "Puppet - All ICMP V4":
  direction => "in",
  action    => "allow",
  protocol  => "icmpv4",
}