#@PDQTest
windows_firewall { "puppet - allow icmp echo":
  ensure        => present,
  direction     => "in",
  action        => "allow",
  protocol      => "icmpv4",
  protocol_type => "8",
  protocol_code => "any",
}