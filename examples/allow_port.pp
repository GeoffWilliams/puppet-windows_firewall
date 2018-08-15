#@PDQTest
windows_firewall { "Puppet - Open SQL Server Port 1433":
  direction => "in",
  action    => "allow",
  protocol  => "tcp",
  localport => 1433,
}