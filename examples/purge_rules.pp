resources { "windows_firewall_rule":
  purge => true,
}

windows_firewall_rule { "puppet - allow all":
  ensure    => present,
  direction => "in",
  action    => "allow",
  protocol  => "tcp",
  localport => "any",
}