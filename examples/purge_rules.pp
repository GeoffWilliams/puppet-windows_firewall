resources { "windows_firewall":
  purge => true,
}

windows_firewall { "puppet - allow all":
  ensure    => present,
  direction => "in",
  action    => "allow",
  protocol  => "tcp",
  localport => "any",
}