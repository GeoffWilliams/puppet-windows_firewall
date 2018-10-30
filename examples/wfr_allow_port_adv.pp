# @PDQTestWin
windows_firewall_rule { "puppet - open port in specific profiles":
  ensure         => present,
  direction      => "inbound",
  action         => "allow",
  protocol       => "tcp",
  profile        => ["private", "domain"],
  local_port     => 666,
  remote_port    => 6661,
  local_address  => "192.168.1.1",
  remote_address => "192.168.1.2",
  interface_type => ["wireless", "wired"],
}