#@PDQTestWin
windows_firewall_rule { "puppet - allow ports 1000-2000":
  ensure     => present,
  direction  => "inbound",
  action     => "allow",
  protocol   => "tcp",
  local_port => "1000-2000",
}

windows_firewall_rule { "puppet - allow port rpc":
  ensure     => present,
  direction  => "inbound",
  action     => "allow",
  protocol   => "tcp",
  local_port => "RPC",
}

windows_firewall_rule { "puppet - allow port rpcemap":
  ensure     => present,
  direction  => "inbound",
  action     => "allow",
  protocol   => "tcp",
  local_port => "RPCEPMap",
}

windows_firewall_rule { "puppet - allow port iphttps - in":
  ensure     => present,
  direction  => "inbound",
  action     => "allow",
  protocol   => "tcp",
  local_port => "IPHTTPSIn",
}

windows_firewall_rule { "puppet - allow port iphttps - out":
  ensure      => present,
  direction   => "outbound",
  action      => "allow",
  protocol    => "tcp",
  remote_port => "IPHTTPSOut",
}