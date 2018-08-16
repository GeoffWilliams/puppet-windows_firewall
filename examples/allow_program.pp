#@PDQTest
windows_firewall_rule { "puppet - allow messenger":
  ensure    => present,
  direction => "in",
  action    => "allow",
  program   => "C:\\programfiles\\messenger\\msnmsgr.exe",
}