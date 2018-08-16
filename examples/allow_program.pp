#@PDQTest
windows_firewall { "puppet - allow messenger":
  ensure    => present,
  direction => "in",
  action    => "allow",
  program   => "C:\\programfiles\\messenger\\msnmsgr.exe",
}