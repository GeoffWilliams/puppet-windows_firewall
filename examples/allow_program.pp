#@PDQTest
windows_firewall { "Puppet - Allow Messenger":
  direction => "in",
  action    => "allow",
  program   => "C:\\programfiles\\messenger\\msnmsgr.exe",
}