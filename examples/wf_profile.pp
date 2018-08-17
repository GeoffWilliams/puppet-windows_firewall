# @PDQTest
windows_firewall_profile { 'private':
  state                      => 'off',
}

windows_firewall_profile { 'domain':
  inboundusernotification    => 'disable',
  firewallpolicy             => 'allowinbound,allowoutbound',
  logallowedconnections      => 'disable',
  logdroppedconnections      => 'disable',
  maxfilesize                => '4000',
  remotemanagement           => 'enable',
  state                      => 'on',
  unicastresponsetomulticast => 'disable',
}