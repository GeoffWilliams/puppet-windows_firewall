# @PDQTest
windows_firewall_profile { 'domain':
  inboundusernotification    => 'disable',
  localconsecrules           => 'n/a (gpo-store only)',
  localfirewallrules         => 'n/a (gpo-store only)',
  logallowedconnections      => 'disable',
  logdroppedconnections      => 'disable',
  maxfilesize                => '4096',
  remotemanagement           => 'disable',
  state                      => 'on',
  unicastresponsetomulticast => 'enable',
}