# @PDQTest
windows_firewall_profile { ['public', 'private', 'domain']:
  state                      => 'on',
}