require 'spec_helper'
describe 'windows_firewall' do
  context 'with default values for all parameters' do
    it { should contain_class('windows_firewall') }
  end
end
