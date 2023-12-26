# frozen_string_literal: true

control 'SV-230499' do
  title 'RHEL 8 must disable IEEE 1394 (FireWire) Support.'
  desc 'It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    The IEEE 1394 (FireWire) is a serial bus standard for high-speed real-time
communication. Disabling FireWire protects the system against exploitation of
any flaws in its implementation.'
  desc 'check', 'Verify the operating system disables the ability to load the firewire-core kernel module.

$ sudo grep -r firewire-core /etc/modprobe.d/* | grep "/bin/true"

install firewire-core /bin/true

If the command does not return any output, or the line is commented out, and use of the firewire-core protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the operating system disables the ability to use the firewire-core kernel module.

Check to see if the firewire-core kernel module is disabled with the following command:

$ sudo grep -r firewire-core /etc/modprobe.d/* | grep "blacklist"

blacklist firewire-core

If the command does not return any output or the output is not "blacklist firewire-core", and use of the firewire-core kernel module is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to use the
firewire-core kernel module.

    Add or update the following lines in the file
"/etc/modprobe.d/blacklist.conf":

    install firewire-core /bin/true
    blacklist firewire-core

    Reboot the system for the settings to take effect.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-230499'
  tag rid: 'SV-230499r792924_rule'
  tag stig_id: 'RHEL-08-040026'
  tag fix_id: 'F-33143r568244_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe kernel_module('firewire_core') do
      it { should be_disabled }
      it { should be_blacklisted }
    end
  end
end
