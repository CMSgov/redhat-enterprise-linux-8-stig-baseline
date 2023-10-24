control 'SV-230498' do
  title 'RHEL 8 must disable mounting of cramfs.'
  desc 'It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Removing support for unneeded filesystem types reduces the local attack
surface of the server.

    Compressed ROM/RAM file system (or cramfs) is a read-only file system
designed for simplicity and space-efficiency.  It is mainly used in embedded
and small-footprint systems.'
  desc 'check', 'Verify the operating system disables the ability to load the cramfs kernel module.

$ sudo grep -r cramfs /etc/modprobe.d/* | grep "/bin/true"

install cramfs /bin/true

If the command does not return any output, or the line is commented out, and use of the cramfs protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the operating system disables the ability to use the cramfs kernel module.

Check to see if the cramfs kernel module is disabled with the following command:

$ sudo grep -r cramfs /etc/modprobe.d/* | grep "blacklist"

blacklist cramfs

If the command does not return any output or the output is not "blacklist cramfs", and use of the cramfs kernel module is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to use the cramfs
kernel module.

    Add or update the following lines in the file
"/etc/modprobe.d/blacklist.conf":

    install cramfs /bin/true
    blacklist cramfs

    Reboot the system for the settings to take effect.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-230498'
  tag rid: 'SV-230498r792922_rule'
  tag stig_id: 'RHEL-08-040025'
  tag fix_id: 'F-33142r568241_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe kernel_module('cramfs') do
      it { should be_disabled }
      it { should be_blacklisted }
    end
  end
end
