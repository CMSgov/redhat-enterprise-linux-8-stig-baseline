# frozen_string_literal: true

control 'SV-244530' do
  title "RHEL 8 must prevent files with the setuid and setgid bit set from
being executed on the /boot/efi directory."
  desc 'The "nosuid" mount option causes the system not to execute
"setuid" and "setgid" files with owner privileges. This option must be used
for mounting any file system not containing approved "setuid" and "setguid"
files. Executing files from untrusted file systems increases the opportunity
for unprivileged users to attain unauthorized administrative access.'
  desc 'check', %q(For systems that use BIOS, this is Not Applicable.

Verify the /boot/efi directory is mounted with the "nosuid" option with the following command:

$ sudo mount | grep '\s/boot/efi\s'

/dev/sda1 on /boot/efi type vfat (rw,nosuid,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=ascii,shortname=winnt,errors=remount-ro)

If the /boot/efi file system does not have the "nosuid" option set, this is a finding.)
  desc 'fix', 'Configure the "/etc/fstab" to use the "nosuid" option on
the /boot/efi directory.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-244530'
  tag rid: 'SV-244530r809336_rule'
  tag stig_id: 'RHEL-08-010572'
  tag fix_id: 'F-47762r743838_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  elsif file('/sys/firmware/efi').exist?
    describe mount('/boot/efi') do
      it { should be_mounted }
      its('options') { should include 'nosuid' }
    end
  else
    impact 0.0
    describe 'System running BIOS' do
      skip 'The System is running BIOS, this control is Not Applicable.'
    end
  end
end
