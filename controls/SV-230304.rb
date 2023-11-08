control 'SV-230304' do
  title "RHEL 8 must prevent code from being executed on file systems that are
used with removable media."
  desc  "The \"noexec\" mount option causes the system not to execute binary
files. This option must be used for mounting any file system not containing
approved binary files, as they may be incompatible. Executing files from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access."
  desc  'rationale', ''
  desc  'check', "
    Verify file systems that are used for removable media are mounted with the
\"noexec\" option with the following command:

    $ sudo more /etc/fstab

    UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat
noauto,owner,ro,nosuid,nodev,noexec 0 0

    If a file system found in \"/etc/fstab\" refers to removable media and it
does not have the \"noexec\" option set, this is a finding.
  "
  desc 'fix', "Configure the \"/etc/fstab\" to use the \"noexec\" option on
file systems that are associated with removable media."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230304'
  tag rid: 'SV-230304r627750_rule'
  tag stig_id: 'RHEL-08-010610'
  tag fix_id: 'F-32948r567659_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  file_systems = etc_fstab.params

  if !file_systems.nil? && !file_systems.empty?
    file_systems.each do |file_sys_line|
      if !input('non_removable_media_fs').include?(file_sys_line['mount_point'])
        describe "The mount point #{file_sys_line['mount_point']}" do
          subject { file_sys_line['mount_options'] }
          it { should include 'noexec' }
        end
      else
        describe "File system \"#{file_sys_line['mount_point']}\" does not correspond to removable media." do
          subject { input('non_removable_media_fs').include?(file_sys_line['mount_point']) }
          it { should eq true }
        end
      end
    end
  else
    describe 'No file systems were found.' do
      subject { file_systems.nil? }
      it { should eq true }
    end
  end
end
