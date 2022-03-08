control 'SV-230305' do
  title "RHEL 8 must prevent files with the setuid and setgid bit set from
being executed on file systems that are used with removable media."
  desc  "The \"nosuid\" mount option causes the system not to execute
\"setuid\" and \"setgid\" files with owner privileges. This option must be used
for mounting any file system not containing approved \"setuid\" and \"setguid\"
files. Executing files from untrusted file systems increases the opportunity
for unprivileged users to attain unauthorized administrative access."
  desc  'rationale', ''
  desc  'check', "
    Verify file systems that are used for removable media are mounted with the
\"nosuid\" option with the following command:

    $ sudo more /etc/fstab

    UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat
noauto,owner,ro,nosuid,nodev,noexec 0 0

    If a file system found in \"/etc/fstab\" refers to removable media and it
does not have the \"nosuid\" option set, this is a finding.
  "
  desc 'fix', "Configure the \"/etc/fstab\" to use the \"nosuid\" option on
file systems that are associated with removable media."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230305'
  tag rid: 'SV-230305r627750_rule'
  tag stig_id: 'RHEL-08-010620'
  tag fix_id: 'F-32949r567662_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  non_removable_media_fs = input('non_removable_media_fs')

  file_systems = etc_fstab.params
  if !file_systems.nil? && !file_systems.empty?
    file_systems.each do |file_sys_line|
      if !non_removable_media_fs.include?(file_sys_line['mount_point'])
        describe "The mount point #{file_sys_line['mount_point']}" do
          subject { file_sys_line['mount_options'] }
          it { should include 'nosuid' }
        end
      else
        describe "File system \"#{file_sys_line['mount_point']}\" does not correspond to removable media." do
          subject { non_removable_media_fs.include?(file_sys_line['mount_point']) }
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
