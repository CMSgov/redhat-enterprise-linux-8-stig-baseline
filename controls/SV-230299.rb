control 'SV-230299' do
  title "RHEL 8 must prevent files with the setuid and setgid bit set from
being executed on file systems that contain user home directories."
  desc  "The \"nosuid\" mount option causes the system not to execute
\"setuid\" and \"setgid\" files with owner privileges. This option must be used
for mounting any file system not containing approved \"setuid\" and \"setguid\"
files. Executing files from untrusted file systems increases the opportunity
for unprivileged users to attain unauthorized administrative access."
  desc  'rationale', ''
  desc  'check', "
    Verify file systems that contain user home directories are mounted with the
\"nosuid\" option.

    Note: If a separate file system has not been created for the user home
directories (user home directories are mounted under \"/\"), this is
automatically a finding as the \"nosuid\" option cannot be used on the \"/\"
system.

    Find the file system(s) that contain the user home directories with the
following command:

    $ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd

    smithj:1001: /home/smithj
    robinst:1002: /home/robinst

    Check the file systems that are mounted at boot time with the following
command:

    $ sudo more /etc/fstab

    UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /home xfs
rw,relatime,discard,data=ordered,nosuid,nodev,noexec 0 0

    If a file system found in \"/etc/fstab\" refers to the user home directory
file system and it does not have the \"nosuid\" option set, this is a finding.
  "
  desc 'fix', "Configure the \"/etc/fstab\" to use the \"nosuid\" option on
file systems that contain user home directories for interactive users."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230299'
  tag rid: 'SV-230299r627750_rule'
  tag stig_id: 'RHEL-08-010570'
  tag fix_id: 'F-32943r567644_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    home_dirs = []
    iuser_entries = passwd.where { uid.to_i >= 1000 && shell !~ /nologin/ }
    iuser_entries.entries.each do |ie|
      username_size = ie.user.length
      home_dirs.append(ie.home[0..ie.home.length - (username_size + 2)])
    end
    home_dirs.uniq.each do |home_dir|
      describe 'User home directories should not be mounted under root' do
        subject { home_dir }
        it { should_not eq '/' }
      end
      describe etc_fstab.where { mount_point == home_dir } do
        it { should be_configured }
        its('mount_options.first') { should include 'nosuid' }
      end
    end
  end
end
