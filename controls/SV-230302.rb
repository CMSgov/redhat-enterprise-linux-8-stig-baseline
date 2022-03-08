control 'SV-230302' do
  title "RHEL 8 must prevent code from being executed on file systems that
contain user home directories."
  desc  "The \"noexec\" mount option causes the system not to execute binary
files. This option must be used for mounting any file system not containing
approved binary files, as they may be incompatible. Executing files from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access."
  desc  'rationale', ''
  desc  'check', "
    Verify file systems that contain user home directories are mounted with the
\"noexec\" option.

    Note: If a separate file system has not been created for the user home
directories (user home directories are mounted under \"/\"), this is
automatically a finding as the \"noexec\" option cannot be used on the \"/\"
system.

    Find the file system(s) that contain the user home directories with the
following command:

    $ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd

    smithj:1001: /home/smithj
    robinst:1002: /home/robinst

    Check the file systems that are mounted at boot time with the following
command:

    $ sudo more /etc/fstab

    UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /home ext4
rw,relatime,discard,data=ordered,nosuid,nodev,noexec 0 2

    If a file system found in \"/etc/fstab\" refers to the user home directory
file system and it does not have the \"noexec\" option set, this is a finding.
  "
  desc 'fix', "Configure the \"/etc/fstab\" to use the \"noexec\" option on
file systems that contain user home directories for interactive users."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230302'
  tag rid: 'SV-230302r627750_rule'
  tag stig_id: 'RHEL-08-010590'
  tag fix_id: 'F-32946r567653_fix'
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
        its('mount_options.first') { should include 'noexec' }
      end
    end
  end
end
