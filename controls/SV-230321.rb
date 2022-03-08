control 'SV-230321' do
  title "All RHEL 8 local interactive user home directories must have mode 0750
or less permissive."
  desc  "Excessive permissions on local interactive user home directories may
allow unauthorized access to user files by other users."
  desc  'rationale', ''
  desc  'check', "
    Verify the assigned home directory of all local interactive users has a
mode of \"0750\" or less permissive with the following command:

    Note: This may miss interactive users that have been assigned a privileged
User Identifier (UID). Evidence of interactive use may be obtained from a
number of log files containing system logon information.

    $ sudo ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}'
/etc/passwd)

    drwxr-x--- 2 smithj admin 4096 Jun 5 12:41 smithj

    If home directories referenced in \"/etc/passwd\" do not have a mode of
\"0750\" or less permissive, this is a finding.
  "
  desc 'fix', "
    Change the mode of interactive user’s home directories to \"0750\". To
change the mode of a local interactive user’s home directory, use the following
command:

    Note: The example will be for the user \"smithj\".

    $ sudo chmod 0750 /home/smithj
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230321'
  tag rid: 'SV-230321r627750_rule'
  tag stig_id: 'RHEL-08-010730'
  tag fix_id: 'F-32965r567710_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  exempt_home_users = input('exempt_home_users')

  uid_min = login_defs.read_params['UID_MIN'].to_i
  uid_min = 1000 if uid_min.nil?

  iuser_entries = passwd.where { uid.to_i >= uid_min && shell !~ /nologin/ && !exempt_home_users.include?(user) }

  if !iuser_entries.users.nil? && !iuser_entries.users.empty?
    iuser_entries.homes.each do |home_dir|
      describe file(home_dir) do
        it { should_not be_more_permissive_than('0750') }
      end
    end
  else
    describe 'No non-exempt interactive user accounts were detected on the system' do
      subject { true }
      it { should be true }
    end
  end
end
