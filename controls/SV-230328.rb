control 'SV-230328' do
  title "A separate RHEL 8 filesystem must be used for user home directories
(such as /home or an equivalent)."
  desc  "The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing."
  desc  'rationale', ''
  desc  'check', "
    Verify that a separate file system/partition has been created for
non-privileged local interactive user home directories.

    Check the home directory assignment for all non-privileged users, users
with a User Identifier (UID) greater than 1000, on the system with the
following command:

    $ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd

    adamsj 1001 /home/adamsj
    jacksonm 1002 /home/jacksonm
    smithj 1003 /home/smithj

    The output of the command will give the directory/partition that contains
the home directories for the non-privileged users on the system (in this
example, \"/home\") and users’ shell. All accounts with a valid shell (such as
/bin/bash) are considered interactive users.

    Check that a file system/partition has been created for the non-privileged
interactive users with the following command:

    Note: The partition of \"/home\" is used in the example.

    $ sudo grep /home /etc/fstab

    UUID=333ada18 /home ext4 noatime,nobarrier,nodev 1 2

    If a separate entry for the file system/partition containing the
non-privileged interactive user home directories does not exist, this is a
finding.
  "
  desc 'fix', "Migrate the \"/home\" directory onto a separate file
system/partition."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230328'
  tag rid: 'SV-230328r627750_rule'
  tag stig_id: 'RHEL-08-010800'
  tag fix_id: 'F-32972r567731_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  exempt_home_users = input('exempt_home_users')
  non_interactive_shells = input('non_interactive_shells')

  ignore_shells = non_interactive_shells.join('|')

  uid_min = login_defs.read_params['UID_MIN'].to_i
  uid_min = 1000 if uid_min.nil?

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    # excluding root because its home directory is usually "/root" (mountpoint "/")
    users.where { !shell.match(ignore_shells) && (uid >= uid_min) }.entries.each do |user_info|
      next if exempt_home_users.include?(user_info.username.to_s)

      home_mount = command(%(df #{user_info.home} --output=target | tail -1)).stdout.strip
      describe user_info.username do
        context 'with mountpoint' do
          context home_mount do
            it { should_not be_empty }
            it { should_not match(%r{^/$}) }
          end
        end
      end
    end
  end
end
