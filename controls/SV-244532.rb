control 'SV-244532' do
  title "RHEL 8 must be configured so that all files and directories contained
in local interactive user home directories are group-owned by a group of which
the home directory owner is a member."
  desc  "If a local interactive user's files are group-owned by a group of
which the user is not a member, unintended users may be able to access them."
  desc  'rationale', ''
  desc  'check', "
    Verify all files and directories in a local interactive user home directory
are group-owned by a group that the user is a member.

    Check the group owner of all files and directories in a local interactive
user's home directory with the following command:

    Note: The example will be for the user \"smithj\", who has a home directory
of \"/home/smithj\".

    $ sudo ls -lLR /<home directory>/<users home directory>/
    -rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1
    -rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2
    -rw-r--r-- 1 smithj sa        231 Mar  5 17:06 file3

    If any files found with a group-owner different from the home directory
user private group, check to see if the user is a member of that group with the
following command:

    $ sudo grep smithj /etc/group
    sa:x:100:juan,shelley,bob,smithj
    smithj:x:521:smithj

    If any files or directories are group owned by a group that the directory
owner is not a member of, this is a finding.
  "
  desc  'fix', "
    Change the group of a local interactive user's files and directories to a
group that the interactive user is a member. To change the group owner of a
local interactive user's files and directories, use the following command:

    Note: The example will be for the user smithj, who has a home directory of
\"/home/smithj\" and is a member of the users group.

    $ sudo chgrp smithj /home/smithj/<file or directory>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-244532'
  tag rid: 'SV-244532r743845_rule'
  tag stig_id: 'RHEL-08-010741'
  tag fix_id: 'F-47764r743844_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  non_interactive_shells = input('non_interactive_shells')

  ignore_shells = non_interactive_shells.join('|')

  findings = Set[]
  users.where { !shell.match(ignore_shells) && (uid >= 1000 || uid == 0) }.entries.each do |user_info|
    findings += command("find #{user_info.home} -xdev -not -gid #{user_info.gid}").stdout.split("\n")
  end
  describe findings do
    it { should be_empty }
  end
end

