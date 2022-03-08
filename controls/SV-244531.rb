control 'SV-244531' do
  title "All RHEL 8 local interactive user home directory files must have mode
0750 or less permissive."
  desc  "Excessive permissions on local interactive user home directories may
allow unauthorized access to user files by other users."
  desc  'rationale', ''
  desc  'check', "
    Verify all files and directories contained in a local interactive user home
directory, excluding local initialization files, have a mode of \"0750\".
    Files that begin with a \".\" are excluded from this requirement.

    Note: The example will be for the user \"smithj\", who has a home directory
of \"/home/smithj\".

    $ sudo ls -lLR /home/smithj
    -rwxr-x--- 1 smithj smithj 18 Mar 5 17:06 file1
    -rwxr----- 1 smithj smithj 193 Mar 5 17:06 file2
    -rw-r-x--- 1 smithj smithj 231 Mar 5 17:06 file3

    If any files or directories are found with a mode more permissive than
\"0750\", this is a finding.
  "
  desc  'fix', "
    Set the mode on files and directories in the local interactive user home
directory with the following command:

    Note: The example will be for the user smithj, who has a home directory of
\"/home/smithj\" and is a member of the users group.

    $ sudo chmod 0750 /home/smithj/<file or directory>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-244531'
  tag rid: 'SV-244531r743842_rule'
  tag stig_id: 'RHEL-08-010731'
  tag fix_id: 'F-47763r743841_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  non_interactive_shells = input('non_interactive_shells')

  ignore_shells = non_interactive_shells.join('|')

  findings = Set[]
  users.where { !shell.match(ignore_shells) && (uid >= 1000 || uid == 0) }.entries.each do |user_info|
    findings += command("find #{user_info.home} -xdev -not -name '.*' -perm /027").stdout.split("\n")
  end
  describe findings do
    it { should be_empty }
  end
end

