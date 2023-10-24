control 'SV-230325' do
  title 'All RHEL 8 local initialization files must have mode 0740 or less
permissive.'
  desc "Local initialization files are used to configure the user's shell
environment upon logon. Malicious modification of these files could compromise
accounts upon logon."
  desc 'check', 'Verify that all local initialization files have a mode of "0740" or less permissive with the following command:

Note: The example will be for the "smithj" user, who has a home directory of "/home/smithj".

     $ sudo ls -al /home/smithj/.[^.]* | more

     -rw-------. 1 smithj users 2984 Apr 27 19:02 .bash_history
     -rw-r--r--. 1 smithj users   18 Aug 21  2019 .bash_logout
     -rw-r--r--. 1 smithj users  193 Aug 21  2019 .bash_profile

If any local initialization files have a mode more permissive than "0740", this is a finding.'
  desc 'fix', 'Set the mode of the local initialization files to "0740" with the
following command:

    Note: The example will be for the smithj user, who has a home directory of
"/home/smithj".

    $ sudo chmod 0740 /home/smithj/.<INIT_FILE>'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230325'
  tag rid: 'SV-230325r917879_rule'
  tag stig_id: 'RHEL-08-010770'
  tag fix_id: 'F-32969r917878_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  non_interactive_shells = input('non_interactive_shells')

  ignore_shells = non_interactive_shells.join('|')

  findings = Set[]
  users.where { !shell.match(ignore_shells) && (uid >= 1000 || uid == 0) }.entries.each do |user_info|
    findings += command("find #{user_info.home} -xdev -maxdepth 1 -name '.*' -type f -perm /037").stdout.split("\n")
  end
  describe findings do
    it { should be_empty }
  end
end
