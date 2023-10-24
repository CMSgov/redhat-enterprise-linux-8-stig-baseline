control 'SV-251711' do
  title 'RHEL 8 must specify the default "include" directory for the /etc/sudoers file.'
  desc 'The "sudo" command allows authorized users to run programs (including shells) as other users, system users, and root. The "/etc/sudoers" file is used to configure authorized "sudo" users as well as the programs they are allowed to run. Some configuration options in the "/etc/sudoers" file allow configured users to run programs without re-authenticating. Use of these configuration options makes it easier for one compromised account to be used to compromise other accounts.

It is possible to include other sudoers files from within the sudoers file currently being parsed using the #include and #includedir directives. When sudo reaches this line it will suspend processing of the current file (/etc/sudoers) and switch to the specified file/directory. Once the end of the included file(s) is reached, the rest of /etc/sudoers will be processed. Files that are included may themselves include other files. A hard limit of 128 nested include files is enforced to prevent include file loops.'
  desc 'check', 'Note: If the "include" and "includedir" directives are not present in the /etc/sudoers file, this requirement is not applicable.

Verify the operating system specifies only the default "include" directory for the /etc/sudoers file with the following command:

$ sudo grep include /etc/sudoers

#includedir /etc/sudoers.d

If the results are not "/etc/sudoers.d" or additional files or directories are specified, this is a finding.

Verify the operating system does not have nested "include" files or directories within the /etc/sudoers.d directory with the following command:

$ sudo grep -r include /etc/sudoers.d

If results are returned, this is a finding.'
  desc 'fix', 'Configure the /etc/sudoers file to only include the /etc/sudoers.d directory.

Edit the /etc/sudoers file with the following command:

$ sudo visudo

Add or modify the following line:
#includedir /etc/sudoers.d'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-55148r833384_chk'
  tag severity: 'medium'
  tag gid: 'V-251711'
  tag rid: 'SV-251711r833385_rule'
  tag stig_id: 'RHEL-08-010379'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55102r809356_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
