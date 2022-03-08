control 'SV-230327' do
  title 'All RHEL 8 local files and directories must have a valid group owner.'
  desc  "Files without a valid group owner may be unintentionally inherited if
a group is assigned the same Group Identifier (GID) as the GID of the files
without a valid group owner."
  desc  'rationale', ''
  desc  'check', "
    Verify all local files and directories on RHEL 8 have a valid group with
the following command:

    Note: The value after -fstype must be replaced with the filesystem type.
XFS is used as an example.

    $ sudo find / -fstype xfs -nogroup

    If any files on the system do not have an assigned group, this is a finding.

    Note: Command may produce error messages from the /proc and /sys
directories.
  "
  desc 'fix', "
    Either remove all files and directories from RHEL 8 that do not have a
valid group, or assign a valid group to all files and directories on the system
with the \"chgrp\" command:

    $ sudo chgrp <group> <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230327'
  tag rid: 'SV-230327r627750_rule'
  tag stig_id: 'RHEL-08-010790'
  tag fix_id: 'F-32971r567728_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command('grep -v "nodev" /proc/filesystems | awk \'NF{ print $NF }\'')
    .stdout.strip.split("\n").each do |fs|
    describe command("find / -xdev -xautofs -fstype #{fs} -nogroup") do
      its('stdout.strip') { should be_empty }
    end
  end
end
