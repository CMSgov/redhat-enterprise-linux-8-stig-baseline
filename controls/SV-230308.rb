control 'SV-230308' do
  title "RHEL 8 must prevent files with the setuid and setgid bit set from
being executed on file systems that are imported via Network File System (NFS)."
  desc  "The \"nosuid\" mount option causes the system not to execute
\"setuid\" and \"setgid\" files with owner privileges. This option must be used
for mounting any file system not containing approved \"setuid\" and \"setguid\"
files. Executing files from untrusted file systems increases the opportunity
for unprivileged users to attain unauthorized administrative access."
  desc  'rationale', ''
  desc  'check', "
    Verify that file systems being imported via NFS are mounted with the
\"nosuid\" option with the following command:

    $ sudo grep nfs /etc/fstab | grep nosuid

    UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store nfs rw,nosuid,nodev,noexec
0 0

    If a file system found in \"/etc/fstab\" refers to NFS and it does not have
the \"nosuid\" option set, this is a finding.
  "
  desc 'fix', "Configure the \"/etc/fstab\" to use the \"nosuid\" option on
file systems that are being imported via NFS."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230308'
  tag rid: 'SV-230308r627750_rule'
  tag stig_id: 'RHEL-08-010650'
  tag fix_id: 'F-32952r567671_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  nfs_systems = etc_fstab.nfs_file_systems.entries

  if !nfs_systems.nil? && !nfs_systems.empty?
    nfs_systems.each do |nfs_system|
      describe "Network File System mounted on #{nfs_system['mount_point']}" do
        subject { nfs_system }
        its('mount_options') { should include 'nosuid' }
      end
    end
  else
    describe 'No NFS file systems were found' do
      subject { nfs_systems.nil? || nfs_systems.empty? }
      it { should eq true }
    end
  end
end
