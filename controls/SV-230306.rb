control 'SV-230306' do
  title "RHEL 8 must prevent code from being executed on file systems that are
imported via Network File System (NFS)."
  desc  "The \"noexec\" mount option causes the system not to execute binary
files. This option must be used for mounting any file system not containing
approved binary as they may be incompatible. Executing files from untrusted
file systems increases the opportunity for unprivileged users to attain
unauthorized administrative access."
  desc  'rationale', ''
  desc  'check', "
    Verify that  file systems being imported via NFS are mounted with the
\"noexec\" option with the following command:

    $ sudo grep nfs /etc/fstab | grep noexec

    UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store nfs rw,nosuid,nodev,noexec
0 0

    If a file system found in \"/etc/fstab\" refers to NFS and it does not have
the \"noexec\" option set, this is a finding.
  "
  desc 'fix', "Configure the \"/etc/fstab\" to use the \"noexec\" option on
file systems that are being imported via NFS."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230306'
  tag rid: 'SV-230306r627750_rule'
  tag stig_id: 'RHEL-08-010630'
  tag fix_id: 'F-32950r567665_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  nfs_systems = etc_fstab.nfs_file_systems.entries

  if !nfs_systems.nil? && !nfs_systems.empty?
    nfs_systems.each do |nfs_system|
      describe "Network File System mounted on #{nfs_system['mount_point']}" do
        subject { nfs_system }
        its('mount_options') { should include 'noexec' }
      end
    end
  else
    describe 'No NFS file systems were found' do
      subject { nfs_systems.nil? || nfs_systems.empty? }
      it { should eq true }
    end
  end
end
