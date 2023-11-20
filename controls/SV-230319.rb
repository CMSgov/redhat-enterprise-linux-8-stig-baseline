control 'SV-230319' do
  title 'All RHEL 8 world-writable directories must be group-owned by root,
sys, bin, or an application group.'
  desc 'If a world-writable directory is not group-owned by root, sys, bin, or
an application Group Identifier (GID), unauthorized users may be able to modify
files created by others.

    The only authorized public directories are those temporary directories
supplied with the system or those designed to be temporary file repositories.
The setting is normally reserved for directories used by the system and by
users for temporary file storage, (e.g., /tmp), and for directories requiring
global read/write access.'
  desc 'check', 'The following command will discover and print world-writable directories
that are not group-owned by a system account, given the assumption that only
system accounts have a gid lower than 1000. Run it once for each local
partition [PART]:

    $ sudo find [PART] -xdev -type d -perm -0002 -gid +999 -print

    If there is output, this is a finding.'
  desc 'fix', 'All directories in local partitions which are world-writable
must be group-owned by root or another system account.  If any world-writable
directories are not group-owned by a system account, this must be investigated.
 Following this, the directories must be deleted or assigned to an appropriate
group.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230319'
  tag rid: 'SV-230319r743961_rule'
  tag stig_id: 'RHEL-08-010710'
  tag fix_id: 'F-32963r567704_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  ww_dirs = Set[]
  partitions = etc_fstab.params.map { |partition| partition['mount_point'] }.uniq
  partitions.each do |part|
    cmd = "find #{part} -xdev -type d -perm -0002 -gid +999 -print"
    ww_dirs += command(cmd).stdout.split("\n")
  end

  describe 'List of world-writeable directories which are not group-owned by system accounts across all partitions' do
    subject { ww_dirs.to_a }
    it { should be_empty }
  end
end
