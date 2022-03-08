control 'SV-244529' do
  title 'RHEL 8 must use a separate file system for /var/tmp.'
  desc  "The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing."
  desc  'rationale', ''
  desc  'check', "
    Verify that a separate file system/partition has been created for
\"/var/tmp\".

    Check that a file system/partition has been created for \"/var/tmp\" with
the following command:

    $ sudo grep /var/tmp /etc/fstab

    UUID=c274f65f /var/tmp xfs noatime,nobarrier 1 2

    If a separate entry for \"/var/tmp\" is not in use, this is a finding.
  "
  desc  'fix', 'Migrate the "/var/tmp" path onto a separate file system.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-244529'
  tag rid: 'SV-244529r743836_rule'
  tag stig_id: 'RHEL-08-010544'
  tag fix_id: 'F-47761r743835_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe etc_fstab.where { mount_point == '/var/tmp' } do
      it { should exist }
    end
  end
end

