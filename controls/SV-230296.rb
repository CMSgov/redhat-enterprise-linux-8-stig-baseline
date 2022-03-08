control 'SV-230296' do
  title "RHEL 8 must not permit direct logons to the root account using remote
access via SSH."
  desc  "Even though the communications channel may be encrypted, an additional
layer of security is gained by extending the policy of not logging on directly
as root. In addition, logging on with a user-specific account provides
individual accountability of actions performed on the system."
  desc  'rationale', ''
  desc  'check', "
    Verify remote access using SSH prevents users from logging on directly as
\"root\".

    Check that SSH prevents users from logging on directly as \"root\" with the
following command:

    $ sudo grep -i PermitRootLogin /etc/ssh/sshd_config

    PermitRootLogin no

    If the \"PermitRootLogin\" keyword is set to \"yes\", is missing, or is
commented out, this is a finding.
  "
  desc 'fix', "
    Configure RHEL 8 to stop users from logging on remotely as the \"root\"
user via SSH.

    Edit the appropriate \"/etc/ssh/sshd_config\" file to uncomment or add the
line for the \"PermitRootLogin\" keyword and set its value to \"no\":

    PermitRootLogin no

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag gid: 'V-230296'
  tag rid: 'SV-230296r627750_rule'
  tag stig_id: 'RHEL-08-010550'
  tag fix_id: 'F-32940r567635_fix'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']

  if virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?
    impact 0.0
    describe "Control not applicable - SSH is not installed within containerized RHEL" do
      skip "Control not applicable - SSH is not installed within containerized RHEL"
    end
  else
    describe sshd_config('/etc/ssh/sshd_config') do
      its('PermitRootLogin') { should eq 'no' }
    end
  end
end
