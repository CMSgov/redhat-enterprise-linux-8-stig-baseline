control 'SV-230380' do
  title "RHEL 8 must not allow accounts configured with blank or null
passwords."
  desc  "If an account has an empty password, anyone could log on and run
commands with the privileges of that account. Accounts with empty passwords
should never be used in operational environments."
  desc  'rationale', ''
  desc  'check', "
    To verify that null passwords cannot be used, run the following command:

    $ sudo grep -i permitemptypasswords /etc/ssh/sshd_config

    PermitEmptyPasswords no

    If \"PermitEmptyPasswords\" is set to \"yes\", this is a finding.
  "
  desc  'fix', "
    Edit the following line in \"etc/ssh/sshd_config\" to prevent logons with
empty passwords.

    PermitEmptyPasswords no

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230380'
  tag rid: 'SV-230380r743993_rule'
  tag stig_id: 'RHEL-08-020330'
  tag fix_id: 'F-33024r743992_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']


  if virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?
    impact 0.0
    describe "Control not applicable - SSH is not installed within containerized RHEL" do
      skip "Control not applicable - SSH is not installed within containerized RHEL"
    end
  else
    describe sshd_config do
      its('PermitEmptyPasswords') { should cmp 'no' }
    end
  end
end
