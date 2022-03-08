control 'SV-244528' do
  title "The RHEL 8 SSH daemon must not allow GSSAPI authentication, except to
fulfill documented and validated mission requirements."
  desc  "Configuring this setting for the SSH daemon provides additional
assurance that remote logon via SSH will require a password, even in the event
of misconfiguration elsewhere."
  desc  'rationale', ''
  desc  'check', "
    Verify the SSH daemon does not allow GSSAPI authentication with the
following command:

    $ sudo grep -i GSSAPIAuthentication  /etc/ssh/sshd_config

    GSSAPIAuthentication no

    If the value is returned as \"yes\", the returned line is commented out, no
output is returned, or has not been documented with the ISSO, this is a finding.
  "
  desc  'fix', "
    Configure the SSH daemon to not allow GSSAPI authentication.

    Add the following line in \"/etc/ssh/sshd_config\", or uncomment the line
and set the value to \"no\":

    GSSAPIAuthentication no

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-244528'
  tag rid: 'SV-244528r743833_rule'
  tag stig_id: 'RHEL-08-010522'
  tag fix_id: 'F-47760r743832_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?
    impact 0.0
    describe "Control not applicable - SSH is not installed within containerized RHEL" do
      skip "Control not applicable - SSH is not installed within containerized RHEL"
    end
  else
    describe sshd_config do
      its('GSSAPIAuthentication') { should cmp 'no' }
    end
  end
end

