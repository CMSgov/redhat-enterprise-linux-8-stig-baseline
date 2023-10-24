control 'SV-230290' do
  title 'The RHEL 8 SSH daemon must not allow authentication using known host’s
authentication.'
  desc 'Configuring this setting for the SSH daemon provides additional
assurance that remote logon via SSH will require a password, even in the event
of misconfiguration elsewhere.'
  desc 'check', 'Verify the SSH daemon does not allow authentication using known host’s authentication with the following command:

$ sudo grep -ir IgnoreUserKnownHosts /etc/ssh/sshd_config*

IgnoreUserKnownHosts yes

If the value is returned as "no", the returned line is commented out, or no output is returned, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to not allow authentication using known host’s
authentication.

    Add the following line in "/etc/ssh/sshd_config", or uncomment the line
and set the value to "yes":

    IgnoreUserKnownHosts yes

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230290'
  tag rid: 'SV-230290r858705_rule'
  tag stig_id: 'RHEL-08-010520'
  tag fix_id: 'F-32934r567617_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end
  else
    describe sshd_config do
      its('IgnoreUserKnownHosts') { should cmp 'yes' }
    end
  end
end
