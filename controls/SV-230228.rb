control 'SV-230228' do
  title 'All RHEL 8 remote access methods must be monitored.'
  desc  "Remote access services, such as those providing remote access to
network devices and information systems, which lack automated monitoring
capabilities, increase risk and make remote user access management difficult at
best.

    Remote access is access to DoD nonpublic information systems by an
authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

    Automated monitoring of remote access sessions allows organizations to
detect cyber attacks and ensure ongoing compliance with remote access policies
by auditing connection activities of remote access capabilities, such as Remote
Desktop Protocol (RDP), on a variety of information system components (e.g.,
servers, workstations, notebook computers, smartphones, and tablets).
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that RHEL 8 monitors all remote access methods.

    Check that remote access methods are being logged by running the following
command:

    $ sudo grep -E '(auth.*|authpriv.*|daemon.*)' /etc/rsyslog.conf

    auth.*;authpriv.*;daemon.* /var/log/secure

    If \"auth.*\", \"authpriv.*\" or \"daemon.*\" are not configured to be
logged, this is a finding.
  "
  desc 'fix', "
    Configure RHEL 8 to monitor all remote access methods by installing rsyslog
with the following command:

    $ sudo yum install rsyslog

    Then add or update the following lines to the \"/etc/rsyslog.conf\" file:

    auth.*;authpriv.*;daemon.* /var/log/secure

    The \"rsyslog\" service must be restarted for the changes to take effect.
To restart the \"rsyslog\" service, run the following command:

    $ sudo systemctl restart rsyslog.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag gid: 'V-230228'
  tag rid: 'SV-230228r627750_rule'
  tag stig_id: 'RHEL-08-010070'
  tag fix_id: 'F-32872r567431_fix'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']

  if virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?
    impact 0.0
    describe "Control not applicable; remote access not configured within containerized RHEL" do
      skip "Control not applicable; remote access not configured within containerized RHEL"
    end
  else
    describe command('grep -E \'(auth.*|authpriv.*|daemon.*)\' /etc/rsyslog.conf') do
      its('stdout.strip') { should match %r{^[\s]*[a-z\.;\*]*auth(,[a-z,]+)*\.\*[\s]*\/*} }
      its('stdout.strip') { should match %r{^[\s]*[a-z\.;\*]*authpriv(,[a-z,]+)*\.\*[\s]*\/*} }
      its('stdout.strip') { should match %r{^[\s]*[a-z\.;\*]*daemon(,[a-z,]+)*\.\*[\s]*\/*} }
    end
  end
end
