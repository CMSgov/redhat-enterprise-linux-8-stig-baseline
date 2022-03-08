control 'SV-230377' do
  title 'RHEL 8 must prevent the use of dictionary words for passwords.'
  desc  "If RHEL 8 allows the user to select passwords based on dictionary
words, this increases the chances of password compromise by increasing the
opportunity for successful guesses, and brute-force attacks."
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 prevents the use of dictionary words for passwords.

    Determine if the field \"dictcheck\" is set in the
\"/etc/security/pwquality.conf\" or \"/etc/pwquality.conf.d/*.conf\" files with
the following command:

    $ sudo grep dictcheck /etc/security/pwquality.conf
/etc/pwquality.conf.d/*.conf

    dictcheck=1

    If the \"dictcheck\" parameter is not set to \"1\", or is commented out,
this is a finding.
  "
  desc 'fix', "
    Configure RHEL 8 to prevent the use of dictionary words for passwords.

    Add or update the following line in the \"/etc/security/pwquality.conf\"
file or a configuration file in the /etc/pwquality.conf.d/ directory to contain
the \"dictcheck\" parameter:

    dictcheck=1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag gid: 'V-230377'
  tag rid: 'SV-230377r627750_rule'
  tag stig_id: 'RHEL-08-020300'
  tag fix_id: 'F-33021r567878_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file('/etc/security/pwquality.conf') do
    its('dictcheck') { should eq '1' }
  end
end
