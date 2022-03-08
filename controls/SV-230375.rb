control 'SV-230375' do
  title 'All RHEL 8 passwords must contain at least one special character.'
  desc  "Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes \"pwquality\" as a mechanism to enforce password
complexity. Note that to require special characters without degrading the
\"minlen\" value, the credit value must be expressed as a negative number in
\"/etc/security/pwquality.conf\".
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the value for \"ocredit\" in \"/etc/security/pwquality.conf\" with
the following command:

    $ sudo grep ocredit /etc/security/pwquality.conf

    ocredit = -1

    If the value of \"ocredit\" is a positive number or is commented out, this
is a finding.
  "
  desc 'fix', "
    Configure the operating system to enforce password complexity by requiring
that at least one special character be used by setting the \"ocredit\" option.

    Add the following line to /etc/security/pwquality.conf (or modify the line
to have the required value):

    ocredit = -1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag gid: 'V-230375'
  tag rid: 'SV-230375r627750_rule'
  tag stig_id: 'RHEL-08-020280'
  tag fix_id: 'F-33019r567872_fix'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']

  describe parse_config_file('/etc/security/pwquality.conf') do
    its('ocredit.to_i') { should cmp < 0 }
  end
end
