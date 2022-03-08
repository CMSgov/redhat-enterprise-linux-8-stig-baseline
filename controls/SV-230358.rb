control 'SV-230358' do
  title "RHEL 8 must enforce password complexity by requiring that at least one
lower-case character be used."
  desc  "Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes pwquality as a mechanism to enforce password complexity.
Note that in order to require lower-case characters without degrading the
\"minlen\" value, the credit value must be expressed as a negative number in
\"/etc/security/pwquality.conf\".
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the value for \"lcredit\" in \"/etc/security/pwquality.conf\" with
the following command:

    $ sudo grep lcredit /etc/security/pwquality.conf

    lcredit = -1

    If the value of \"lcredit\" is a positive number or is commented out, this
is a finding.
  "
  desc 'fix', "
    Configure the operating system to enforce password complexity by requiring
that at least one lower-case character be used by setting the \"lcredit\"
option.

    Add the following line to /etc/security/pwquality.conf (or modify the line
to have the required value):

    lcredit = -1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag gid: 'V-230358'
  tag rid: 'SV-230358r627750_rule'
  tag stig_id: 'RHEL-08-020120'
  tag fix_id: 'F-33002r567821_fix'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']

  describe parse_config_file('/etc/security/pwquality.conf') do
    its('lcredit.to_i') { should cmp < 0 }
  end
end
