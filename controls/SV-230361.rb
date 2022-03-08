control 'SV-230361' do
  title "RHEL 8 must require the maximum number of repeating characters be
limited to three when passwords are changed."
  desc  "Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes \"pwquality\" as a mechanism to enforce password
complexity. The \"maxrepeat\" option sets the maximum number of allowed same
consecutive characters in a new password.
  "
  desc  'rationale', ''
  desc  'check', "
    Check for the value of the \"maxrepeat\" option in
\"/etc/security/pwquality.conf\" with the following command:

    $ sudo grep maxrepeat /etc/security/pwquality.conf

    maxrepeat = 3

    If the value of \"maxrepeat\" is set to more than \"3\" or is commented
out, this is a finding.
  "
  desc 'fix', "
    Configure the operating system to require the change of the number of
repeating consecutive characters when passwords are changed by setting the
\"maxrepeat\" option.

    Add the following line to \"/etc/security/pwquality.conf conf\" (or modify
the line to have the required value):

    maxrepeat = 3
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag gid: 'V-230361'
  tag rid: 'SV-230361r627750_rule'
  tag stig_id: 'RHEL-08-020150'
  tag fix_id: 'F-33005r567830_fix'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']

  describe parse_config_file('/etc/security/pwquality.conf') do
    its('maxrepeat') { should cmp <= 3 }
    its('maxrepeat') { should cmp > 0 }
  end
end
