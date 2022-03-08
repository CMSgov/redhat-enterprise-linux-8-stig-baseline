control 'SV-230362' do
  title "RHEL 8 must require the change of at least four character classes when
passwords are changed."
  desc  "Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes \"pwquality\" as a mechanism to enforce password
complexity. The \"minclass\" option sets the minimum number of required classes
of characters for the new password (digits, uppercase, lowercase, others).
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the value of the \"minclass\" option in
\"/etc/security/pwquality.conf\" with the following command:

    $ sudo grep minclass /etc/security/pwquality.conf
    minclass = 4

    If the value of \"minclass\" is set to less than \"4\" or is commented out,
this is a finding.
  "
  desc 'fix', "
    Configure the operating system to require the change of at least four
character classes when passwords are changed by setting the \"minclass\" option.

    Add the following line to \"/etc/security/pwquality.conf conf\" (or modify
the line to have the required value):

    minclass = 4
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag gid: 'V-230362'
  tag rid: 'SV-230362r627750_rule'
  tag stig_id: 'RHEL-08-020160'
  tag fix_id: 'F-33006r567833_fix'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']

  describe parse_config_file('/etc/security/pwquality.conf') do
    its('minclass') { should cmp >= 4 }
  end
end
