control 'SV-230369' do
  title 'RHEL 8 passwords must have a minimum of 15 characters.'
  desc  "The shorter the password, the lower the number of possible
combinations that need to be tested before the password is compromised.

    Password complexity, or strength, is a measure of the effectiveness of a
password in resisting attempts at guessing and brute-force attacks. Password
length is one factor of several that helps to determine strength and how long
it takes to crack a password. Use of more characters in a password helps to
increase exponentially the time and/or resources required to compromise the
password.

    RHEL 8 utilizes \"pwquality\" as a mechanism to enforce password
complexity. Configurations are set in the \"etc/security/pwquality.conf\" file.

    The \"minlen\", sometimes noted as minimum length, acts as a \"score\" of
complexity based on the credit components of the \"pwquality\" module. By
setting the credit components to a negative value, not only will those
components be required, they will not count towards the total \"score\" of
\"minlen\". This will enable \"minlen\" to require a 15-character minimum.

    The DoD minimum password requirement is 15 characters.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system enforces a minimum 15-character password
length. The \"minlen\" option sets the minimum number of characters in a new
password.

    Check for the value of the \"minlen\" option in
\"/etc/security/pwquality.conf\" with the following command:

    $ sudo grep minlen /etc/security/pwquality.conf
    minlen = 15

    If the command does not return a \"minlen\" value of 15 or greater, this is
a finding.
  "
  desc 'fix', "
    Configure operating system to enforce a minimum 15-character password
length.

    Add the following line to \"/etc/security/pwquality.conf\" (or modify the
line to have the required value):

    minlen = 15
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag gid: 'V-230369'
  tag rid: 'SV-230369r627750_rule'
  tag stig_id: 'RHEL-08-020230'
  tag fix_id: 'F-33013r567854_fix'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']

  min_len = input('min_len')

  describe parse_config_file('/etc/security/pwquality.conf') do
    its('minlen.to_i') { should cmp >= min_len }
  end
end
