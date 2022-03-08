control 'SV-230356' do
  title 'RHEL 8 must ensure a password complexity module is enabled.'
  desc  "Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks. \"pwquality\" enforces complex password construction
configuration and has the ability to limit brute-force attacks on the system.

    RHEL 8 utilizes \"pwquality\" as a mechanism to enforce password
complexity. This is set in both:
    /etc/pam.d/password-auth
    /etc/pam.d/system-auth

    Note the value of \"retry\" set in these configuration files should be
between \"1\" and \"3\". Manual changes to the listed files may be overwritten
by the \"authselect\" program.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system uses \"pwquality\" to enforce the password
complexity rules.

    Check for the use of \"pwquality\" with the following commands:

    $ sudo cat /etc/pam.d/password-auth | grep pam_pwquality

    password required pam_pwquality.so retry=3

    $ sudo cat /etc/pam.d/system-auth | grep pam_pwquality

    password required pam_pwquality.so retry=3

    If both commands do not return a line containing the value
\"pam_pwquality.so\", or the line is commented out, this is a finding.

    If the value of \"retry\" is set to \"0\" or greater than \"3\", this is a
finding.
  "
  desc 'fix', "
    Configure the operating system to use \"pwquality\" to enforce password
complexity rules.

    Add the following line to both \"/etc/pam.d/password-auth\" and
\"/etc/pam.d/system-auth\" (or modify the line to have the required value):

    password required pam_pwquality.so retry=3
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag gid: 'V-230356'
  tag rid: 'SV-230356r627750_rule'
  tag stig_id: 'RHEL-08-020100'
  tag fix_id: 'F-33000r567815_fix'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']

  max_retry = input('max_retry')

  describe pam('/etc/pam.d/passwd') do
    its('lines') { should match_pam_rule('password (required|requisite) pam_pwquality.so') }
    its('lines') { should match_pam_rule('password (required|requisite) pam_pwquality.so').all_with_integer_arg('retry', '>=', 1) }
    its('lines') { should match_pam_rule('password (required|requisite) pam_pwquality.so').all_with_integer_arg('retry', '<=', max_retry) }
  end
  describe pam('/etc/pam.d/password-auth') do
    its('lines') { should match_pam_rule('password (required|requisite) pam_pwquality.so') }
    its('lines') { should match_pam_rule('password (required|requisite) pam_pwquality.so').all_with_integer_arg('retry', '>=', 1) }
    its('lines') { should match_pam_rule('password (required|requisite) pam_pwquality.so').all_with_integer_arg('retry', '<=', max_retry) }
  end
end
