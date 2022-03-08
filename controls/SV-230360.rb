control 'SV-230360' do
  title "RHEL 8 must require the maximum number of repeating characters of the
same character class be limited to four when passwords are changed."
  desc  "Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes \"pwquality\" as a mechanism to enforce password
complexity. The \"maxclassrepeat\" option sets the maximum number of allowed
same consecutive characters in the same class in the new password.
  "
  desc  'rationale', ''
  desc  'check', "
    Check for the value of the \"maxclassrepeat\" option in
\"/etc/security/pwquality.conf\" with the following command:

    $ sudo grep maxclassrepeat /etc/security/pwquality.conf

    maxclassrepeat = 4

    If the value of \"maxclassrepeat\" is set to more than \"4\" or is
commented out, this is a finding.
  "
  desc 'fix', "
    Configure the operating system to require the change of the number of
repeating characters of the same character class when passwords are changed by
setting the \"maxclassrepeat\" option.

    Add the following line to \"/etc/security/pwquality.conf\" conf (or modify
the line to have the required value):

    maxclassrepeat = 4
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag gid: 'V-230360'
  tag rid: 'SV-230360r627750_rule'
  tag stig_id: 'RHEL-08-020140'
  tag fix_id: 'F-33004r567827_fix'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']

  describe parse_config_file('/etc/security/pwquality.conf') do
    its('maxclassrepeat') { should cmp <= 4 }
    its('maxclassrepeat') { should cmp > 0 }
  end
end
