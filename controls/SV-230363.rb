control 'SV-230363' do
  title "RHEL 8 must require the change of at least 8 characters when passwords
are changed."
  desc  "Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes \"pwquality\" as a mechanism to enforce password
complexity. The \"difok\" option sets the number of characters in a password
that must not be present in the old password.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the value of the \"difok\" option in
\"/etc/security/pwquality.conf\" with the following command:

    $ sudo grep difok /etc/security/pwquality.conf

    difok = 8

    If the value of \"difok\" is set to less than \"8\" or is commented out,
this is a finding.
  "
  desc 'fix', "
    Configure the operating system to require the change of at least eight of
the total number of characters when passwords are changed by setting the
\"difok\" option.

    Add the following line to \"/etc/security/pwquality.conf\" (or modify the
line to have the required value):

    difok = 8
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag gid: 'V-230363'
  tag rid: 'SV-230363r627750_rule'
  tag stig_id: 'RHEL-08-020170'
  tag fix_id: 'F-33007r567836_fix'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']

  difok = input('difok')

  describe parse_config_file('/etc/security/pwquality.conf') do
    its('difok') { should cmp >= difok }
  end
end
