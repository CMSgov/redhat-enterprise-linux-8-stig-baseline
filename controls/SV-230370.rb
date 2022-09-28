control 'SV-230370' do
  title "RHEL 8 passwords for new users must have a minimum of #{input('min_len')} characters."
  desc  "The shorter the password, the lower the number of possible
combinations that need to be tested before the password is compromised.

    Password complexity, or strength, is a measure of the effectiveness of a
password in resisting attempts at guessing and brute-force attacks. Password
length is one factor of several that helps to determine strength and how long
it takes to crack a password. Use of more characters in a password helps to
increase exponentially the time and/or resources required to compromise the
password.

    The #{input('org_name')[:acronym]} minimum password requirement is #{input('min_len')} characters.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that RHEL 8 enforces a minimum #{input('min_len')}-character password length for new
user accounts by running the following command:

    $ sudo grep -i  pass_min_len /etc/login.defs

    PASS_MIN_LEN #{input('min_len')}

    If the \"PASS_MIN_LEN\" parameter value is less than \"#{input('min_len')}\", or commented
out, this is a finding.
  "
  desc 'fix', "
    Configure operating system to enforce a minimum #{input('min_len')}-character password
length for new user accounts.

    Add, or modify the following line in the \"/etc/login.defs\" file:

    PASS_MIN_LEN #{input('min_len')}
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag gid: 'V-230370'
  tag rid: 'SV-230370r627750_rule'
  tag stig_id: 'RHEL-08-020231'
  tag fix_id: 'F-33014r567857_fix'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']

  min_len = input('min_len')

  describe login_defs do
    its('PASS_MIN_LEN.to_i') { should be >= min_len }
  end
end
