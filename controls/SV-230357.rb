control 'SV-230357' do
  title 'RHEL 8 must enforce password complexity by requiring that at least one
uppercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes pwquality as a mechanism to enforce password complexity.
Note that in order to require uppercase characters, without degrading the
"minlen" value, the credit value must be expressed as a negative number in
"/etc/security/pwquality.conf".'

  desc 'check', 'Verify the value for "ucredit" with the following command:

$ sudo grep -r ucredit /etc/security/pwquality.conf*

/etc/security/pwquality.conf:ucredit = -1

If the value of "ucredit" is a positive number or is commented out, this is a finding.

If conflicting results are returned, this is a finding.'

  desc 'fix', 'Configure the operating system to enforce password complexity by requiring that at least one uppercase character be used by setting the "ucredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

ucredit = -1

Remove any configurations that conflict with the above value.'

  impact 0.5

  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag gid: 'V-230357'
  tag rid: 'SV-230357r858771_rule'
  tag stig_id: 'RHEL-08-020110'
  tag fix_id: 'F-33001r858770_fix'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']

  describe 'pwquality.conf settings' do
    let(:config) { parse_config_file('/etc/security/pwquality.conf', multiple_values: true) }
    let(:setting) { 'ucredit' }
    let(:count) { config.params[setting].length }
    it 'only sets `ucredit` once' do
      expect(count).to eq(1)
    end
    it 'does not set `ucredit` to a positive value' do
      expect(config.params[setting]).to cmp < 0
    end
  end
end
