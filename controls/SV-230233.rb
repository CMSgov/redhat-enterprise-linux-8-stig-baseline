control 'SV-230233' do
  title 'The RHEL 8 shadow password suite must be configured to use a sufficient number of hashing rounds.'
  desc 'The system must use a strong hashing algorithm to store the password.
The system must use a sufficient number of hashing rounds to ensure the
required level of entropy.

    Passwords need to be protected at all times, and encryption is the standard
method for protecting passwords. If passwords are not encrypted, they can be
plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Check that a minimum number of hash rounds is configured by running the following command:

     $ sudo grep -E "^SHA_CRYPT_" /etc/login.defs

If only one of "SHA_CRYPT_MIN_ROUNDS" or "SHA_CRYPT_MAX_ROUNDS" is set, and this value is below "5000", this is a finding.

If both "SHA_CRYPT_MIN_ROUNDS" and "SHA_CRYPT_MAX_ROUNDS" are set, and the highest value for either is below "5000", this is a finding.'
  desc 'fix', 'Configure RHEL 8 to encrypt all stored passwords with a strong cryptographic hash.

Edit/modify the following line in the "/etc/login.defs" file and set "SHA_CRYPT_MIN_ROUNDS" to a value no lower than "5000":

SHA_CRYPT_MIN_ROUNDS 5000'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag gid: 'V-230233'
  tag rid: 'SV-230233r880705_rule'
  tag stig_id: 'RHEL-08-010130'
  tag fix_id: 'F-32877r809272_fix'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']

  describe.one do
    describe login_defs do
      its('SHAH_CRYPT_MIN_ROUNDS') { should cmp >= 5000 }
    end
    describe login_defs do
      its('SHAH_CRYPT_MIN_ROUNDS') { should be_nil }
    end
  end

  describe.one do
    describe login_defs do
      its('SHAH_CRYPT_MAX_ROUNDS') { should cmp >= 5000 }
    end
    describe login_defs do
      its('SHAH_CRYPT_MAX_ROUNDS') { should be_nil }
    end
  end
end
