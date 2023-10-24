control 'SV-230232' do
  title 'RHEL 8 must employ FIPS 140-2 approved cryptographic hashing
algorithms for all stored passwords.'
  desc 'The system must use a strong hashing algorithm to store the password.

    Passwords need to be protected at all times, and encryption is the standard
method for protecting passwords. If passwords are not encrypted, they can be
plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Confirm that the interactive user account passwords are using a strong
password hash with the following command:

    $ sudo cut -d: -f2 /etc/shadow


$6$kcOnRq/5$NUEYPuyL.wghQwWssXRcLRFiiru7f5JPV6GaJhNC2aK5F3PZpE/BCCtwrxRc/AInKMNX3CdMw11m9STiql12f/

    Password hashes "!" or "*" indicate inactive accounts not available for
logon and are not evaluated. If any interactive user password hash does not
begin with "$6$", this is a finding.'
  desc 'fix', 'Lock all interactive user accounts not using SHA-512 hashing
until the passwords can be regenerated with SHA-512.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag gid: 'V-230232'
  tag rid: 'SV-230232r877397_rule'
  tag stig_id: 'RHEL-08-010120'
  tag fix_id: 'F-32876r567443_fix'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']

  weak_pw_hash_users = inspec.shadow.where { password !~ /^[*!]{1,2}.*$|^\$6\$.*$|^$/ }.users

  describe weak_pw_hash_users do
    it 'should only contain SHA512 hashes' do
      message = "Users without SHA512 hashes: #{weak_pw_hash_users.join(', ')}"
      expect(weak_pw_hash_users).to be_empty, message
    end
  end
end
