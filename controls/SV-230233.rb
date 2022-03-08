control 'SV-230233' do
  title "The RHEL 8 password-auth file must be configured to use a sufficient
number of hashing rounds."
  desc  "The system must use a strong hashing algorithm to store the password.
The system must use a sufficient number of hashing rounds to ensure the
required level of entropy.

    Passwords need to be protected at all times, and encryption is the standard
method for protecting passwords. If passwords are not encrypted, they can be
plainly read (i.e., clear text) and easily compromised.
  "
  desc  'rationale', ''
  desc  'check', "
    Check that a minimum number of hash rounds is configured by running the
following command:

    $ sudo grep rounds /etc/pam.d/password-auth

    password sufficient pam_unix.so sha512 rounds=5000

    If \"rounds\" has a value below \"5000\", or is commented out, this is a
finding.
  "
  desc  'fix', "
    Configure RHEL 8 to encrypt all stored passwords with a strong
cryptographic hash.

    Edit/modify the following line in the \"/etc/pam.d/password-auth\" file and
set \"rounds\" to a value no lower than \"5000\":

    password sufficient pam_unix.so sha512 rounds=5000
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag gid: 'V-230233'
  tag rid: 'SV-230233r743919_rule'
  tag stig_id: 'RHEL-08-010130'
  tag fix_id: 'F-32877r743918_fix'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']

  describe pam('/etc/pam.d/password-auth') do
    its('lines') { should match_pam_rule('password sufficient pam_unix.so').all_with_integer_arg('rounds', '>=', 5000) }
  end
end
