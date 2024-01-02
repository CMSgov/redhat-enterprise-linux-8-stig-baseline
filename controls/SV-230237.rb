control 'SV-230237' do
  title 'The RHEL 8 pam_unix.so module must be configured in the password-auth
file to use a FIPS 140-2 approved cryptographic hashing algorithm for system
authentication.'
  desc 'Unapproved mechanisms that are used for authentication to the
cryptographic module are not verified and therefore cannot be relied upon to
provide confidentiality or integrity, and DoD data may be compromised.

    RHEL 8 systems utilizing encryption are required to use FIPS-compliant
mechanisms for authenticating to cryptographic modules.

    FIPS 140-2 is the current standard for validating that mechanisms used to
access cryptographic modules utilize authentication that meets DoD
requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a
general-purpose computing system.'
  desc 'check', 'Verify that the pam_unix.so module is configured to use sha512.

Check that the pam_unix.so module is configured to use sha512 in /etc/pam.d/password-auth with the following command:

$ sudo grep password /etc/pam.d/password-auth | grep pam_unix

password sufficient pam_unix.so sha512

If "sha512" is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication.

Edit/modify the following line in the "/etc/pam.d/password-auth" file to include the sha512 option for pam_unix.so:

password sufficient pam_unix.so sha512'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag gid: 'V-230237'
  tag rid: 'SV-230237r809276_rule'
  tag stig_id: 'RHEL-08-010160'
  tag fix_id: 'F-32881r809275_fix'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']

  describe pam('/etc/pam.d/password-auth') do
    its('lines') { should match_pam_rule('password sufficient pam_unix.so sha512') }
  end
end
