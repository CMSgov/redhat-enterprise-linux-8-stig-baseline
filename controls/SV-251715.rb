# frozen_string_literal: true

control 'SV-251715' do
  title 'RHEL 8 systems below version 8.4 must ensure the password complexity module in the password-auth file is configured for three retries or less.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.

RHEL 8 uses "pwquality" as a mechanism to enforce password complexity. This is set in both:
/etc/pam.d/password-auth
/etc/pam.d/system-auth

By limiting the number of attempts to meet the pwquality module complexity requirements before returning with an error, the system will audit abnormal attempts at password changes.'
  desc 'check', 'Note: This requirement applies to RHEL versions 8.0 through 8.3. If the system is RHEL version 8.4 or newer, this requirement is not applicable.

Verify the operating system is configured to limit the "pwquality" retry option to 3.

Check for the use of the "pwquality" retry option in the password-auth file with the following command:

     $ sudo cat /etc/pam.d/password-auth | grep pam_pwquality

     password requisite pam_pwquality.so retry=3

If the value of "retry" is set to "0" or greater than "3", this is a finding.'
  desc 'fix', 'Configure the operating system to limit the "pwquality" retry option to 3.

Add the following line to the "/etc/pam.d/password-auth" file (or modify the line to have the required value):

     password requisite pam_pwquality.so retry=3'
  impact 0.5
  tag check_id: 'C-55152r902744_chk'
  tag severity: 'medium'
  tag gid: 'V-251715'
  tag rid: 'SV-251715r902746_rule'
  tag stig_id: 'RHEL-08-020103'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55106r902745_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  only_if("This requirement only applies to RHEL 8 versions below 8.4", impact: 0.0) {
    if os.release.to_f < 8.4
  }

  describe pam_auth_files['password-auth'] do
    its('lines') { should match_pam_rule('.* .* pam_pwquality.so').any_with_integer_arg('retry', '>=', input('min_retry')) }
  end
end
