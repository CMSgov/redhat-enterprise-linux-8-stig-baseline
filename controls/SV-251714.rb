control 'SV-251714' do
  title 'RHEL 8 systems below version 8.4 must ensure the password complexity module in the system-auth file is configured for three retries or less.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.

RHEL 8 uses "pwquality" as a mechanism to enforce password complexity. This is set in both:
/etc/pam.d/password-auth
/etc/pam.d/system-auth

By limiting the number of attempts to meet the pwquality module complexity requirements before returning with an error, the system will audit abnormal attempts at password changes.'
  desc 'check', 'Note: This requirement applies to RHEL versions 8.0 through 8.3. If the system is RHEL version 8.4 or newer, this requirement is not applicable.

Verify the operating system is configured to limit the "pwquality" retry option to 3. 

Check for the use of the "pwquality" retry option in the system-auth file with the following command:

     $ sudo cat /etc/pam.d/system-auth | grep pam_pwquality

     password requisite pam_pwquality.so retry=3

If the value of "retry" is set to "0" or greater than "3", this is a finding.'
  desc 'fix', 'Configure the operating system to limit the "pwquality" retry option to 3.

Add the following line to the "/etc/pam.d/system-auth" file (or modify the line to have the required value):

     password requisite pam_pwquality.so retry=3'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-55151r902741_chk'
  tag severity: 'medium'
  tag gid: 'V-251714'
  tag rid: 'SV-251714r902743_rule'
  tag stig_id: 'RHEL-08-020102'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55105r902742_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
