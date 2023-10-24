control 'SV-251717' do
  title 'RHEL 8 must be configured in the system-auth file to prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to reuse their password consecutively when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements.

RHEL 8 uses "pwhistory" consecutively as a mechanism to prohibit password reuse. This is set in both:
/etc/pam.d/password-auth
/etc/pam.d/system-auth.

Note that manual changes to the listed files may be overwritten by the "authselect" program.'
  desc 'check', 'Verify the operating system is configured in the system-auth file to prohibit password reuse for a minimum of five generations.

Check for the value of the "remember" argument in "/etc/pam.d/system-auth" with the following command:

     $ sudo grep -i remember /etc/pam.d/system-auth

     password requisite pam_pwhistory.so use_authtok remember=5 retry=3

If the line containing "pam_pwhistory.so" does not have the "remember" module argument set, is commented out, or the value of the "remember" module argument is set to less than "5", this is a finding.'
  desc 'fix', 'Configure the operating system in the system-auth file to prohibit password reuse for a minimum of five generations.

Add the following line in "/etc/pam.d/system-auth" (or modify the line to have the required value):

     password requisite pam_pwhistory.so use_authtok remember=5 retry=3'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-55154r902747_chk'
  tag severity: 'medium'
  tag gid: 'V-251717'
  tag rid: 'SV-251717r902749_rule'
  tag stig_id: 'RHEL-08-020221'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-55108r902748_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
