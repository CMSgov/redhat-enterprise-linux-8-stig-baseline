control 'SV-250316' do
  title 'RHEL 8 systems below version 8.2 must configure SELinux context type to allow the use of a non-default faillock tally directory.'
  desc %q(By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

From "Pam_Faillock" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable, a different tally directory must be set with the "dir" option.

SELinux, enforcing a targeted policy, will require any non-default tally directory's security context type to match the default directory's security context type. Without updating the security context type, the pam_faillock module will not write failed login attempts to the non-default tally directory.)
  desc 'check', 'If the system does not have SELinux enabled and enforcing a targeted policy, or if the pam_faillock module is not configured for use, this requirement is not applicable.

Note: This check applies to RHEL versions 8.0 and 8.1. If the system is RHEL version 8.2 or newer, this check is not applicable.

Verify the location of the non-default tally directory for the pam_faillock module with the following command:

$ sudo grep -w dir /etc/pam.d/password-auth

auth   required   pam_faillock.so preauth dir=/var/log/faillock
auth   required   pam_faillock.so authfail dir=/var/log/faillock

Check the security context type of the non-default tally directory with the following command:

$ sudo ls -Zd /var/log/faillock

unconfined_u:object_r:faillog_t:s0 /var/log/faillock

If the security context type of the non-default tally directory is not "faillog_t", this is a finding.'
  desc 'fix', 'Configure RHEL 8 to allow the use of a non-default faillock tally directory while SELinux enforces a targeted policy.

Update the /etc/selinux/targeted/contexts/files/file_contexts.local with "faillog_t" context type for the non-default faillock tally directory with the following command:

$ sudo semanage fcontext -a -t faillog_t "/var/log/faillock(/.*)?" 

Next, update the context type of the non-default faillock directory/subdirectories and files with the following command:	

$ sudo restorecon -R -v /var/log/faillock'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-53750r793003_chk'
  tag severity: 'medium'
  tag gid: 'V-250316'
  tag rid: 'SV-250316r854080_rule'
  tag stig_id: 'RHEL-08-020028'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-53704r793004_fix'
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
