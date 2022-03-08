control 'SV-230335' do
  title "RHEL 8 must automatically lock an account when three unsuccessful
logon attempts occur during a 15-minute time period."
  desc  "By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    In RHEL 8.2 the \"/etc/security/faillock.conf\" file was incorporated to
centralize the configuration of the pam_faillock.so module.  Also introduced is
a \"local_users_only\" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

    From \"faillock.conf\" man pages: Note that the default directory that
\"pam_faillock\" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the \"dir\" option.


  "
  desc  'rationale', ''
  desc  'check', "
    Note: This check applies to RHEL versions 8.2 or newer, if the system is
RHEL version 8.0 or 8.1, this check is not applicable.

    Verify the \"/etc/security/faillock.conf\" file is configured to lock an
account after three unsuccessful logon attempts within 15 minutes:

    $ sudo grep 'fail_interval =' /etc/security/faillock.conf

    fail_interval = 900

    If the \"fail_interval\" option is not set to \"900\" or more, is missing
or commented out, this is a finding.
  "
  desc  'fix', "
    Configure the operating system to lock an account when three unsuccessful
logon attempts occur in 15 minutes.

    Add/Modify the \"/etc/security/faillock.conf\" file to match the following
line:

    fail_interval = 900
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-230335'
  tag rid: 'SV-230335r743969_rule'
  tag stig_id: 'RHEL-08-020013'
  tag fix_id: 'F-32979r743968_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  fail_interval = input('fail_interval')

  if os.release.to_f <= 8.2
    impact 0.0
    describe "The release is #{os.release}" do
      skip 'The release is lower than 8.2; this control is Not Applicable.'
    end
  else
    describe parse_config_file('/etc/security/faillock.conf') do
      its('fail_interval') { should cmp >= fail_interval }
      its('fail_interval') { should_not cmp 0 }
    end
  end
end
