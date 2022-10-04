control 'SV-230337' do
  title "RHEL 8 must automatically lock an account #{input('lockout_time') == 0? 'until the locked account is released by an administrator' : "for #{input('lockout_time')/60} minutes"} when #{input('unsuccessful_attempts')} unsuccessful logon attempts occur
during a #{input('fail_interval')/60}-minute time period."
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
account #{input('lockout_time') == 0? 'until released by an administrator' : "for #{input('lockout_time')/60} minutes"} after #{input('unsuccessful_attempts')} unsuccessful logon
attempts:

    $ sudo grep 'unlock_time =' /etc/security/faillock.conf

    unlock_time = #{input('lockout_time')}

    If the \"unlock_time\" option is not set to \"#{input('lockout_time')}\", is missing or commented
out, this is a finding.
  "
  desc 'fix', "
    Configure the operating system to lock an account #{input('lockout_time') == 0? 'until released by an administrator' : "for #{input('lockout_time')/60} minutes"} when #{input('unsuccessful_attempts')} unsuccessful logon attempts occur in #{input('fail_interval')/60} minutes.

    Add/Modify the \"/etc/security/faillock.conf\" file to match the following
line:

    unlock_time = #{input('lockout_time')}
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-230337'
  tag rid: 'SV-230337r743972_rule'
  tag stig_id: 'RHEL-08-020015'
  tag fix_id: 'F-32981r743971_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  lockout_time = input('lockout_time')

  if os.release.to_f <= 8.2
    impact 0.0
    describe "The release is #{os.release}" do
      skip 'The release is lower than 8.2; this control is Not Applicable.'
    end
  else
    describe.one do
      describe parse_config_file('/etc/security/faillock.conf') do
        its('unlock_time') { should cmp 0 }
      end
      describe parse_config_file('/etc/security/faillock.conf') do
        its('unlock_time') { should cmp >= lockout_time }
        its('unlock_time') { should cmp <= 604800 }
      end
    end
  end
end
