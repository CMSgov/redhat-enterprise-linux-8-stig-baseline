control 'SV-230341' do
  title "RHEL 8 must prevent system messages from being presented when #{input('unsuccessful_atempts')}
unsuccessful logon attempts occur."
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

    Verify the \"/etc/security/faillock.conf\" file is configured to prevent
informative messages from being presented at logon attempts:

    $ sudo grep silent /etc/security/faillock.conf

    silent

    If the \"silent\" option is not set, is missing or commented out, this is a
finding.
  "
  desc 'fix', "
    Configure the operating system to prevent informative messages from being
presented at logon attempts.

    Add/Modify the \"/etc/security/faillock.conf\" file to match the following
line:

    silent
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-230341'
  tag rid: 'SV-230341r743978_rule'
  tag stig_id: 'RHEL-08-020019'
  tag fix_id: 'F-32985r743977_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  if os.release.to_f <= 8.2
    impact 0.0
    describe "The release is #{os.release}" do
      skip 'The release is lower than 8.2; this control is Not Applicable.'
    end
  else
    describe parse_config_file('/etc/security/faillock.conf') do
      its('silent') { should_not be nil }
    end
  end
end
