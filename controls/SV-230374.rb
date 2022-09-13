control 'SV-230374' do
  title "RHEL 8 emergency accounts must be automatically removed or disabled
after the crisis is resolved or within #{input('temp_account_expire_time')[:hours]} hours."
  desc  "Emergency accounts are privileged accounts established in response to
crisis situations where the need for rapid account activation is required.
Therefore, emergency account activation may bypass normal account authorization
processes. If these accounts are automatically disabled, system maintenance
during emergencies may not be possible, thus adversely affecting system
availability.

    Emergency accounts are different from infrequently used accounts (i.e.,
local logon accounts used by the organization's system administrators when
network or normal logon/access is not available). Infrequently used accounts
are not subject to automatic termination dates. Emergency accounts are accounts
created in response to crisis situations, usually for use by maintenance
personnel. The automatic expiration or disabling time period may be extended as
needed until the crisis is resolved; however, it must not be extended
indefinitely. A permanent account should be established for privileged users
who need long-term maintenance accounts.

    To address access requirements, many RHEL 8 systems can be integrated with
enterprise-level authentication/access mechanisms that meet or exceed access
control policy requirements.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify emergency accounts have been provisioned with an expiration date of
    #{input('temp_account_expire_time')[:hours]} hours.

    For every existing emergency account, run the following command to obtain
its account expiration information.

    $ sudo chage -l system_account_name

    Verify each of these accounts has an expiration date set within #{input('temp_account_expire_time')[:hours]} hours.
    If any emergency accounts have no expiration date set or do not expire
within #{input('temp_account_expire_time')[:hours]} hours, this is a finding.
  "
  desc 'fix', "
    If an emergency account must be created, configure the system to terminate
the account after #{input('temp_account_expire_time')[:hours]} hours with the following command to set an expiration date
for the account. Substitute \"system_account_name\" with the account to be
created.

    $ sudo chage -E `date -d \"+#{input('temp_account_expire_time')[:days]} days\" +%Y-%m-%d` system_account_name

    The automatic expiration or disabling time period may be extended as needed
until the crisis is resolved.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag gid: 'V-230374'
  tag rid: 'SV-230374r627750_rule'
  tag stig_id: 'RHEL-08-020270'
  tag fix_id: 'F-33018r567869_fix'
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']

  temporary_accounts = input('temporary_accounts')
  max_day = input('temp_account_expire_time')[:days]

  if temporary_accounts.empty?
    describe 'Temporary accounts' do
      subject { temporary_accounts }
      it { should be_empty }
    end
  else
    temporary_accounts.each do |acct|
      describe user(acct.to_s) do
        its('maxdays') { should cmp <= max_day }
        its('maxdays') { should cmp > 0 }
      end
    end
  end
end
