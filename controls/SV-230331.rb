control 'SV-230331' do
  title "RHEL 8 temporary user accounts must be provisioned with an expiration
time of 72 hours or less."
  desc  "If temporary user accounts remain active when no longer needed or for
an excessive period, these accounts may be used to gain unauthorized access. To
mitigate this risk, automated termination of all temporary accounts must be set
upon account creation.

    Temporary accounts are established as part of normal account activation
procedures when there is a need for short-term accounts without the demand for
immediacy in account activation.

    If temporary accounts are used, RHEL 8 must be configured to automatically
terminate these types of accounts after a DoD-defined time period of 72 hours.

    To address access requirements, many RHEL 8 operating systems may be
integrated with enterprise-level authentication/access mechanisms that meet or
exceed access control policy requirements.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that temporary accounts have been provisioned with an expiration
date of 72 hours.

    For every existing temporary account, run the following command to obtain
its account expiration information.

    $ sudo chage -l system_account_name

    Verify each of these accounts has an expiration date set within 72 hours.

    If any temporary accounts have no expiration date set or do not expire
within 72 hours, this is a finding.
  "
  desc 'fix', "
    If a temporary account must be created configure the system to terminate
the account after a 72 hour time period with the following command to set an
expiration date on it. Substitute \"system_account_name\" with the account to
be created.

    $ sudo chage -E `date -d \"+3 days\" +%Y-%m-%d` system_account_name
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag gid: 'V-230331'
  tag rid: 'SV-230331r627750_rule'
  tag stig_id: 'RHEL-08-020000'
  tag fix_id: 'F-32975r567740_fix'
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']

  temporary_accounts = input('temporary_accounts')

  if temporary_accounts.empty?
    describe 'Temporary accounts' do
      subject { temporary_accounts }
      it { should be_empty }
    end
  else
    temporary_accounts.each do |acct|
      describe user(acct.to_s) do
        its('maxdays') { should cmp <= 3 }
        its('maxdays') { should cmp > 0 }
      end
    end
  end
end
