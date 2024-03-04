control 'SV-230331' do
  title 'RHEL 8 temporary user accounts must be provisioned with an expiration
time of 72 hours or less.'
  desc 'If temporary user accounts remain active when no longer needed or for
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
exceed access control policy requirements.'
  desc 'check', 'Verify that temporary accounts have been provisioned with an expiration
date of 72 hours.

    For every existing temporary account, run the following command to obtain
its account expiration information.

    $ sudo chage -l system_account_name

    Verify each of these accounts has an expiration date set within 72 hours.

    If any temporary accounts have no expiration date set or do not expire
within 72 hours, this is a finding.'
  desc 'fix', 'If a temporary account must be created configure the system to terminate
the account after a 72 hour time period with the following command to set an
expiration date on it. Substitute "system_account_name" with the account to
be created.

    $ sudo chage -E `date -d "+3 days" +%Y-%m-%d` system_account_name'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag gid: 'V-230331'
  tag rid: 'SV-230331r627750_rule'
  tag stig_id: 'RHEL-08-020000'
  tag fix_id: 'F-32975r567740_fix'
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
  tag 'host', 'container'

  tmp_users = input('temporary_accounts')
  tmp_max_days = input('temporary_account_max_days')

  if tmp_users.empty?
    describe 'Temporary accounts' do
      subject { tmp_users }
      it { should be_empty }
    end
  else
    # user has to specify what the tmp accounts are, so we will print a different pass message
    # if none of those tmp accounts even exist on the system for clarity
    tmp_users_existing = tmp_users.select { |u| user(u).exists? }
    failing_users = tmp_users_existing.select { |u| user(u).maxdays > tmp_max_days }

    describe 'Temporary accounts' do
      if tmp_users_existing.nil?
        it "should have expiration times less than or equal to '#{tmp_max_days}' days" do
          expect(failing_users).to be_empty, "Failing users:\n\t- #{failing_users.join("\n\t- ")}"
        end
      else
        it "(input as '#{tmp_users.join("', '")}') were not found on this system" do
          expect(tmp_users_existing).to be_empty
        end
      end
    end
  end
end
