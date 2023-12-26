# frozen_string_literal: true

control 'SV-230374' do
  title 'RHEL 8 must automatically expire temporary accounts within 72 hours.'
<<<<<<< HEAD
  desc 'Temporary accounts are privileged or nonprivileged accounts that are
    established during pressing circumstances, such as new software or hardware
    configuration or an incident response, where the need for prompt account
    activation requires bypassing normal account authorization procedures.

    If any inactive temporary accounts are left enabled on the system and are
    not either manually removed or automatically expired within 72 hours, the
    security posture of the system will be degraded and exposed to exploitation
    by unauthorized users or insider threat actors.

    Temporary accounts are different from emergency accounts. Emergency accounts,
    also known as "last resort" or "break glass" accounts, are local logon accounts
    enabled on the system for emergency use by authorized system administrators
    to manage a system when standard logon methods are failing or not available.

    Emergency accounts are not subject to manual removal or scheduled expiration
    requirements.

    The automatic expiration of temporary accounts may be extended as needed by
    the circumstances but it must not be extended indefinitely. A documented
    permanent account should be established for privileged users who need long-term
    maintenance accounts.'

  desc 'check', 'Verify temporary accounts have been provisioned with an
    expiration date of 72 hours.

    For every existing temporary account, run the following command to obtain its
    account expiration information:

    $ sudo chage -l <temporary_account_name> | grep -i "account expires"

    Verify each of these accounts has an expiration date set within 72 hours.

    If any temporary accounts have no expiration date set or do not expire within
    72 hours, this is a finding.'

  desc 'fix', "Configure the operating system to expire temporary accounts after
    72 hours with the following command:

    $ sudo chage -E $(date -d +3days +%Y-%m-%d) <temporary_account_name>"

=======
  desc 'Temporary accounts are privileged or nonprivileged accounts that are established during pressing circumstances, such as new software or hardware configuration or an incident response, where the need for prompt account activation requires bypassing normal account authorization procedures. If any inactive temporary accounts are left enabled on the system and are not either manually removed or automatically expired within 72 hours, the security posture of the system will be degraded and exposed to exploitation by unauthorized users or insider threat actors.

Temporary accounts are different from emergency accounts. Emergency accounts, also known as "last resort" or "break glass" accounts, are local logon accounts enabled on the system for emergency use by authorized system administrators to manage a system when standard logon methods are failing or not available. Emergency accounts are not subject to manual removal or scheduled expiration requirements.

The automatic expiration of temporary accounts may be extended as needed by the circumstances but it must not be extended indefinitely. A documented permanent account should be established for privileged users who need long-term maintenance accounts.'
  desc 'check', 'Verify temporary accounts have been provisioned with an expiration date of 72 hours.

For every existing temporary account, run the following command to obtain its account expiration information:

     $ sudo chage -l <temporary_account_name> | grep -i "account expires"

Verify each of these accounts has an expiration date set within 72 hours.
If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding.'
  desc 'fix', 'Configure the operating system to expire temporary accounts after 72 hours with the following command:

     $ sudo chage -E $(date -d +3days +%Y-%m-%d) <temporary_account_name>'
>>>>>>> 87a05e3c31795238f35c7bb155a9770db9a9c15c
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag gid: 'V-230374'
  tag rid: 'SV-230374r903129_rule'
  tag stig_id: 'RHEL-08-020270'
  tag fix_id: 'F-33018r902730_fix'
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']

  temp_accounts = input('temporary_accounts')

  if temp_accounts.empty?
    describe 'Temporary accounts' do
      it 'should be empty' do
        expect(temp_accounts).to be_empty
      end
    end
  else
    temp_accounts.each do |acct|
      context "User #{acct}" do
        it 'should have maxdays less than or equal to 3' do
          expect(user(acct.to_s).maxdays).to be <= 3
        end

        it 'should have maxdays greater than 0' do
          expect(user(acct.to_s).maxdays).to be > 0
        end
      end
    end
  end
end
