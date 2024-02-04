control 'SV-230373' do
  title 'RHEL 8 account identifiers (individuals, groups, roles, and devices)
    must be disabled after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications because
    attackers may exploit an inactive identifier and potentially obtain undetected
    access to the system. Owners of inactive accounts will not notice if
    unauthorized access to their user account has been obtained.

    RHEL 8 needs to track periods of inactivity and disable application
    identifiers after 35 days of inactivity.'
  desc 'check', 'Verify the account identifiers (individuals, groups, roles, and devices)
    are disabled after 35 days of inactivity with the following command:

    Check the account inactivity value by performing the following command:

        $ sudo grep -i inactive /etc/default/useradd

        INACTIVE=35

    If "INACTIVE" is set to "-1", a value greater than "35", or is
    commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to disable account identifiers after 35 days of inactivity
    after the password expiration.

    Run the following command to change the configuration for useradd:

      $ sudo useradd -D -f 35

    DoD recommendation is 35 days, but a lower value is acceptable. The value "-1" will
    disable this feature, and "0" will disable the account immediately after the
    password expires.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag gid: 'V-230373'
  tag rid: 'SV-230373r627750_rule'
  tag stig_id: 'RHEL-08-020260'
  tag fix_id: 'F-33017r567866_fix'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
  tag 'host', 'container'

  days_of_inactivity = input('days_of_inactivity')

  describe 'Useradd configuration' do
    useradd_config = parse_config_file('/etc/default/useradd')

    context 'when INACTIVE is set' do
      it 'should exist' do
        expect(useradd_config.params).to include('INACTIVE')
      end

      it 'should not be nil' do
        expect(useradd_config.params['INACTIVE']).not_to be_nil
      end

      it 'should have INACTIVE greater than or equal to 0' do
        expect(useradd_config.params['INACTIVE'].to_i).to be >= 0
      end

      it 'should have INACTIVE less than or equal to days_of_inactivity' do
        expect(useradd_config.params['INACTIVE'].to_i).to be <= days_of_inactivity
      end

      it 'should not have INACTIVE equal to -1' do
        expect(useradd_config.params['INACTIVE']).not_to eq '-1'
      end
    end
  end
end
