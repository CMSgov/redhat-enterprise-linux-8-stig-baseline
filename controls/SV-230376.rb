control 'SV-230376' do
  title 'RHEL 8 must prohibit the use of cached authentications after one day.'
  desc  "If cached authentication information is out-of-date, the validity of
the authentication information may be questionable.

    RHEL 8 includes multiple options for configuring authentication, but this
requirement will be focus on the System Security Services Daemon (SSSD). By
default sssd does not cache credentials.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that the SSSD prohibits the use of cached authentications after one
day.

    Note: If smart card authentication is not being used on the system this
item is Not Applicable.

    Check that SSSD allows cached authentications with the following command:

    $ sudo grep cache_credentials /etc/sssd/sssd.conf

    cache_credentials = true

    If \"cache_credentials\" is set to \"false\" or missing from the
configuration file, this is not a finding and no further checks are required.

    If \"cache_credentials\" is set to \"true\", check that SSSD prohibits the
use of cached authentications after one day with the following command:

    $ sudo grep offline_credentials_expiration  /etc/sssd/sssd.conf

    offline_credentials_expiration = 1

    If \"offline_credentials_expiration\" is not set to a value of \"1\", this
is a finding.
  "
  desc 'fix', "
    Configure the SSSD to prohibit the use of cached authentications after one
day.

    Add or change the following line in \"/etc/sssd/sssd.conf\" just below the
line \"[pam]\".

    offline_credentials_expiration = 1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag gid: 'V-230376'
  tag rid: 'SV-230376r627750_rule'
  tag stig_id: 'RHEL-08-020290'
  tag fix_id: 'F-33020r567875_fix'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']

  sssd_config = parse_config_file('/etc/sssd/sssd.conf')

  if virtualization.system.eql?('docker') && sssd_config.content == nil
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    if input('smart_card_status')
      describe.one do
        describe 'Cache credentials enabled' do
          subject { sssd_config.content }
          it { should_not match /cache_credentials\s*=\s*true/ }
        end
        describe 'Offline credentials expiration' do
          subject { sssd_config }
          its('pam.offline_credentials_expiration') { should cmp '1' }
        end
      end
    else
      impact 0.0
      describe 'The system is not utilizing smart card authentication' do
        skip 'The system is not utilizing smart card authentication, this control is Not Applicable.'
      end
    end
  end
end
