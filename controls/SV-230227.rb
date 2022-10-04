control 'SV-230227' do
  title "RHEL 8 must display the Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent
Banner before granting local or remote access to the system via a command line
user logon."
  desc  "Display of a standardized and approved use notification before
granting access to the operating system ensures privacy and security
notification verbiage used is consistent with applicable federal laws,
Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces
with human users and are not required when such human interfaces do not exist.

    The banner must be formatted in accordance with applicable #{input('org_name')[:acronym]} policy. Use
the following verbiage for operating systems that can accommodate banners of
1300 characters:

    \"#{input('banner_message_text_cli')}\"


  "
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 displays the Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent Banner
before granting access to the operating system via a command line user logon.

    Check that RHEL 8 displays a banner at the command line login screen with
the following command:

    $ sudo cat /etc/issue

    If the banner is set correctly it will return the following text:

    “#{input('banner_message_text_cli')}”

    If the banner text does not match the Standard Mandatory #{input('org_name')[:acronym]} Notice and
Consent Banner exactly, this is a finding.
  "
  desc 'fix', "
    Configure RHEL 8 to display the Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent
Banner before granting access to the system via command line logon.

    Edit the \"/etc/issue\" file to replace the default text with the Standard
Mandatory #{input('org_name')[:acronym]} Notice and Consent Banner. The #{input('org_name')[:acronym]}-required text is:

    \"#{input('banner_message_text_cli')}\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: %w(SRG-OS-000023-GPOS-00006 SRG-OS-000228-GPOS-00088)
  tag gid: 'V-230227'
  tag rid: 'SV-230227r627750_rule'
  tag stig_id: 'RHEL-08-010060'
  tag fix_id: 'F-32871r567428_fix'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']

  banner_message_text_cli = input('banner_message_text_cli')

  clean_banner = banner_message_text_cli.gsub(/[\r\n\s]/, '')
  banner_file = file('/etc/issue')
  banner_missing = !banner_file.exist?

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe 'The banner text is not set because /etc/issue does not exist' do
        subject { banner_missing }
        it { should be false }
      end if banner_missing
    
      banner_message = banner_file.content.gsub(/[\r\n\s]/, '')
    
      describe 'The banner text should match the standard banner' do
        subject { banner_message }
        it { should cmp clean_banner }
      end unless banner_missing
  end
end
