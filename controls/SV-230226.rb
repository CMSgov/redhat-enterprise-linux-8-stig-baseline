control 'SV-230226' do
  title "RHEL 8 must display the Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent
Banner before granting local or remote access to the system via a graphical
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

    \"#{input('banner_message_text_gui')}\"


  "
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 displays the Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent Banner
before granting access to the operating system via a graphical user logon.

    Note: This requirement assumes the use of the RHEL 8 default graphical user
interface, Gnome Shell. If the system does not have any graphical user
interface installed, this requirement is Not Applicable.

    Check that the operating system displays the exact Standard Mandatory #{input('org_name')[:acronym]}
Notice and Consent Banner text with the command:

    $ sudo grep banner-message-text /etc/dconf/db/local.d/*

    banner-message-text=
    '#{input('banner_message_text_gui')}'

    Note: The \"\
     \" characters are for formatting only. They will not be displayed on the
graphical interface.

    If the banner does not match the Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent
Banner exactly, this is a finding.
  "
  desc  'fix', "
    Configure the operating system to display the Standard Mandatory #{input('org_name')[:acronym]} Notice
and Consent Banner before granting access to the system.

    Note: If the system does not have a graphical user interface installed,
this requirement is Not Applicable.

    Add the following lines to the [org/gnome/login-screen] section of the
\"/etc/dconf/db/local.d/01-banner-message\":

    banner-message-text='#{input('banner_message_text_gui')}'

    Note: The \"\
     \" characters are for formatting only. They will not be displayed on the
graphical interface.

    Run the following command to update the database:

    $ sudo dconf update
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag gid: 'V-230226'
  tag rid: 'SV-230226r743916_rule'
  tag stig_id: 'RHEL-08-010050'
  tag fix_id: 'F-32870r743915_fix'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']

  banner_message_text_gui = input('banner_message_text_gui')

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    if package('gnome-desktop3').installed?
      describe command('grep ^banner-message-text /etc/dconf/db/local.d/*') do
        its('stdout.strip') { should cmp banner_message_text_gui }
      end
    else
      impact 0.0
      describe 'The system does not have GNOME installed' do
        skip "The system does not have GNOME installed, this requirement is Not
        Applicable."
      end
    end
  end
end
