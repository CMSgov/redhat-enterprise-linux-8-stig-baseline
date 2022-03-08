control 'SV-230530' do
  title "The x86 Ctrl-Alt-Delete key sequence in RHEL 8 must be disabled if a
graphical user interface is installed."
  desc  "A locally logged-on user, who presses Ctrl-Alt-Delete, when at the
console, can reboot the system. If accidentally pressed, as could happen in the
case of a mixed OS environment, this can create the risk of short-term loss of
availability of systems due to unintentional reboot. In a graphical user
environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is
reduced because the user will be prompted before any action is taken."
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 is not configured to reboot the system when Ctrl-Alt-Delete
is pressed when using a graphical user interface with the following command:

    This requirement assumes the use of the RHEL 8 default graphical user
interface, Gnome Shell. If the system does not have any graphical user
interface installed, this requirement is Not Applicable.

    $ sudo grep logout /etc/dconf/db/local.d/*

    logout=''

    If the \"logout\" key is bound to an action, is commented out, or is
missing, this is a finding.
  "
  desc 'fix', "
    Configure the system to disable the Ctrl-Alt-Delete sequence when using a
graphical user interface by creating or editing the
/etc/dconf/db/local.d/00-disable-CAD file.

    Add the setting to disable the Ctrl-Alt-Delete sequence for a graphical
user interface:

    [org/gnome/settings-daemon/plugins/media-keys]
    logout=''

    Note: The value above is set to two single quotations.

    Then update the dconf settings:

    $ sudo dconf update
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230530'
  tag rid: 'SV-230530r646883_rule'
  tag stig_id: 'RHEL-08-040171'
  tag fix_id: 'F-33174r568337_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    if package('gnome-desktop3').installed?
      describe command('grep logout /etc/dconf/db/local.d/*') do
        its('stdout.strip') { should cmp "logout=''" }
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
