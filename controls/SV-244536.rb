control 'SV-244536' do
  title "RHEL 8 must disable the user list at logon for graphical user
interfaces."
  desc  "Leaving the user list enabled is a security risk since it allows
anyone with physical access to the system to enumerate known user accounts
without authenticated access to the system."
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system disables the user logon list for graphical user
interfaces with the following command:
    Note: This requirement assumes the use of the RHEL 8 default graphical user
interface, Gnome Shell. If the system does not have any graphical user
interface installed, this requirement is Not Applicable.

    $ sudo gsettings get org.gnome.login-screen disable-user-list
    true

    If the setting is \"false\", this is a finding.
  "
  desc  'fix', "
    Configure the operating system to disable the user list at logon for
graphical user interfaces.

    Create a database to contain the system-wide screensaver settings (if it
does not already exist) with the following command:
    Note: The example below is using the database \"local\" for the system, so
if the system is using another database in \"/etc/dconf/profile/user\", the
file should be created under the appropriate subdirectory.

    $ sudo touch /etc/dconf/db/local.d/02-login-screen

    [org/gnome/login-screen]
    disable-user-list=true

    Update the system databases:
    $ sudo dconf update
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-244536'
  tag rid: 'SV-244536r743857_rule'
  tag stig_id: 'RHEL-08-020032'
  tag fix_id: 'F-47768r743856_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    if package('gnome-desktop3').installed?
      describe command('gsettings get org.gnome.login-screen disable-user-list') do
        its('stdout.strip') { should cmp 'true' }
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

