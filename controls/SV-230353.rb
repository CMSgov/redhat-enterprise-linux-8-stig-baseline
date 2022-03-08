control 'SV-230353' do
  title "RHEL 8 must automatically lock command line user sessions after 15
minutes of inactivity."
  desc  "Terminating an idle session within a short time period reduces the
window of opportunity for unauthorized personnel to take control of a
management session enabled on the console or console port that has been left
unattended. In addition, quickly terminating an idle session will also free up
resources committed by the managed network element.

    Terminating network connections associated with communications sessions
includes, for example, de-allocating associated TCP/IP address/port pairs at
the operating system level and de-allocating networking assignments at the
application level if multiple application sessions are using a single operating
system-level network connection. This does not mean the operating system
terminates all sessions or network access; it only ends the inactive session
and releases the resources associated with that session.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system initiates a session lock after 15 minutes of
inactivity.

    Check the value of the system inactivity timeout with the following command:

    $ sudo grep -i lock-after-time /etc/tmux.conf

    set -g lock-after-time 900

    If \"lock-after-time\" is not set to \"900\" or less in the global tmux
configuration file to enforce session lock after inactivity, this is a finding.
  "
  desc 'fix', "
    Configure the operating system to enforce session lock after a period of 15
minutes of inactivity by adding the following line to the \"/etc/tmux.conf\"
global configuration file:

    set -g lock-after-time 900
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag satisfies: %w(SRG-OS-000029-GPOS-00010 SRG-OS-000031-GPOS-00012)
  tag gid: 'V-230353'
  tag rid: 'SV-230353r627750_rule'
  tag stig_id: 'RHEL-08-020070'
  tag fix_id: 'F-32997r567806_fix'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']

  system_inactivity_timeout = input('system_inactivity_timeout')

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe command("grep -i lock-after-time /etc/tmux.conf | cut -d ' ' -f4") do
      its('stdout.strip') { should cmp <= system_inactivity_timeout }
    end
  end
end
