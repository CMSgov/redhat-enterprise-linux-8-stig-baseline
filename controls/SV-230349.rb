control 'SV-230349' do
  title "RHEL 8 must ensure session control is automatically started at shell
initialization."
  desc  "A session lock is a temporary action taken when a user stops work and
moves away from the immediate physical vicinity of the information system but
does not want to log out because of the temporary nature of the absence.

    The session lock is implemented at the point where session activity can be
determined. Rather than be forced to wait for a period of time to expire before
the user session can be locked, RHEL 8 needs to provide users with the ability
to manually invoke a session lock so users can secure their session if it is
necessary to temporarily vacate the immediate physical vicinity.

    Tmux is a terminal multiplexer that enables a number of terminals to be
created, accessed, and controlled from a single screen.  Red Hat endorses tmux
as the recommended session controlling package.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system shell initialization file is configured to
start each shell with the tmux terminal multiplexer with the following command:

    $ sudo grep -i tmux /etc/bashrc

    [ -n \"$PS1\" -a -z \"$TMUX\" ] && exec tmux

    If \"tmux\" is not configured as the example above, is commented out, or
missing from the \"/etc/bashrc\" initialization file, this is a finding.
  "
  desc 'fix', "
    Configure the operating system to initialize the tmux terminal multiplexer
as each shell is called by adding the following line to the end of the
\"/etc/bashrc\" configuration file:

    [ -n \"$PS1\" -a -z \"$TMUX\" ] && exec tmux

    This setting will take effect at next logon.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag satisfies: %w(SRG-OS-000028-GPOS-00009 SRG-OS-000030-GPOS-00011)
  tag gid: 'V-230349'
  tag rid: 'SV-230349r627750_rule'
  tag stig_id: 'RHEL-08-020041'
  tag fix_id: 'F-32993r567794_fix'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe command('grep -i tmux /etc/bashrc') do
      its('stdout.strip') { should cmp '[ -n "$PS1" -a -z "$TMUX" ] && exec tmux' }
    end
  end
end
