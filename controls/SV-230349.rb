control 'SV-230349' do
  title 'RHEL 8 must ensure session control is automatically started at shell
initialization.'
  desc 'Tmux is a terminal multiplexer that enables a number of terminals to be created, accessed, and controlled from a single screen. Red Hat endorses tmux as the recommended session controlling package.'
  desc 'check', 'Verify the operating system shell initialization file is configured to start each shell with the tmux terminal multiplexer with the following commands:

Determine if tmux is currently running:
     $ sudo ps all | grep tmux | grep -v grep

If the command does not produce output, this is a finding.
 
Determine the location of the tmux script:
     $ sudo grep -r tmux /etc/bashrc /etc/profile.d

     /etc/profile.d/tmux.sh:  case "$name" in (sshd|login) tmux ;; esac

Review the tmux script by using the following example:
     $ sudo cat /etc/profile.d/tmux.sh

if [ "$PS1" ]; then
parent=$(ps -o ppid= -p $$)
name=$(ps -o comm= -p $parent)
case "$name" in (sshd|login) tmux ;; esac
fi

If "tmux" is not configured as the example above, is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure the operating system to initialize the tmux terminal multiplexer as each shell is called by adding the following lines to a custom.sh shell script in the /etc/profile.d/ directory:

if [ "$PS1" ]; then
parent=$(ps -o ppid= -p $$)
name=$(ps -o comm= -p $parent)
case "$name" in (sshd|login) tmux ;; esac
fi

This setting will take effect at next logon.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag gid: 'V-230349'
  tag rid: 'SV-230349r917920_rule'
  tag stig_id: 'RHEL-08-020041'
  tag fix_id: 'F-32993r880735_fix'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe command('grep -i tmux /etc/bashrc') do
      its('stdout.strip') { should cmp '[ -n "$PS1" -a -z "$TMUX" ] && exec tmux' }
    end
  end
end
