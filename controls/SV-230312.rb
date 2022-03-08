control 'SV-230312' do
  title 'RHEL 8 must disable acquiring, saving, and processing core dumps.'
  desc  "It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    A core dump includes a memory image taken at the time the operating system
terminates an application. The memory image could contain sensitive data and is
generally useful only for developers trying to debug problems.

    When the kernel invokes systemd-coredumpt to handle a core dump, it runs in
privileged mode, and will connect to the socket created by the
systemd-coredump.socket unit. This, in turn,  will spawn an unprivileged
systemd-coredump@.service instance to process the core dump.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 is not configured to acquire, save, or process core dumps
with the following command:

    $ sudo systemctl status systemd-coredump.socket

    systemd-coredump.socket
    Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)
    Active: inactive (dead)

    If the \"systemd-coredump.socket\" is loaded and not masked and the need
for core dumps is not documented with the Information System Security Officer
(ISSO) as an operational requirement, this is a finding.
  "
  desc 'fix', "
    Configure the system to disable the systemd-coredump.socket with the
following command:

    $ sudo systemctl mask systemd-coredump.socket

    Created symlink /etc/systemd/system/systemd-coredump.socket -> /dev/null

    Reload the daemon for this change to take effect.

    $ sudo systemctl daemon-reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230312'
  tag rid: 'SV-230312r627750_rule'
  tag stig_id: 'RHEL-08-010672'
  tag fix_id: 'F-32956r619859_fix'
  tag cci: ['CCI-000366']
  tag legacy: []
  tag nist: ['CM-6 b']

  s = systemd_service('systemd-coredump.socket')

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe.one do
      describe s do
        its('params.LoadState') { should eq 'masked' }
      end
      describe s do
        its('params.LoadState') { should eq 'not-found' }
      end
    end
  end
end
