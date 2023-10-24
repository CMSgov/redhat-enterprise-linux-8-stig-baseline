control 'SV-230554' do
  title 'RHEL 8 network interfaces must not be in promiscuous mode.'
  desc 'Network interfaces in promiscuous mode allow for the capture of all
network traffic visible to the system. If unauthorized individuals can access
these applications, it may allow them to collect information such as logon IDs,
passwords, and key exchanges between systems.

    If the system is being used to perform a network troubleshooting function,
the use of these tools must be documented with the Information System Security
Officer (ISSO) and restricted to only authorized personnel.'
  desc 'check', 'Verify network interfaces are not in promiscuous mode unless approved by
the ISSO and documented.

    Check for the status with the following command:

    $ sudo ip link | grep -i promisc

    If network interfaces are found on the system in promiscuous mode and their
use has not been approved by the ISSO and documented, this is a finding.'
  desc 'fix', 'Configure network interfaces to turn off promiscuous mode unless approved
by the ISSO and documented.

    Set the promiscuous mode of an interface to off with the following command:

    $ sudo ip link set dev <devicename> multicast off promisc off'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230554'
  tag rid: 'SV-230554r627750_rule'
  tag stig_id: 'RHEL-08-040330'
  tag fix_id: 'F-33198r568409_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe command('ip link | grep -i promisc') do
      its('stdout.strip') { should match /^$/ }
    end
  end
end
