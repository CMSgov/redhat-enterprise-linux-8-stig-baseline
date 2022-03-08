control 'SV-244554' do
  title "RHEL 8 must enable hardening for the Berkeley Packet Filter
Just-in-time compiler."
  desc  "It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.
    Enabling hardening for the Berkeley Packet Filter (BPF) Just-in-time (JIT)
compiler aids in mitigating JIT spraying attacks.  Setting the value to \"2\"
enables JIT hardening for all users.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 enables hardening for the BPF JIT with the following commands:

    $ sudo sysctl net.core.bpf_jit_harden

    net.core.bpf_jit_harden = 2

    If the returned line does not have a value of \"2\", or a line is not
returned, this is a finding.
  "
  desc  'fix', "
    Configure RHEL 8 to enable hardening for the BPF JIT compiler by adding the
following line to a file in the \"/etc/sysctl.d\" directory:

    net.core.bpf_jit_harden = 2

    The system configuration files need to be reloaded for the changes to take
effect. To reload the contents of the files, run the following command:

    $ sudo sysctl --system
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-244554'
  tag rid: 'SV-244554r743911_rule'
  tag stig_id: 'RHEL-08-040286'
  tag fix_id: 'F-47786r743910_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe kernel_parameter('net.core.bpf_jit_harden') do
      its('value') { should eq 2 }
    end
  end
end

