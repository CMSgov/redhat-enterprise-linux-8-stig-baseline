control 'SV-230546' do
  title 'RHEL 8 must restrict usage of ptrace to descendant  processes.'
  desc  "It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors."
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 restricts usage of ptrace to descendant processes with the
following commands:

    $ sudo sysctl kernel.yama.ptrace_scope

    kernel.yama.ptrace_scope = 1

    If the returned line does not have a value of \"1\", or a line is not
returned, this is a finding.
  "
  desc 'fix', "
    Configure RHEL 8 to restrict usage of ptrace to descendant processes by
adding the following line to a file in the \"/etc/sysctl.d\" directory:

    kernel.yama.ptrace_scope = 1

    The system configuration files need to be reloaded for the changes to take
effect. To reload the contents of the files, run the following command:

    $ sudo sysctl --system
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230546'
  tag rid: 'SV-230546r627750_rule'
  tag stig_id: 'RHEL-08-040282'
  tag fix_id: 'F-33190r568385_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe kernel_parameter('kernel.yama.ptrace_scope') do
      its('value') { should eq 1 }
    end
  end
end
