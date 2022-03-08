control 'SV-230268' do
  title "RHEL 8 must enable kernel parameters to enforce discretionary access
control on hardlinks."
  desc  "Discretionary Access Control (DAC) is based on the notion that
individual users are \"owners\" of objects and therefore have discretion over
who should be authorized to access the object and in which mode (e.g., read or
write). Ownership is usually acquired as a consequence of creating the object
or via specified ownership assignment. DAC allows the owner to determine who
will have access to objects they control. An example of DAC includes
user-controlled file permissions.

    When discretionary access control policies are implemented, subjects are
not constrained with regard to what actions they can take with information for
which they have already been granted access. Thus, subjects that have been
granted access to information are not prevented from passing (i.e., the
subjects have the discretion to pass) the information to other subjects or
objects. A subject that is constrained in its operation by Mandatory Access
Control policies is still able to operate under the less rigorous constraints
of this requirement. Thus, while Mandatory Access Control imposes constraints
preventing a subject from passing information to another subject operating at a
different sensitivity level, this requirement permits the subject to pass the
information to any subject at the same sensitivity level. The policy is bounded
by the information system boundary. Once the information is passed outside the
control of the information system, additional means may be required to ensure
the constraints remain in effect. While the older, more traditional definitions
of discretionary access control require identity-based access control, that
limitation is not required for this use of discretionary access control.

    By enabling the fs.protected_hardlinks kernel parameter, users can no
longer create soft or hard links to files they do not own. Disallowing such
hardlinks mitigate vulnerabilities based on insecure file system accessed by
privileged programs, avoiding an exploitation vector exploiting unsafe use of
open() or creat().


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system is configured to enable DAC on hardlinks with
the following commands:

    Check the status of the fs.protected_hardlinks kernel parameter.

    $ sudo sysctl fs.protected_hardlinks

    fs.protected_hardlinks = 1

    If \"fs.protected_hardlinks\" is not set to \"1\" or is missing, this is a
finding.

    Check that the configuration files are present to enable this kernel
parameter.

    $ sudo grep -r fs.protected_hardlinks /etc/sysctl.conf /etc/sysctl.d/*.conf

    /etc/sysctl.d/99-sysctl.conf:fs.protected_hardlinks = 1

    If \"fs.protected_hardlinks\" is not set to \"1\", is missing or commented
out, this is a finding.
  "
  desc 'fix', "
    Configure the operating system to enable DAC on hardlinks.

    Add or edit the following line in a system configuration file in the
\"/etc/sysctl.d/\" directory:

    fs.protected_hardlinks = 1

    Load settings from all system configuration files with the following
command:

    $ sudo sysctl --system
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000312-GPOS-00122'
  tag satisfies: %w(SRG-OS-000312-GPOS-00122 SRG-OS-000312-GPOS-00123
                    SRG-OS-000312-GPOS-00124 SRG-OS-000324-GPOS-00125)
  tag gid: 'V-230268'
  tag rid: 'SV-230268r627750_rule'
  tag stig_id: 'RHEL-08-010374'
  tag fix_id: 'F-32912r567551_fix'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe kernel_parameter('fs.protected_hardlinks') do
      its('value') { should eq 1 }
    end
  
    describe command('grep -r ^fs.protected_hardlinks /etc/sysctl.conf /etc/sysctl.d/*.conf') do
      its('stdout') { should match /fs.protected_hardlinks=1$/ }
    end
  end
end
