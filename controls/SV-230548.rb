control 'SV-230548' do
  title 'RHEL 8 must disable the use of user namespaces.'
  desc  "It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    User namespaces are used primarily for Linux container.  The value 0
disallows the use of user namespaces.  When containers are not in use,
namespaces should be disallowed.  When containers are deployed on a system, the
value should be set to a large non-zero value.  The default value is 7182.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 disables the use of user namespaces with the following
commands:

    Note: User namespaces are used primarily for Linux containers.  If
containers are in use, this requirement is not applicable.

    $ sudo sysctl user.max_user_namespaces

    user.max_user_namespaces = 0

    If the returned line does not have a value of \"0\", or a line is not
returned, this is a finding.
  "
  desc 'fix', "
    Configure RHEL 8 to disable the use of user namespaces by adding the
following line to a file in the \"/etc/sysctl.d\" directory:

    Note: User namespaces are used primarily for Linux containers.  If
containers are in use, this requirement is not applicable.

    user.max_user_namespaces = 0

    The system configuration files need to be reloaded for the changes to take
effect. To reload the contents of the files, run the following command:

    $ sudo sysctl --system
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230548'
  tag rid: 'SV-230548r627750_rule'
  tag stig_id: 'RHEL-08-040284'
  tag fix_id: 'F-33192r568391_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  container_host = input('container_host')

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    if container_host
      impact 0.0
      describe true do
        skip 'Profile running on a container host -- User namespaces are used primarily for Linux containers.; this control is Not Applicable'
      end
    else
      describe kernel_parameter('user.max_user_namespaces') do
        its('value') { should eq 0 }
      end
    end
  end
end
