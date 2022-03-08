control 'SV-230512' do
  title 'RHEL 8 must mount /tmp with the nosuid option.'
  desc  "The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The \"noexec\" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.
    The \"nodev\" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.
    The \"nosuid\" mount option causes the system to not execute \"setuid\" and
\"setgid\" files with owner privileges. This option must be used for mounting
any file system not containing approved \"setuid\" and \"setguid\" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify \"/tmp\" is mounted with the \"nosuid\" option:

    $ sudo mount | grep /tmp

    /dev/mapper/rhel-tmp on /tmp type xfs (rw,nodev,nosuid,noexec,seclabel)

    Verify that the \"nosuid\" option is configured for /tmp:

    $ sudo cat /etc/fstab | grep /tmp

    /dev/mapper/rhel-tmp /tmp xfs defaults,nodev,nosuid,noexec 0 0

    If results are returned and the \"nosuid\" option is missing, or if /tmp is
mounted without the \"nosuid\" option, this is a finding.
  "
  desc 'fix', "
    Configure the system so that /tmp is mounted with the \"nosuid\" option by
adding /modifying the /etc/fstab with the following line:

    /dev/mapper/rhel-tmp /tmp xfs defaults,nodev,nosuid,noexec 0 0
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-230512'
  tag rid: 'SV-230512r627750_rule'
  tag stig_id: 'RHEL-08-040124'
  tag fix_id: 'F-33156r568283_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe etc_fstab.where { mount_point == '/tmp' } do
      its('mount_options.flatten') { should include 'nosuid' }
    end
  end
end
