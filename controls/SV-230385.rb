control 'SV-230385' do
  title 'RHEL 8 must define default permissions for logon and non-logon shells.'
  desc  "The umask controls the default access mode assigned to newly created
files. A umask of 077 limits new files to mode 600 or less permissive. Although
umask can be represented as a four-digit number, the first digit representing
special access modes is typically ignored or required to be \"0\". This
requirement applies to the globally configured system defaults and the local
interactive user defaults for each account on the system."
  desc  'rationale', ''
  desc  'check', "
    Verify that the umask default for installed shells is \"077\".

    Check for the value of the \"UMASK\" parameter in the \"/etc/bashrc\" and
\"/etc/csh.cshrc\" files with the following command:

    Note: If the value of the \"UMASK\" parameter is set to \"000\" in either
the \"/etc/bashrc\" or the \"/etc/csh.cshrc\" files, the Severity is raised to
a CAT I.

    # grep -i umask /etc/bashrc /etc/csh.cshrc

    /etc/bashrc:          umask 077
    /etc/bashrc:          umask 077
    /etc/csh.cshrc:      umask 077
    /etc/csh.cshrc:      umask 077

    If the value for the \"UMASK\" parameter is not \"077\", or the \"UMASK\"
parameter is missing or is commented out, this is a finding.
  "
  desc 'fix', "
    Configure the operating system to define default permissions for all
authenticated users in such a way that the user can only read and modify their
own files.

    Add or edit the lines for the \"UMASK\" parameter in the \"/etc/bashrc\"
and \"etc/csh.cshrc\" files to \"077\":

    UMASK 077
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230385'
  tag rid: 'SV-230385r627750_rule'
  tag stig_id: 'RHEL-08-020353'
  tag fix_id: 'F-33029r567902_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  umask_regexp = /umask\s*(?<umask_code>\d\d\d)/

  bashrc_umask = file('/etc/bashrc').content.match(umask_regexp)[:umask_code]
  cshrc_umask = file('/etc/csh.cshrc').content.match(umask_regexp)[:umask_code]

  if bashrc_umask == '000' || cshrc_umask == '000'
    impact 0.7
    tag severity: 'high'
  end

  describe 'umask value defined in /etc/bashrc' do
    subject { bashrc_umask }
    it { should cmp '077' }
  end
  describe 'umask value defined in /etc/csh.cshrc' do
    subject { cshrc_umask }
    it { should cmp '077' }
  end
end
