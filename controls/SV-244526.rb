control 'SV-244526' do
  title "The RHEL 8 SSH daemon must be configured to use system-wide crypto
policies."
  desc  "Without cryptographic integrity protections, information can be
altered by unauthorized users without detection.

    Remote access (e.g., RDP) is access to DoD nonpublic information systems by
an authorized user (or an information system) communicating through an
external, non-organization-controlled network. Remote access methods include,
for example, dial-up, broadband, and wireless.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography
enabling distribution of the public key to verify the hash information while
maintaining the confidentiality of the secret key used to generate the hash.

    RHEL 8 incorporates system-wide crypto policies by default. The SSH
configuration file has no effect on the ciphers, MACs, or algorithms unless
specifically defined in the /etc/sysconfig/sshd file. The employed algorithms
can be viewed in the /etc/crypto-policies/back-ends/ directory.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify that system-wide crypto policies are in effect:

    $ sudo grep -i crypto_policy /etc/sysconfig/sshd

    # crypto_policy=

    If the \"crypto_policy\" is uncommented, this is a finding.
  "
  desc  'fix', "
    Configure the RHEL 8 SSH daemon to use system-wide crypto policies by
adding the following line to /etc/sysconfig/sshd:

    # crypto_policy=

    A reboot is required for the changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173',
'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065']
  tag gid: 'V-244526'
  tag rid: 'SV-244526r743827_rule'
  tag stig_id: 'RHEL-08-010287'
  tag fix_id: 'F-47758r743826_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe "Control not applicable - SSH is not installed within containerized RHEL" do
      skip "Control not applicable - SSH is not installed within containerized RHEL"
    end
  else
    describe parse_config_file('/etc/sysconfig/sshd') do
      its('CRYPTO_POLICY') { should be_nil }
    end
  end
end

