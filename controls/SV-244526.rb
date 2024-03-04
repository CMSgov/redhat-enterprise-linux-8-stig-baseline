control 'SV-244526' do
  title 'The RHEL 8 SSH daemon must be configured to use system-wide crypto policies.'
  desc "Without cryptographic integrity protections, information can be
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
can be viewed in the /etc/crypto-policies/back-ends/ directory."
  desc 'check', 'Verify that system-wide crypto policies are in effect:

$ sudo grep CRYPTO_POLICY /etc/sysconfig/sshd

# CRYPTO_POLICY=

If the "CRYPTO_POLICY " is uncommented, this is a finding.'
  desc 'fix', "Configure the RHEL 8 SSH daemon to use system-wide crypto policies by adding the following line to /etc/sysconfig/sshd:

# CRYPTO_POLICY=

A reboot is required for the changes to take effect."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065']
  tag gid: 'V-244526'
  tag rid: 'SV-244526r877394_rule'
  tag stig_id: 'RHEL-08-010287'
  tag fix_id: 'F-47758r809333_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
  tag 'host', 'container-conditional'

  impact 0.0 if virtualization.system.eql?('docker') && !package('openssh-server').installed?

  if virtualization.system.eql?('docker')
    describe 'In a container Environment' do
      if package('openssh-server').installed?
        it 'the OpenSSH Server should be installed when allowed in Docker environment' do
          expect(input('allow_container_openssh_server')).to eq(true), 'OpenSSH Server is installed but not approved for the Docker environment'
        end
      else
        it 'the OpenSSH Server is not installed' do
          skip 'This requirement is not applicable as the OpenSSH Server is not installed in the Docker environment.'
        end
      end
    end
  else
    describe 'The system' do
      it 'does not have a CRYPTO_POLICY setting configured' do
        expect(parse_config_file('/etc/sysconfig/sshd').params['CRYPTO_POLICY']).to be_nil, 'The CRYPTO_POLICY setting in the /etc/sysconfig/sshd should not be present. Please ensure it is commented out.'
      end
    end
  end
end
