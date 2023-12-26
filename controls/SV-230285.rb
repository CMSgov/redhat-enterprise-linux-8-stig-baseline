# frozen_string_literal: true

control 'SV-230285' do
  title 'RHEL 8 must enable the hardware random number generator entropy
gatherer service.'
<<<<<<< HEAD
  desc 'The most important characteristic of a random number generator is its randomness, namely its ability to deliver random numbers that are impossible to predict. Entropy in computer security is associated with the unpredictability of a source of randomness.  The random source with high entropy tends to achieve a uniform distribution of random values. Random number generators are one of the most important building blocks of cryptosystems.
=======
  desc 'The most important characteristic of a random number generator is its randomness, namely its ability to deliver random numbers that are impossible to predict. Entropy in computer security is associated with the unpredictability of a source of randomness.  The random source with high entropy tends to achieve a uniform distribution of random values. Random number generators are one of the most important building blocks of cryptosystems.  
>>>>>>> 87a05e3c31795238f35c7bb155a9770db9a9c15c

The rngd service feeds random data from hardware device to kernel random device. Quality (nonpredictable) random number generation is important for several security functions (i.e., ciphers).'
  desc 'check', 'Note: For RHEL versions 8.4 and above running with kernel FIPS mode enabled as specified by RHEL-08-010020, this requirement is Not Applicable.

Check that  RHEL 8 has enabled the hardware random number generator entropy gatherer service.

Verify the rngd service is enabled and active with the following commands:

     $ sudo systemctl is-enabled rngd
     enabled

     $ sudo systemctl is-active rngd
     active

If the service is not "enabled" and "active", this is a finding.'
  desc 'fix', 'Start the rngd service and enable the rngd service with the following commands:

     $ sudo systemctl start rngd.service

     $ sudo systemctl enable rngd.service'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230285'
  tag rid: 'SV-230285r928587_rule'
  tag stig_id: 'RHEL-08-010471'
  tag fix_id: 'F-32929r917875_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe service('rngd') do
      it { should be_enabled }
      it { should be_running }
    end
  end
end
