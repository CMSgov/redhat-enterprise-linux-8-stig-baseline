# frozen_string_literal: true

control 'SV-230487' do
  title 'RHEL 8 must not have the telnet-server package installed.'
  desc 'It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services, provided by default, may not be
necessary to support essential organizational operations (e.g., key missions,
functions).

    Examples of non-essential capabilities include, but are not limited to,
games, software packages, tools, and demonstration software not related to
requirements or providing a wide array of functionality not required for every
mission, but which cannot be disabled.

    Verify the operating system is configured to disable non-essential
capabilities. The most secure way of ensuring a non-essential capability is
disabled is to not have the capability installed.

    The telnet service provides an unencrypted remote access service that does
not provide for the confidentiality and integrity of user passwords or the
remote session.

    If a privileged user were to log on using this service, the privileged user
password could be compromised.'
  desc 'check', 'Check to see if the telnet-server package is installed with the following
command:

    $ sudo yum list installed telnet-server

    If the telnet-server package is installed, this is a finding.'
  desc 'fix', 'Configure the operating system to disable non-essential capabilities by
removing the telnet-server package from the system with the following command:

    $ sudo yum remove telnet-server'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-230487'
  tag rid: 'SV-230487r627750_rule'
  tag stig_id: 'RHEL-08-040000'
  tag fix_id: 'F-33131r568208_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe package('telnet-server') do
    it { should_not be_installed }
  end
end
