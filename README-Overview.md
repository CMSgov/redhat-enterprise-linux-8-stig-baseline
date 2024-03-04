# RedHat Enterprise Linux 8 v1r12 STIG Profile


## Directory Structure
```shell
├── baseline                            # Source of the profile, XCCDF Benchmark
├── controls                            # InSpec Tests for the Benchmark
├── libraries                           # Profile Resources that were created for the benchmarks
└── spec                                # The tetsing suite of the benchmark
    ├── ansible                         # Test suite based of `Ansible-Lockdown RHEL8-STIG`
    │   └── roles
    │       └── ansible-role-rhel-vanilla
    │           ├── defaults
    │           ├── handlers
    │           ├── meta
    │           ├── tests
    │           └── vars
    ├── results                         # Location of test results for the test suite
    └── utils                           # Utilities created to help with profile updates and testing
├── ./Gemfile                           # Gemfile for the profile
├── ./LICENSE                           # License for the profile
├── ./README-Overview.md                # ... this file ...
├── ./README.md                         # The README for the profile
├── ./Rakefile                          # Rakefile for running lint and lint:autocorrect
├── ./control-status.md                 # Useful information about the profiles tests
├── ./hardened.threshold.yml            # Baselined `pass/fail/NR/NA` for a `hardened` system
├── ./inspec.yml                        # InSpec profile minifest file
├── ./kitchen.ec2.yml                   # test-kitchen ec2 config file
├── ./kitchen.inputs.yml                # profile inputs used in kitchen-ec2 testing
├── ./kitchen.vagrant.yml               # profile inputs used in kitchen-vagrant testing
├── ./kitchen.yml                       # Base test-kitchen setup file
├── ./setup_local_kitchen.sh            # setup your KITCHEN_LOCAL_YAML file for testing
└── ./vanilla.threshold.yml             # Baselined `pass/fail/NR/NA` for a `non-hardened` system
```