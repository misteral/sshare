//! Throwaway ed25519 SSH keypairs used only by the test suite.
//!
//! These are NOT real credentials — they exist solely so tests can exercise the
//! encrypt/decrypt round trip without touching the user's `~/.ssh`.

pub(crate) const ALICE_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB/gfpInCKMN/BmzA072GUXsrebu/hcAWYakfr6QKlqu alice@sshare-test";

pub(crate) const ALICE_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAf4H6SJwijDfwZswNO9hlF7K3m7v4XAFmGpH6+kCpargAAAJjjtb/F47W/
xQAAAAtzc2gtZWQyNTUxOQAAACAf4H6SJwijDfwZswNO9hlF7K3m7v4XAFmGpH6+kCparg
AAAED+3UMPiQr96qPd+I8NwZbIq+LILeFzVGhafO649Y9GqB/gfpInCKMN/BmzA072GUXs
rebu/hcAWYakfr6QKlquAAAAEWFsaWNlQHNzaGFyZS10ZXN0AQIDBA==
-----END OPENSSH PRIVATE KEY-----
";

pub(crate) const MALLORY_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOzxHqUFE7nQV4hAGBe4RGkxZkdsvpzZhmDViwK/HW+z mallory@sshare-test";

pub(crate) const MALLORY_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDs8R6lBRO50FeIQBgXuERpMWZHbL6c2YZg1YsCvx1vswAAAJg/gTMFP4Ez
BQAAAAtzc2gtZWQyNTUxOQAAACDs8R6lBRO50FeIQBgXuERpMWZHbL6c2YZg1YsCvx1vsw
AAAEBVsdeSzRdkkd8fr14IWBArsCgW7t08rPO18bSF+pzFf+zxHqUFE7nQV4hAGBe4RGkx
ZkdsvpzZhmDViwK/HW+zAAAAE21hbGxvcnlAc3NoYXJlLXRlc3QBAg==
-----END OPENSSH PRIVATE KEY-----
";
