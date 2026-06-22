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

/// A legacy PEM-format ECDSA key — the kind `age` cannot parse. Used to verify that
/// `crypto::decrypt` emits an actionable "convert your key" error rather than a cryptic one.
pub(crate) const ECDSA_PEM_KEY: &str = "\
-----BEGIN EC PRIVATE KEY-----
MIIBaAIBAQQgG1/eFPmqLkamByjcdKxbi5Jau4cP2hDteqSMW5m+ryaggfowgfcC
AQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////
MFsEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57Pr
vVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEE
axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54W
K84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8
YyVRAgEBoUQDQgAEhZaTwIo/92ALWoC0OA1ABmCEj8XP0cou6ozr7mT4FhI8ihHA
GobJdhUtbD3etWKviqk0jBHZSm8yxO5cn7IYLw==
-----END EC PRIVATE KEY-----
";
