# Security policy

**brnr-e2ee has not had an independent security audit.** The protocol ([SPEC.md](SPEC.md)) and the code have been reviewed only by the author, with help from automated adversarial reviews. An independent audit is listed as deferred in [SPEC §2](SPEC.md#2-scope), and there's no date for one yet. Until there is, treat the library accordingly.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.x     | Yes       |
| < 1.0   | No        |

Only the latest release gets fixes. A fix ships as a new patch release, published from CI with npm provenance.

## Reporting a vulnerability

Please use GitHub's private reporting: **[open a draft security advisory](https://github.com/AshwinSathian/brnr-e2ee/security/advisories/new)**. If you can't use GitHub, email ashwinsathyan19@gmail.com with the subject `brnr-e2ee security`.

Don't open a public issue or pull request, and don't post details anywhere public, until a fix is out.

It helps to include:

- the version (from `npm ls brnr-e2ee`);
- what you saw and how to reproduce it, ideally as a failing test;
- which part of SPEC.md or THREATMODEL.md it breaks, if you know;
- whether you think it's being exploited.

You'll get an acknowledgement within 72 hours. I'll keep you posted while I work on a fix, agree the disclosure date with you, and credit you in the advisory unless you'd rather not be named. Advisories are published on GitHub, with a CVE where one applies.

## What counts

[THREATMODEL.md](THREATMODEL.md) says who the library defends against. A vulnerability is anything that lets one of those adversaries do something the threat model says they can't, for example:

- reading or forging a message without the keys;
- getting a message accepted under the wrong identity, conversation or device;
- replaying a message inside the retained window so that it's accepted twice or changes state;
- making a message or a state cost more memory or work than [SPEC §17](SPEC.md#17-limits) allows;
- the library behaving differently from SPEC.md in a way that weakens any of the above.

The library's code, SPEC.md, the test vectors and the release workflow are in scope.

Not in scope here:

- the known limits listed in THREATMODEL.md, unless you've found a way to make one worse than it says;
- problems in an app's own code, storage (`KeyStore` implementations), server or UI, or an app that skips one of the consumer responsibilities in [SPEC §19](SPEC.md#19-consumer-responsibilities); report those to the app;
- vulnerabilities in `@noble/*` or `zod` themselves; report those upstream, though I'd like to hear about them too.
