# mpc-lib — Security Model and Submission Contract

This document is the authoritative reference for the security model under
which the protocols in this repository are designed and reviewed, and for
the contract between this library and any application that integrates it.

It is intended primarily for security researchers and AI-assisted analysis
pipelines preparing submissions to the Fireblocks bug bounty program, and
secondarily for integrators evaluating the library's deployment
responsibilities. If you are a researcher, [`CLAUDE.md`](CLAUDE.md) is a
shorter entry point. For the disclosure channel and program scope, see
[`SECURITY.md`](SECURITY.md).

## Sections

- §1 — Threat Model. What "secure" means for these protocols, and which
  attacker classes are in and out of scope.
- §2 — Integrator Contract. What this library expects from any application
  that integrates it. Findings whose impact only materializes when a
  contract item is violated are out of scope of the library bounty.
- §3 — Safe-by-Design Patterns. Recurring code shapes that look like
  vulnerabilities to a code-only reader but are sound under the
  protocols' published security proofs.
- §4 — What Makes a High-Signal Submission. Categories of finding that
  the program actively wants to receive, with the framing that gets them
  to a triage decision fastest.
- §5 — Severity Calibration. How findings are mapped to severity levels.
- §6 — Frequent Wrong Claims. Submission patterns the program has
  explained, where similar-looking submissions have a documented
  reason they are not findings.

---

## §1 — Threat Model

### §1.1 — The Malicious-Adversary Model

The MPC protocols in this library are designed to remain secure in the
**malicious-adversary model**:

- Any participant in the protocol can be malicious or attacker-controlled.
- The protocol provides its security guarantees to each *honest*
  participant. A malicious party deviating from the protocol — sending
  malformed messages, choosing degenerate values, withholding or replaying
  messages, colluding with other malicious parties — must not, for any
  honest participant, break the security guarantees or put that honest
  participant's secrets at risk.
- **The degenerate case where all participants in a protocol run are
  malicious is explicitly out of scope.** There is always at least one
  honest participant.

This is the published security model for the protocols implemented here
(see [CMP, IACR ePrint 2020/492](https://eprint.iacr.org/2020/492); [BAM, IACR ePrint 2024/1950](https://eprint.iacr.org/2024/1950)). When a
finding's exploit chain requires all participants to be malicious
simultaneously, the finding falls outside the model and is out of scope
regardless of code-level severity.

### §1.2 — What an Honest Participant Is Guaranteed

Under §1.1, an honest participant is guaranteed each of the following
properties across any combination of malicious peers:

1. **Long-term key secrecy.** The honest party's long-term key share is
   not recoverable by any malicious peer or any external observer,
   beyond the negligible information leakage inherent in the protocol
   transcript.
2. **Unforgeability against the threshold.** No coalition of malicious
   parties strictly smaller than the threshold can produce a valid
   signature on a message that the honest party did not agree to sign.
3. **Threshold preservation.** The honest party's contribution remains
   necessary for signature production. The protocol's output does not
   collapse such that a strict subset of the parties can sign
   unilaterally.
4. **Liveness against per-protocol-run adversaries.** A protocol run
   that completes successfully produces a valid signature. Adversarial
   denial-of-protocol-completion within a single run is a separate scope
   item — see §5.

A finding is meaningful under this threat model if and only if it
demonstrates that at least one of (1)–(4) is broken for the honest
participant by some attacker action permitted under §1.1.

### §1.3 — Security-Property Carve-Outs: Where the Library Stops

The library does not guarantee security properties that depend on
layers outside the cryptographic protocol itself. Three carve-outs
recur in submissions:

- **Persistency / storage layer.** The library declares interfaces for
  storing protocol state (signing data, presigning slots, key material)
  and ships mock implementations sufficient to run the test suite. The
  production persistency implementation is the integrator's
  responsibility. Properties like single-use semantics, atomic
  load-and-delete, replay rejection, and durable-write semantics are
  enforced by that implementation, not by the library code that calls
  into it. See §2 for the full integrator-persistency contract.
- **Authentication and transport security.** The library expects
  messages between parties to arrive intact, in the protocol's
  designated order, and authenticated as originating from the claimed
  party. Confidentiality and integrity of the transport channel are the
  integrator's responsibility.
- **Tenant authorization and policy enforcement.** Per-tenant access
  control, per-transaction policy approval, and the binding of
  high-level transaction intent to the message that gets signed are
  responsibilities of the application layer. The library does not
  inspect message content beyond what the protocol requires for
  signing.

A finding whose exploit chain requires the integrator to violate one of
these carve-outs is not a library vulnerability. The library publishes
interface contracts and a test suite that the integrator must satisfy;
integrations that do not satisfy them are invalid. See §2 for the
contract surface.

### §1.4 — The Single-Honest-Party Test

For any candidate finding, the operative question is:

> Does the bug, when triggered, cause an honest participant to lose one
> or more of the §1.2 guarantees against an attacker acting within the
> §1.1 model?

If the answer is yes, the finding is in scope and §5 calibrates its
severity. If the answer is no — for example, the attacker only weakens
their own security position, or the bug only materializes when the
honest party's own preconditions are violated — the finding is out of
scope of the library bounty, regardless of how it looks at the code
level.

§3 and §6 walk through recurring patterns where a code-only reading
suggests a vulnerability but the §1.2 + §1.1 lens shows otherwise.

---

## §2 — Integrator Contract

The library exposes a set of interfaces that an integrating application
implements to deploy the protocols in production. The items in this
section are the contract those interfaces define. Findings whose
exploit chain depends on the integrator violating one of these items
are not library vulnerabilities.

### §2.1 — Persistency Interface

The library defines pure-virtual interfaces for storing protocol state
between rounds and between calls. Concrete examples include the
signature-data persistency, the presigning-data persistency, and the
key-material persistency. The library ships mock implementations
sufficient to run the test suite; the production implementation is the
integrator's.

The contract for any concrete persistency implementation:

- **Single-use semantics for nonces and presigning slots.** Any value
  whose protocol role requires it to be consumed at most once — a
  nonce share, a presigning tuple, a one-shot commitment — must not be
  retrievable a second time once consumed. The integrator's
  implementation must honor single-use atomicity: a successful load must
  remove the value, and the value must not subsequently be readable by
  any code path.
- **Atomic load-and-delete.** The "load" and "delete" steps of the
  atomic operation above are not allowed to be separated by an
  externally observable window. Implementations that load first and
  delete later do not satisfy the contract.
- **Replay rejection.** Operations that consume a value identified by
  a key (`tx_id`, presigning index, key-id, etc.) must reject any
  subsequent operation with the same key. Replay attempts must throw,
  not silently return success or silently overwrite.
- **Durable write before successful return.** When a library operation
  returns successfully after writing into the persistency, the write
  must be durable. Operations that buffer writes and lose them on
  process restart do not satisfy the contract.

The bundled test suite encodes this contract: replay-attempt assertions
are paired with `REQUIRE_NOTHROW` on the first call and
`REQUIRE_THROWS_AS` on the second. A production persistency that does
not pass the bundled tests is an invalid integration.

### §2.2 — Transport and Authentication

The library expects messages between protocol parties to arrive intact,
in the protocol's designated order, and authenticated as originating
from the claimed sending party. Specifically:

- Message origin and integrity must be verifiable: the recipient must
  be able to confirm that a received message was sent by the claimed
  party and has not been altered since it was sent. The library's ZKP
  and consistency checks reject malformed or manipulated protocol
  messages; the transport layer must prevent undetected substitution of
  one party's messages for another's.
- Cross-session replays must be rejected by the transport layer (the
  library's own per-session state-machine handles intra-session replay
  in conjunction with §2.1).
- Confidentiality of message contents, where required by the
  deployment, is the integrator's responsibility.

### §2.3 — Tenant Authorization and Policy Enforcement

Per-tenant authorization, per-transaction policy approval, and the
binding of high-level transaction intent to the message-to-be-signed
are application-layer responsibilities. The library exposes
tenant-related identifiers in its interfaces for the integrator's use
but does not enforce tenant boundaries on its own.

### §2.4 — Caller-Enforced Bounds

The library exposes operations whose safe use requires the caller to
respect bounds documented in the public headers. Examples include but
are not limited to:

- BIP-32 / BIP-44 derivation path lengths.
- Multi-block signing batch sizes (subject to a library-defined upper
  bound such as `MAX_BLOCKS_TO_SIGN`).
- Cryptographic key size lower bounds.

Where the library enforces such a bound internally, it does so as a
defense-in-depth measure to prevent invalid computation; this does not
substitute for caller-side validation of the bounds documented in the
public API. Submissions claiming that passing a value outside the
caller's documented contract produces incorrect behavior are
caller-contract issues, not library vulnerabilities.

### §2.5 — Randomness Provenance

The library uses the OpenSSL CSPRNG to generate all secret material
(long-term key shares, nonces, blinding values, MtA randomness,
commitment openings). OpenSSL's CSPRNG is documented as cryptographically
secure; return values from RNG calls are checked at every site.

The library also exposes a deterministic random generator
(`drng_*`) that is used **exclusively** to derive Fiat-Shamir challenges
from committed inputs. The deterministic property is a feature of the
Fiat-Shamir transformation: both the prover and verifier must derive
the same challenge from the same transcript. `drng_*` is not used to
sample secret material. Submissions premised on `drng_*` being
"insecure because it is deterministic" are not findings — see §6.2.

### §2.6 — Test Code

Code under the `test/` directory is not part of the deployed attack
surface; the library considers the test suite a normative specification
of the integrator contract. Issues in test code are not eligible for
standard bug bounty awards, though submissions that identify a genuine
gap in normative test coverage may be considered for a small
discretionary bonus.

---

## §3 — Safe-by-Design Patterns

Several recurring submission shapes look like vulnerabilities to a
reader who is examining the code in isolation, but are sound under the
composition argument of the protocol they appear in. This section
documents the patterns and points researchers at the published
references that establish their soundness. Researchers submitting a
finding that fits one of these shapes must demonstrate end-to-end
exploitation against the §1.2 properties. Showing that a verifier
accepts a particular input, demonstrating an algebraic collapse, or
identifying a degenerate value — without completing the chain to an
actual §1.2 breach — is not sufficient to establish a finding.

### §3.1 — Degenerate Commitment Parameters Generated by a Malicious Party

The protocols make use of commitment schemes (Ring-Pedersen-style and
Damgård-Fujisaki-style) in which each protocol participant generates a
set of parameters that the *other* parties use when committing values
*to* that participant. The parameter-generating party acts as the
verifier of those commitments; the committing parties are the provers.
Each parameter-generating party proves their parameters are well-formed
via a dedicated zero-knowledge parameter proof.

If a malicious party i generates degenerate parameters — for example,
s_i = 1 — then commitments that the honest party j forms using those
parameters are degenerate: regardless of what value j commits to, the
resulting commitment is the same. This means the binding property is
broken in the sense that j could in principle open to any value.
However, the hiding property holds trivially: since all committed values
produce the same commitment output, party i cannot distinguish what j
actually committed — party i learns nothing about j's secret from the
degenerate commitment.

This is a case of an attacker degrading their own protocol position.
By choosing degenerate parameters, the malicious party i gives up any
meaningful ability to receive verifiable commitments from j, while
gaining no information about j's secrets in return. It does not break
any §1.2 guarantee for the honest party. A submission against this
pattern must demonstrate that the honest party j's secrets are actually
recoverable by i through the degenerate commitment — not merely that
i's verification capability over j's commitments is weakened.

References for the binding and hiding properties of the commitment
schemes used: the Pedersen, Ring-Pedersen, and Damgård-Fujisaki
literature. The specific role of each in the threshold-ECDSA protocols
this library implements is described in
[CMP, IACR ePrint 2020/492](https://eprint.iacr.org/2020/492) §3, and
[BAM, IACR ePrint 2024/1950](https://eprint.iacr.org/2024/1950).

### §3.2 — ZKP Verifier Accepting the Point at Infinity or a Zero Scalar

Schnorr-family zero-knowledge proofs (and their generalizations to
DDH-log, exponent-of-Paillier-ciphertext, and similar relations)
verify equations of the form `g^response = commitment · public^challenge`.
When `public` is the identity element of the group (the point at
infinity on an elliptic curve, or the unit in a multiplicative group),
the term `public^challenge` becomes the identity, and the verifier
equation reduces to `g^response = commitment`. A prover honestly
claiming "the witness for this `public` value is 0" satisfies this
equation by setting `commitment = g^response` — which is a correct,
sound proof of the zero-witness statement.

The program's position is that the verifier-level acceptance of the
identity element is not a soundness break in itself: while the point at
infinity is invalid as input to most EC-related algorithms, it is a
legitimate input to a zero-knowledge proof — a ZKP proves that the
prover knows a secret value, and the value can be zero. If a
higher-level protocol requires the proven value to be non-zero, that
check belongs outside the ZKP, not inside the verifier.

This pattern is sound when all of the following hold:

1. **The natural witness for the identity-element input is `0`**, and
   a prover claiming that witness genuinely knows it.
2. **The protocol's algebraic structure forces all matching
   prover-supplied values to be self-consistent with the zero-witness
   statement.** In a Schnorr ZKP composed with a Paillier-ciphertext
   check, for instance, the Paillier verifier forces the ciphertext to
   encrypt the same value the EC point commits to; if the EC point is
   the identity, the ciphertext is forced to encrypt zero.
3. **Any compensating consistency check downstream catches the
   trivially-true zero claim.** Final-signature verification,
   aggregate-equation checks (such as `g^δ = Π Γ_i`), and DH-consistency
   relations across parties all serve this role at different points
   in the protocols.

When all three conditions hold, the verifier-level acceptance of the
identity element does not constitute a soundness break: the prover can
only prove the trivially-true zero-witness statement, and a
trivially-true statement is not a forgery.

Submissions claiming a soundness break of this form must demonstrate
that one of the three conditions fails *and* that the failure produces
end-to-end exploitation against a §1.2 guarantee. Naming a verifier
that accepts the identity element, exhibiting algebra in which terms
cancel when the input is the identity, or showing a PoC that produces
a signature on a message the honest participant agreed to sign — none
of these alone constitute a §1.2 break.

Reference: Schnorr, "Efficient Signature Generation by Smart Cards,"
Journal of Cryptology, 1991, for the underlying ZKP construction;
Fiat–Shamir (CRYPTO 1986) for the non-interactive transformation;
[CMP (IACR ePrint 2020/492)](https://eprint.iacr.org/2020/492) and
[BAM (IACR ePrint 2024/1950)](https://eprint.iacr.org/2024/1950) for
the specific compositions used in this library.

### §3.3 — Test-Enforced Single-Use Semantics

Single-use semantics for nonces, presigning slots, and other one-shot
values are enforced by the integrator's persistency implementation
(see §2.1), not by the library code that calls into it. The library
expresses the contract through the *names* of interface methods (such
as the explicit `load_signature_data_and_delete` operation, which is
atomic by name) and through the *test suite*, which exercises replay
attempts against the mock persistency and asserts they throw.

A submission of the form *"the library does not enforce single-use
because the call site does not call a delete after the load"* misses
the contract: the load *is* the delete, and the integrator's
persistency must honor that. Similarly, *"a persistency implementation
that allows UPSERT on duplicate `tx_id` would enable nonce reuse"* is
an observation about a non-compliant persistency, not a library
vulnerability.

A submission *is* in scope when the exploit chain runs through a
library-internal state-machine path that resurrects an already-consumed
value through the library's own code — not through any integrator
behavior. This is a distinct class of finding from the persistency-
contract pattern and is evaluated on its own merits.

Reference: §2.1 of this document; the bundled `test/cosigner/` test
files for the normative replay-rejection assertions.

---

## §4 — What Makes a High-Signal Submission

This section describes the categories of finding the program actively
seeks. Submissions that fit these categories and present the required
evidence reach a triage decision fastest.

### §4.1 — Security Issues in the Signing Protocol

Findings that demonstrate, against an attacker acting within §1.1,
that an honest participant loses one or more §1.2 guarantees:

- Recovery of an honest party's long-term key share.
- Collapse of the threshold property such that a strict subset of the
  parties can sign without the honest party's participation.
- Permanent denial of an honest party's ability to sign with a key
  (as distinct from per-run disruption — see §4.3).

These are the highest-priority submissions. Severity is calibrated in
§5; in general these map to P1 (Critical) or P2 (High).

### §4.2 — Cryptographic Failures

The program identifies four sub-categories of cryptographic failure:

- **Bypassing verification checks.** A ZKP verifier that accepts an
  invalid proof, such that an attacker can substitute a value the
  protocol would otherwise reject. See §3.2 for the safe-by-design
  baseline; submissions must clear that baseline to be in scope.
- **Biased random generation.** A non-uniform output from a function
  expected to produce uniform values, where the bias is exploitable.
  Note that some biases are intentional and documented in code
  comments; if the bias is documented and bounded, it is not a
  finding.
- **Incomplete ZKP generation.** A ZKP that, due to an integer
  overflow, an off-by-one, or a missing repetition, does not achieve
  the soundness level its parameters claim.
- **Sensitive-data memory persistency.** Secret material left in
  memory beyond the computation that requires it, in a state that
  could be exposed by a separate disclosure primitive.

For each, a submission's value depends on the demonstrated impact on
the §1.2 properties.

### §4.3 — Disruption of Co-Signers

A malicious party providing malformed protocol input must not crash an
honest co-signer or cause it to leak memory. Findings that demonstrate
such behavior are in scope; their severity depends on whether the
effect is per-protocol-run or persistent (see §5).

### §4.4 — Memory Leaks

Memory leaks in deployed code paths — both the normal path and the
error path — are in scope. Memory leaks are typically Low (P4)
severity unless they enable a separate disclosure primitive.

### §4.5 — Side-Channels with Demonstrated Signal

A side-channel finding is in scope when **both** of the following hold:

- The leaked information is secret, private, or otherwise sensitive
  (timing variations on public values are not in scope).
- The attack's success probability is demonstrated with an
  experimental measurement of the timing signal above realistic noise,
  appropriate to the access the attacker is assumed to have (local,
  network-remote, co-tenant, etc.).

The rating depends on the difficulty of the demonstrated attack.

### §4.6 — Required Submission Elements

A submission reaches a triage decision fastest when it includes:

- **A working proof-of-concept**, or an unambiguous reduction of the
  finding to a known primitive cryptographic attack.
- **An explicit adversary-capability statement** — what the attacker
  controls, what messages they can send, what is observable on-wire.
- **The §1.2 property the finding breaks**, and the §1.1 attacker
  action that triggers the break.
- **An explicit statement of any §2 contract item the finding depends
  on** — and an explanation of why the finding is a library
  vulnerability rather than an integrator-contract violation.

Submissions that do not include these elements may still be triaged,
but the back-and-forth required to establish them lengthens the
turnaround.

### §4.7 — Findings That Do Not Require a Practical Attack Path

A finding does not need a complete practical attack path to be valid.
Cryptographic attacks do not need to be practical to be considered:
a finding that demonstrates a soundness break under a theoretical
model is in scope even if its practical exploitation requires
capabilities beyond what is reasonable for any deployed adversary.
The severity in this case will typically be lower than the same
finding with a practical attack path.

### §4.8 — Automated-Tool Findings

Undefined behavior, non-portable code, and misaligned memory issues
are often reported by automated tools. These are considered findings
only when the reporter provides a PoC that demonstrates unwanted
behavior on x86_64 or aarch64. Sanitizer outputs (ASAN, UBSAN, etc.)
are not by themselves a PoC: sanitizers insert checks that interrupt
execution when triggered, and that interruption is a property of the
sanitizer-instrumented binary, not the production binary.

---

## §5 — Severity Calibration

Severity ratings map findings to the program's payout tiers. The
mapping below uses the §1.2 properties as the primary axis and the
program's rating conventions for sub-classification.

### §5.1 — P1 (Critical)

Findings that demonstrate, with a working PoC against an attacker
operating within §1.1, a direct break of §1.2.1 or §1.2.2:

- Recovery of an honest party's long-term key share.
- Threshold collapse (§1.2.3) in a deployed protocol such that a strict
  subset of parties — not including the honest party — can sign
  unilaterally on a key the honest party participated in generating.

### §5.2 — P2 (High)

Findings of the same shape as §5.1 but with strong preconditions —
adversarial timing windows that occur with low probability, exploit
chains requiring multiple specific message orderings, or attacks that
require many rounds to succeed. A P2 finding still demonstrates a real
§1.2 break; the rating reflects practical difficulty, not theoretical
soundness.

Also typically P2:

- ZKP soundness breaks that demonstrably allow false-statement proofs
  to be accepted (§3.2's three conditions for safety must be
  demonstrably violated), with end-to-end exploitation against §1.2.
- Per-share secret extraction primitives that the attacker can
  combine across sessions.

### §5.3 — P3 (Medium)

- Cryptographic failures with low success probability that do not yet
  reach end-to-end §1.2 break.
- Persistent denial of one or more co-signers' ability to operate (as
  distinct from per-run disruption).
- Side-channel attacks (§4.5) with a demonstrated signal at modest
  attacker capability.
- Sensitive-data memory persistency without a demonstrated disclosure
  primitive (§4.2 fourth sub-category).

### §5.4 — P4 (Low)

- Per-protocol-run disruption (a malformed peer message causes a
  protocol run to abort, but the honest party recovers).
- Memory leaks in normal or error paths.
- Hardening recommendations that do not correspond to a §1.2 break.
- Theoretical cryptographic failures whose demonstrated impact does
  not reach P3.

### §5.5 — P5 (Informational / Out-of-Scope)

- Findings whose exploit chain requires §1.3 carve-out violations.
- Findings whose exploit chain requires a §2 contract item to be
  violated by the integrator.
- Findings whose exploit chain requires all participants in a
  protocol run to be malicious (§1.1).
- Findings that match a §3 safe-by-design pattern and do not
  demonstrate end-to-end exploitation against a §1.2 guarantee.
- Findings already in §6 with no novel angle.
- Findings in test code (§2.6).

---

## §6 — Frequent Wrong Claims

Each item below is a submission pattern the program has explained.
Researchers preparing a submission that resembles one of these
patterns should read the corresponding explanation before submitting.

### §6.1 — Unsecure Cryptographic Sizes

*What is reported:*

- "We don't forbid trivially small keys; this breaks the security."
- "An attacker can generate a small Paillier (or Pedersen) key that
  will be accepted. It's insecure!"

*Why it's not an issue:*

The `crypto/` folder contains generic implementations of cryptographic
primitives. A caller can generate keys of any size, with the library
disallowing bit sizes smaller than a minimum for non-security
correctness reasons. The protocols built on top of these primitives
constrain the sizes that are *actually* acceptable for security; that
constraint lives in the protocol code, not in the primitive code.

Submissions claiming that small key sizes are accepted by the
*primitive* layer are not findings; submissions claiming that the
*protocol* layer accepts an insecure size require demonstrating that
the protocol accepts it to be considered valid.

### §6.2 — RNG Determinism (`drng_*`)

*What is reported:*

- "We make use of a deterministic Random Number Generator in the
  mpc-lib, so it does not produce unpredictable random values."

*Why it's not an issue:*

The `drng_*` functions are used **only** to derive Fiat-Shamir
challenges from committed inputs. Fiat-Shamir requires the challenge
to be deterministic — both the prover and the verifier must derive
the same challenge from the same transcript. The deterministic
property is achieved by hashing the transcript with a cryptographically
secure hash function; the output looks random in the sense the
Fiat-Shamir transformation requires.

`drng_*` is not used to sample any secret material. A submission
claiming "`drng_*` is insecure because it is deterministic" should
re-examine the function's role in the protocol.

### §6.3 — Absence of RFC 6979 Deterministic Nonces

*What is reported:*

- "We don't use the deterministic nonce generation of RFC 6979,
  therefore there is a risk of generating the same nonce twice for
  different messages."

*Why it's not an issue:*

The library uses OpenSSL's CSPRNG to generate signing nonces. The
probability of generating the same value twice is cryptographically
negligible, and RNG-call return values are checked at every site for
the case where the OpenSSL RNG cannot generate randomness or is
improperly seeded.

Moreover, applying RFC 6979 in an MPC context introduces a subtle
attack. If some parties derive their nonce contribution deterministically
using RFC 6979 (from their key share and the message) while others use
random nonces, a malicious party can observe the difference between a
signature produced under a fully-deterministic setting and one produced
under a mixed setting. By exploiting this shift, the malicious party
can mount a key extraction attack and recover the full recombined
signing key, breaking the MPC threshold guarantee. This library does
not use RFC 6979, eliminating this mixed-determinism attack surface.
The non-use of RFC 6979 is a deliberate design choice, not an
oversight.

### §6.4 — OpenSSL Random Functions

*What is reported:*

- "We call OpenSSL functions to generate random ECDSA/EdDSA nonces,
  so it's insecure."
- "We don't have a mechanism to ensure that nonces are not reused."
- "ECDSA is vulnerable to nonce reuse, so our implementation is
  vulnerable too."

*Why it's not an issue:*

The OpenSSL CSPRNG is cryptographically secure (see the
[OpenSSL documentation](https://docs.openssl.org/3.1/man3/BN_rand/)
for the explicit guarantee). The probability of
generating the same nonce twice is cryptographically negligible.

While it is true that ECDSA and EdDSA are vulnerable to nonce reuse
attacks in the abstract, the question for a submission is whether
*this* library exhibits a code path that produces nonce reuse against
an honest party. A Python script demonstrating the standard
nonce-reuse extraction from two signatures with the same `R` is well
understood; demonstrating that the library produces two such
signatures under the §1.1 attacker model is the part that constitutes
a finding.

### §6.5 — `is_coprime_fast` Non-Constant-Time

*What is reported:*

- "We call a non-constant-time function to compute the GCD of a
  Paillier modulus with an attacker-controlled value. It can be used
  to factorize the Paillier modulus, and break the scheme."
- "We use a non-constant-time function to compute the GCD; this can
  leak information about inputs to this function."

*Why it's not an issue:*

`is_coprime_fast` is invoked with public values. Timing discrepancies
on public inputs are not a side-channel because the public information
they could reveal is already public. The function never receives
secret material under any code path in the library's protocols.

The further claim that GCD computation with the modulus and an
attacker-chosen value could be used to factorize the modulus would be
a ground-breaking advance in number theory: integer factorization is
one of the most-studied problems in classical cryptography, and no
efficient algorithm is known.

### §6.6 — ZKP Verifier Accepts the Point at Infinity

*What is reported:*

- "I can forge a Zero-Knowledge Proof with the point at infinity that
  is accepted as valid; therefore the soundness is broken."
- "You don't check that the point at infinity is correctly rejected
  by co-signers; this breaks the security assumption."

*Why it's not an issue:*

While the point at infinity is invalid as input to most EC-related
algorithms, it is a legitimate input to a zero-knowledge proof. A ZKP
proves that the prover knows a secret value — and the value can be
zero. If a higher-level protocol requires the proven value to be
non-zero, that check belongs outside the ZKP, not inside the verifier.

The full pattern, with the three conditions that make it sound and
the protocol-level reasoning, is in §3.2 of this document. Submissions
must demonstrate end-to-end exploitation against a §1.2 guarantee, not
merely verifier-level acceptance of the identity element.

---

*This document is maintained alongside the protocols and primitives it
references. For the disclosure channel and program scope, see
[`SECURITY.md`](SECURITY.md). For the researcher / AI-tooling entry
point, see [`CLAUDE.md`](CLAUDE.md).*
