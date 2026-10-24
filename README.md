# Container images

Small, reviewed derivative images built on trusted upstream release images.

The goal is to ship targeted dependency fixes without maintaining application forks. Start with Hermes, Camofox and Plex; add other images independently.

## Status

The public design and policies are established. Hermes now has a Dockerfile, lock-coherent security override, tests and a **manual-only GitHub-hosted verification workflow**. Check its actual Actions results before treating a revision as verified. Camofox and Plex remain design-only targets. No image publishing, scheduled builds or production deployment is configured.

## Recommended approach

**Use a publisher image as the base, plus a minimal application-specific overlay.** Do not make one universal Dockerfile that upgrades everything in every image.

Illustrative base syntax (replace the placeholders with a verified release and digest):

```dockerfile
FROM publisher/application:release@sha256:DIGEST
```

A release label makes the source understandable; the digest identifies the actual input. For multiple architectures, use a manifest-list digest or explicitly record each architecture's image digest. Do not use an ARM64-only digest as an AMD64 base.

A rebuild alone is not a fix. A fixed base digest, an explicit dependency change, or a reviewed patch must actually reach the executed code.

## Layout

```text
images/
  hermes/README.md       # Hermes-specific ownership and acceptance checks
  camofox/README.md      # server, Node and browser tracked separately
  plex/README.md         # media-server and transcoding compatibility
  <name>/
    Dockerfile          # added when its base and overrides are reviewed
    image.yaml          # base, platforms, upstream version and overrides
    tests/              # image-specific smoke and regression tests
scripts/                # shared build/test tooling, when implemented
docs/
  build-pipeline.md     # proposed CI/publishing and promotion contract
  override-policy.md    # how to override dependencies safely
```

Hermes includes its recipe, override helper and executable tests; its verification workflow runs only on GitHub-hosted runners. The `image.yaml` schema and shared tooling shown above remain a proposed extension. Camofox and Plex currently have README guidance only. There are no placeholder Dockerfiles that silently publish an unchanged vulnerable base.

## Update layers independently

| Layer | Preferred mechanism | What it does not cover |
| --- | --- | --- |
| Application | Move to a reviewed upstream release image | A newer release is not proof that every dependency is fixed |
| Distribution packages | Install specific fixed packages from the same supported distro suite | Vendored, static or wheel-bundled libraries |
| Python / Node dependencies | Change the dependency actually used by the app, with constraints and lock ownership respected | Other environments or a dependency manager restoring the old pin |
| Node / Python runtime | Replace through a supported runtime mechanism and test all executable copies | Bundled native code in unrelated applications |
| Browser | Update and test the separately packaged browser | Updating only its HTTP wrapper or npm packages |
| Proprietary app binaries | Follow the publisher's supported update/release mechanism | A generic OS package upgrade does not patch the app binary |

## Defaults

- Public source repository; never include runtime profiles, private configuration, media, login state or credentials.
- Release-based upstream pins; no automatic production tracking of application `main` branches.
- Independent image versions and platform lists; start only with architectures actually needed and supported.
- Prefer the fixed upstream image over a custom override whenever it meets the same tests.
- Targeted changes first. A broader distro-package refresh is allowed only after an image-specific review and regression tests.
- Build on ephemeral GitHub-hosted runners, not on the production host.
- Validate pull requests without publishing. Publish only reviewed default-branch changes or an authorized manual run.
- Immutable candidate tags plus published digests; no automatic production deployment or mutable `latest` promotion.
- Minimal workflow permissions; use the job's `GITHUB_TOKEN` for GHCR, not a personal publishing token.
- No production credentials, Docker socket, SSH access or persistent application data in CI.

## Before the first image is enabled

1. Verify the actual upstream publisher, release, platforms, license and base digest.
2. Inventory OS packages, runtimes, language environments, bundled libraries and the browser if present.
3. Select the smallest supported fix and record its rationale and removal condition.
4. Implement the image recipe and tests, preserving the publisher's startup contract.
5. Exercise a build and its tests on every declared architecture.
6. Publish a candidate, record the exact digest and verify the registry artifact.
7. Test the candidate with disposable state. Production replacement needs separate approval and rollback planning.

See [override policy](docs/override-policy.md), [build pipeline](docs/build-pipeline.md) and the notes for [Hermes](images/hermes/README.md), [Camofox](images/camofox/README.md), and [Plex](images/plex/README.md).

## References

- [Docker build best practices](https://docs.docker.com/build/building/best-practices/)
- [GitHub Actions: publishing container images](https://docs.github.com/en/actions/use-cases-and-examples/publishing-packages/publishing-docker-images)
- [GitHub Actions security](https://docs.github.com/en/actions/reference/security/secure-use)
- [GHCR authentication and package visibility](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
