# Changelog

Notable changes are documented below. Earlier releases are available in the repository tags and GitHub Releases.

## [Unreleased]

### Changed

- Refresh the Fiber adapter dependencies: schema v1.10.0, utils/v2 v2.6.5,
  compress v1.20.5 and fasthttp v1.80.0.
- Update `golang.org/x/crypto`, `net`, `sys` and `text` to v0.59.0, v0.63.0,
  v0.50.0 and v0.44.0 respectively.


## [3.0.6] - 2026-11-13

### Changed

- Update `github.com/gofiber/fiber/v3` from v3.6.1 to v3.7.0. An application that selects this release is moved to Fiber v3.7.0 or later.

The module path and the public API are unchanged.

## [3.0.5] - 2026-11-13

### Changed

- Require Go 1.27.4, which carries security fixes to cgo, the go command, the compiler, the linker and `net/http`.

The module path and the public API are unchanged.

## [3.0.4] - 2026-11-01

### Changed

- Update the optional Fiber adapter dependency from Fiber v3.5.0 to v3.6.1, with compatible schema, utils, compression, fasthttp and networking patches.
- Update the test-only YAML dependency to v3.0.6.
- Pin Go Test Report v1.1.3 and Go Report Card v1.1.4; retain Go 1.27.3 and the public API.

