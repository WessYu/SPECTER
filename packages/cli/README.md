# @specter-security/cli

Defensive application-security CLI for SPECTER.

```bash
npx @specter-security/cli scan .
npx @specter-security/cli scan https://example.com
npx @specter-security/cli scan . --json
npx @specter-security/cli scan . --sarif
npx @specter-security/cli scan . --ci --fail-on high
```

See the repository README for configuration, security model and limitations.

## Terminal welcome

Run `specter`, `specter help` or `specter --help` to display the arcade
ghost, mint wordmark, cyan dividers and command reference. Terminals with at
least 118 columns show the artwork beside the commands; smaller terminals
use a stacked layout. Colors respect `NO_COLOR`, `FORCE_COLOR` and `TERM=dumb`.
Reports and version output do not include the artwork.

The built package also prints this screen from its `postinstall` hook.
Package managers may hide lifecycle output or disable lifecycle scripts.
For npm, use `npm install -g @specter-security/cli --foreground-scripts`
to expose the hook output. CI skips the installation welcome.
Source workspace installation skips it until the CLI has been built.
The terminal rendition uses text and ANSI colors; the reference image's glow
and font rendering depend on the terminal and are not embedded image effects.
