# Installing DBDelve

## macOS

Apple Silicon, macOS 12 or later — that's what it's built and tested on. Intel
and older macOS aren't blocked by anything in the code, they're just untested.

Homebrew is the recommended way. It handles installing and upgrading:

```sh
brew install --cask ShayanAbbas1/dbdelve/dbdelve
xattr -dr com.apple.quarantine /Applications/DBDelve.app
```

Don't skip the second line, or macOS will refuse to open the app. DBDelve is
signed ad-hoc: there's no Developer ID behind it and nothing is notarized, so
Gatekeeper declines until the quarantine flag is cleared.

Your connections and query history are kept outside the app and survive updates.
macOS will ask once more for the saved passwords in your Keychain after each
update, because each release carries a different ad-hoc signature. I'll
pay for a Developer ID if enough people end up using this, which removes all of
the above.

Failing Homebrew, take the `.dmg` from [the latest release][releases] and drag
DBDelve to Applications. Same quarantine step and you have to update manually.

To build it yourself instead, `DBDELVE_CHANNEL=release dev/bundle.sh` produces
`target/DBDelve.app` with the release build, icon and signature. Drag that to
Applications; the quarantine step doesn't apply here.

## Linux

The releases carry only the macOS app, so on Linux, build from source. On
Debian or Ubuntu the build needs:

```sh
sudo apt install build-essential pkg-config cmake libfontconfig-dev \
  libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev libdbus-1-dev
cargo build --release
```

The binary lands at `target/release/dbdelve` and runs from anywhere. X11 and
Wayland both work, and you need a Vulkan or OpenGL driver, a Secret Service
keyring (gnome-keyring or KWallet) for saved passwords, and xdg-desktop-portal
for the export dialog. Connections and query history go to
`$XDG_DATA_HOME/dbdelve`, or `~/.local/share/dbdelve`.

## Windows

The releases carry only the macOS app, so on Windows, build from source. The
build needs the MSVC toolchain and the Windows SDK, which is what compiles the
bundled SQLite and GPUI's shaders:

```sh
cargo build --release
```

The binary is `target\release\dbdelve.exe`. Connections and query history go
to `%APPDATA%\dbdelve`. Passwords go in Credential Manager. The window draws
its own title bar, buttons included. Chords are the same as macOS with Ctrl in
place of Cmd.

## Updating

`brew upgrade --cask dbdelve`, if you installed it that way. Otherwise the
status bar links to [the latest release][releases] once there is a newer one.

There is no telemetry. The only request DBDelve makes on its own is one to
GitHub at startup to check for updates, which you can turn off in Settings.

[releases]: https://github.com/ShayanAbbas1/dbdelve/releases/latest
