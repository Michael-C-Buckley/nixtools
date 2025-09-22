# Development Configs

I use this folder to assist with my development, it's mostly triggered by tooling via my `.envrc`

## Suggested `.envrc`

This is the envrc I'm using with this project:

```
watch_file nix/devshells.nix
use flake
layout python3
export UV_PROJECT_ENVIRONMENT="$VIRTUAL_ENV"
export UV_LINK_MODE=copy
```
