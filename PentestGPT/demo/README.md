# Demo Recordings

This folder contains asciinema recordings demonstrating PentestGPT.

## Files

| File | Description |
|------|-------------|
| `install.cast` | Installation and setup process |
| `demo.cast` | PentestGPT solving a benchmark challenge |

## Viewing Locally

```bash
# Install asciinema
pip install asciinema

# Play a recording
asciinema play demo/install.cast
asciinema play demo/demo.cast
```

## Uploading to asciinema.org

To embed these recordings in the main README:

```bash
# Upload recordings
asciinema upload demo/install.cast
asciinema upload demo/demo.cast
```

After uploading, copy the recording IDs from the URLs and update the embeds in the main `README.md`.
