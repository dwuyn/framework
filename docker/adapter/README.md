# Container adapter bundle

The provider shim is the only model-call boundary inside a baseline image.
Images do not receive ADC or Vertex credentials. The shell entrypoint removes
credential discovery variables, enforces non-root execution, and creates only
the per-run writable directory.
