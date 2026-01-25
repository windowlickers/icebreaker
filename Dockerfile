# Build stage using Nix
FROM nixos/nix:2.24.0 AS builder

# Enable flakes and nix-command
RUN echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf

# Set working directory
WORKDIR /app

# Copy the entire project including flake files
COPY . .

# Build using the flake - specifically the CLI package
RUN nix build .#icebreaker-cli --no-sandbox --print-build-logs

# Extract the binary from the Nix store result
RUN mkdir -p /output && \
    cp result/bin/icebreaker /output/icebreaker

# Runtime stage - distroless with SHA pinning
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:189bd2ce1f7750193c2c10220d9201ba38c11e30fbb75b036606829fadbc81b1

# Copy the binary from builder with proper ownership
COPY --chown=65532:65532 --from=builder /output/icebreaker /usr/local/bin/icebreaker

# Default port for proxy
EXPOSE 8080
# Default port for metrics
EXPOSE 9090

# Set the binary as entrypoint
ENTRYPOINT ["/usr/local/bin/icebreaker"]

# Default command
CMD ["serve", "--bind", "0.0.0.0", "--port", "8080", "--metrics-enabled", "--metrics-port", "9090"]
