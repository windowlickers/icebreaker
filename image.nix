{ pkgs, icebreaker-cli, version, revision }:

pkgs.dockerTools.buildLayeredImage {
  name = "icebreaker";
  tag = version;

  contents = [
    icebreaker-cli
    pkgs.cacert
  ];

  extraCommands = ''
    mkdir -p tmp var/tmp
    chmod 1777 tmp var/tmp
  '';

  config = {
    Entrypoint = [ "${icebreaker-cli}/bin/icebreaker" ];
    Cmd = [ "serve" "--bind" "0.0.0.0" "--port" "8080" "--metrics-enabled" "--metrics-port" "9090" ];
    WorkingDir = "/";
    User = "65532:65532";

    ExposedPorts = {
      "8080/tcp" = {};
      "9090/tcp" = {};
    };

    Env = [
      "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
      "SSL_CERT_DIR=${pkgs.cacert}/etc/ssl/certs"
    ];

    Labels = {
      "org.opencontainers.image.title" = "Icebreaker";
      "org.opencontainers.image.description" = "Stateless tokenizer proxy for secure API credential injection";
      "org.opencontainers.image.version" = version;
      "org.opencontainers.image.revision" = revision;
      "org.opencontainers.image.source" = "https://git.windowlicke.rs/windowlickers/icebreaker";
      "org.opencontainers.image.licenses" = "Apache-2.0";
    };
  };
}
