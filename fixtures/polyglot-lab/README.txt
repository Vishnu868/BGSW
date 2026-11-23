TEST FIXTURE - not a real application.
Shows which scanner covers which language:
  dotnet/  C#   (NuGet .csproj)  Newtonsoft.Json 12.0.1, System.Text.Encodings.Web 4.5.0  -> OSV + Trivy + Grype
  cpp/     C/C++ (Conan lock)    zlib 1.2.11, openssl 1.1.1k                             -> Trivy + Grype only
  rust/    Rust (Cargo.lock)     smallvec 1.6.0                                          -> Trivy + Grype only
