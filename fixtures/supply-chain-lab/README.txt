TEST FIXTURE - not a real application.
Planted supply-chain risks so every Guardian detector has something to find:
  1.1 vulnerable direct dependency      lodash 4.17.4
  1.2 vulnerable transitive dependency  minimist 0.0.8 (via mkdirp 0.5.1)
  1.3 typosquat                         crossenv (look-alike of cross-env)
  1.4 install script                    telemetry-helper-demo (hasInstallScript)
  1.5 unsafe container                  FROM node:latest, curl | bash, runs as root
  1.6 lockfile tampering                minimist resolved from a non-official host; no integrity hash
  1.7 unsafe CI                         unpinned third-party action, pull_request_target + PR checkout,
                                        script injection from the PR title
Business context: an internet-facing Express API that stores passwords and card numbers.
