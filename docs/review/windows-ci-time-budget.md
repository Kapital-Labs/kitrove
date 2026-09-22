# Windows validation time budget

Main run 35797074178 reached its 30-minute job limit. The Windows canonical suite
passed, followed by the standard-user installer boundary. Rust 1.85 installation
also passed; the final CLI dependency check was cancelled while compiling. GitHub's
annotation explicitly reports the execution-time limit, not a test failure.

Allow 45 minutes only for Windows in the main and operating-system-sensitive PR
jobs. Mac PR checks retain 20 minutes; other main platforms retain 30 minutes.
The matrix, change classifier, checks, credential boundaries and required summary
are unchanged. This raises the worst-case Windows job ceiling, not the number of
runs or successful-job duration. Avoid retrying the old run under its old limit.

Review checked both workflow paths and retained standard-user/MSRV coverage.
Regression checks bind the platform-specific limits and required commands. This
is validation scheduling only; NS-07/NS-09 and production signing gates are unchanged.
