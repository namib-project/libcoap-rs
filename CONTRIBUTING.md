# Contribution Guide for libcoap-rs

1. [Environment Setup](#environment-setup)
    1. [Using Nix/devenv.sh natively](#using-nixdevenvsh-natively)
        1. [IDE Setup](#ide-setup)
    2. [Manual Environment Setup](#manual-environment-setup)
    3. [Using Nix/devenv.sh with an IDE using devcontainers](#using-nixdevenvsh-with-an-ide-using-devcontainers)
2. [Committing your Code](#committing-your-code)
3. [Submitting a Pull Request](#submitting-a-pull-request)
    1. [Legal Considerations](#legal-considerations)
    2. [LLM Usage Policy](#llm-usage-policy)
4. [Conduct Guidelines](#conduct-guidelines)

## Environment Setup

In order to work on or with libcoap-rs, you need an environment that provides
the necessary dependencies and tools for building the library. You may either
provide this environment by installing the necessary dependencies yourself or
by using the Nix-based development shell (based on
[devenv.sh](https://devenv.sh/)) provided as part of this repository.

If you desire an isolated environment, do not want to install the Nix package
manager on your system, or want to develop on systems unsupported by Nix while
still not manually installing the necessary dependencies, we also provide some
(minimally tested) [Development Containers](https://containers.dev/) for use 
with JetBrains CLion or VS Code.

### Using Nix/devenv.sh natively

Assuming you have the [Nix package manager](https://nixos.org/) installed, you
can enter the preconfigured development shell from the command line using the
following commands while in the repository's root directory:

```sh
# Install devenv in your local profile (if not already installed)
nix profile add 'nixpkgs#devenv'
devenv shell
```

If you have [`direnv`](https://direnv.net/) installed and configured for your
shell, you may also set the necessary environment variables for your current
shell by running `direnv allow`. You will typically be prompted for this when
entering the repository's root directory using your shell (feel free to
inspect `.envrc` to ensure you're not running untrusted code).
This way, you can use the preconfigured environment while still utilizing your
local shell's features and custom configuration.

#### IDE Setup

For VS Code, is should suffice to install the `mkhl.direnv` extension and allow
the `.envrc` file to use the Nix-provided environment.

On JetBrains IDEs (namely, CLion and RustRover), follow these steps:
1. Install the [Direnv integration](https://plugins.jetbrains.com/plugin/15285-direnv-integration)
   plugin.
   On CLion, also install the [Rust plugin](https://plugins.jetbrains.com/plugin/22407-rust)
   for language support.
2. On restart, you will get a notification that prompts you to allow importing
   the direnv configuration (`.envrc`). Do this.
3. Go to `File -> Settings -> Languages & Frameworks -> Rust`.
   Set your toolchain location to `[REPOSITORY ROOT]/.devenv/profile/bin`.
   Set the standard library (sources) path to
   `[REPOSITORY ROOT]/.devenv/profile/lib/rustlib/src/rust`.
   Save your changed settings.
4. Open `libcoap/Cargo.toml` (not `Cargo.toml` or `libcoap-sys/Cargo.toml`) in
   the IDE's editor, navigate to the line defining the `vendored` feature, and
   tick the checkmark to the left (between the line number and the line
   content).
   Because the provided development environment doesn't have a system-wide
   version of the C library to link against, this is necessary to allow the
   `Cargo` sync/code completion/etc. to work properly.

Note that changes to the environment (due to changes in `devenv.nix` or
`devenv.lock`) might require an IDE restart to apply.

### Manual Environment Setup

The specifics of manually setting up your environment depend on your operating
system and remaining environment.

In general, a development environment for libcoap-rs must contain all necessary
dependencies for building libcoap as well as a recent version of `Rust` (see the
`libcoap` and `libcoap-sys` crate's `Cargo.toml` for the current Minimum
Supported Rust Version).
These dependencies are also necessary for utilizing `libcoap-rs` as a library,
you can therefore refer to [`BUILDING.md`](BUILDING.md) for the current list
of dependencies.

Additionally, you will want to install the following tools:
- `clippy` and `rustfmt` (**strongly recommended**)

  These are static analysis tools we utilize to maintain a consistent code style
  and prevent common mistakes.
  If you've been writing Rust code for some time, you're probably already
  familiar with these tools.
    
  Resolving all `clippy` warnings and `rustfmt` lints is necessary before your
  merge/pull request can be accepted. The CI pipeline will also perform these
  checks and show lints in the Pull/Merge Request overview, but it is easier and
  quicker to run these tools and resolve these issues before creating a commit,
  pushing it, or creating a pull request.

  If you are using `rustup`, you can install these tools using
  `rustup component add rustfmt clippy`.
- Rust (and possibly C) integrations for your favorite code editor or IDE
  (**recommended**).

  As libcoap-rs is a Rust binding to a C library, you will probably want your
  editor to support both languages.
  
  For VSCode, you can use the `rust-lang.rust-analyzer` and `ms-vscode.cpptools`
  extensions for syntax highlighting and `vadimcn.vscode-lldb` for
  running/debugging support.
  
  If you're using JetBrains IDEs, you can use CLion for C support and install
  the [Rust plugin](https://plugins.jetbrains.com/plugin/22407-rust) to gain
  the functionality usually included with RustRover.

### Using Nix/devenv.sh with an IDE using devcontainers

> [!NOTE]
> This is only minimally tested, contributions for improvements are welcome.

We also provide a `.devcontainer.json` file conforming to the [Development
Containers](https://containers.dev/) specification for use with VS Code and
CLion (RustRover is untested as of now).

If you have the necessary dev container support installed in your IDE, you will
get a notification asking you whether you want to start the dev container when
opening the cloned repository.

For VS Code, everything should work out of the box. For CLion, you might have
to follow the [IDE setup outlined previously](#ide-setup) with the repository
root at `/IdeaProjects/libcoap-rs`, i.e.:
- Toolchain location: `/IdeaProjects/libcoap-rs/.devenv/profile/bin`
- Standard library: `/IdeaProjects/libcoap-rs/.devenv/profile/lib/rustlib/src/rust`

For both IDEs, don't forget to allow importing the direnv config/`.envrc` file
if prompted.

## Committing your Code

In general, we follow the typical workflow used for open source Git(Hub)
projects, which can be summed up as follows:
- If you are not a project member, create a fork of the `libcoap-rs` repository
- Create a separate branch for each independent "thing" (feature, bugfix, ...)
  you work on. Try to find a middle ground between creating too many branches
  for changes that are tightly coupled to each other and creating huge branches
  full of unrelated changes.
- Create a separate commit (within reason) for each independent change you make
  in your branch. Ideally, each commit represents an atomic intermediate step
  in development that can be independently tested and cherry-picked (although
  there are many situations in which this is not possible).
- Commit your changes to the appropriate branch with a descriptive commit
  message (see below).
- Prefer rebasing over merging when pulling in changes from the upstream main
  branch, *unless there is a good reason to merge*.
- Prefer using [fixup commits](https://git-scm.com/docs/git-commit/2.51.0#Documentation/git-commit.txt---fixupamendrewordcommit)
  over creating new commits when fixing code created in this branch.

For your commit message, adhere to the [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/)
specification. You may use types other than `fix` and `feat` in your commit
message where appropriate (e.g., `docs` for documentation changes or
`refactor` for refactorings). While `libcoap-rs` is not stable, you may omit
marking breaking changes explicitly.

The first line of your commit message must concisely describe the change you
made. Ideally, the remainder of the commit message describes both the reasoning
behind your change as well as any other important information relating to it.

## Submitting a Pull Request

Once you are happy with your changes, you may submit them for upstreaming by
creating a pull request. The upstream repository provides a template for the
pull request description that you should use when creating your PR.

Please make sure that your pull request is appropriately marked as ready for
review or as a draft. You may create a draft pull request if you intend to get
feedback on your code before it is ready for submission. If so, please indicate
the kind of feedback you want in your pull request description.

Before marking your PR as ready for review, please make sure to rebase and
[autosquash](https://git-scm.com/docs/git-rebase#Documentation/git-rebase.txt---autosquash)
your branch to clean up the commit history. Once the review process is
completed and your PR is approved, you should also rebase and squash any changes
made as part of the review process. **However, please do not rebase and/or
squash the commit history during the review process, as this will make it harder
to keep track of changes**.

For your Pull Request to be merged, the following conditions need to be met:
- You must have checked off all items in the checklist provided in the PR
  description template.
- The CI pipeline must complete without failures.
- All review comments must be addressed/your PR must be approved by a
  maintainer.
- Your commit history must be autosquashed to be free of any fixup commits
  created during the development process (i.e., you must autosquash all fixup
  commits **after** the review process is completed).
- Your branch should be free of merge conflicts with the upstream main branch.
- Your commit history should follow the recommendations made in
  [the previous section](#committing-your-code).

### Legal Considerations

For any code you submit as a contribution to the libcoap-rs repository, you
**must** ensure that you own all necessary rights to submit said code under the
project's license (BSD-2-Clause). Note that this may also have implications on
the use of code generated by Large Language Models (see below).

### LLM Usage Policy

In general, we do allow the use of Large Language Models for pull requests 
submitted to libcoap-rs. 

However:
- Usage of Large Language Models for code generation must be disclosed in the
  pull request. This disclosure must also include the model/tool used.
- The author of the pull request is responsible for the generated code, i.e.,
  we expect the person submitting the pull request to fully understand all code
  that they submit as if they wrote it themselves.
- The author of the pull request is still responsible for ensuring that all
  submitted code can be licensed under the project's license.

## Conduct Guidelines

While we do not have a formal code of conduct, we expect any contributor to be
respectful of others and act appropriately. We reserve the right to exclude any
contributor for any behavior that we deem to be inappropriate or malicious.
