# Contributing to Amazing eBPF Learning & Practice

First off, thank you for considering contributing to this eBPF learning repository! It's people like you who make this resource valuable for the community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Adding Code Examples](#adding-code-examples)
  - [Improving Documentation](#improving-documentation)
  - [Creating Labs and Exercises](#creating-labs-and-exercises)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
  - [C/eBPF Code](#cebpf-code)
  - [Go Code](#go-code)
  - [Python Code](#python-code)
  - [Shell Scripts](#shell-scripts)
- [Testing Requirements](#testing-requirements)
- [Documentation Standards](#documentation-standards)
- [Pull Request Process](#pull-request-process)
- [Community Guidelines](#community-guidelines)
- [Recognition](#recognition)

---

## Code of Conduct

This project and everyone participating in it is governed by our commitment to:

- **Be Respectful**: Treat all contributors with respect and kindness
- **Be Inclusive**: Welcome contributors of all backgrounds and experience levels
- **Be Constructive**: Provide helpful feedback and accept criticism gracefully
- **Be Collaborative**: Work together to improve the project
- **Be Patient**: Remember everyone is learning

**Unacceptable behavior includes**:

- Harassment, discrimination, or offensive comments
- Personal attacks or trolling
- Publishing others' private information
- Other conduct which could reasonably be considered inappropriate

Project maintainers have the right to remove, edit, or reject contributions that violate these principles.

---

## How Can I Contribute?

### Reporting Bugs

Found a bug? Help us fix it!

**Before submitting a bug report**:

1. Check the [issue tracker](https://github.com/yourusername/Amazing-eBPF-learning-Practice/issues) to avoid duplicates
2. Verify the issue on the latest commit
3. Collect relevant information (kernel version, distro, error messages)

**How to submit a good bug report**:

```markdown
**Description**
Clear description of the issue

**To Reproduce**
Steps to reproduce:

1. Go to '...'
2. Run command '...'
3. See error

**Expected Behavior**
What you expected to happen

**Environment**

- OS: [e.g., Ubuntu 22.04]
- Kernel version: [e.g., 5.15.0]
- Architecture: [e.g., x86_64]
- Relevant tools: [e.g., clang 14.0]

**Additional Context**

- Error messages (full output)
- Relevant logs
- Screenshots if applicable
```

**Labels to use**:

- `bug` - Something isn't working
- `critical` - Blocks learning or causes crashes
- `documentation` - Issue with docs
- `help wanted` - Community input needed

---

### Suggesting Enhancements

Have an idea? We'd love to hear it!

**Before suggesting enhancements**:

1. Check if it already exists in issues or discussions
2. Consider if it fits the project scope (learning-focused)
3. Think about how it benefits learners

**How to suggest enhancements**:

```markdown
**Feature Description**
Clear description of the feature

**Use Case**
Why this feature is valuable for learners

**Proposed Implementation**
How you think this could be implemented (optional)

**Alternatives Considered**
Other approaches you've thought about

**Additional Context**
Examples, mockups, or references
```

**Labels to use**:

- `enhancement` - New feature or improvement
- `good first issue` - Good for newcomers
- `level-01` through `level-05` - Specific to a level

---

### Adding Code Examples

Code examples are the heart of this project!

**What makes a good code example**:

- **Correct**: Code compiles and runs without errors
- **Complete**: Includes all necessary files (Makefile, README)
- **Commented**: Clear inline comments explaining eBPF concepts
- **Tested**: Verified on at least one kernel version
- **Focused**: Demonstrates one concept clearly
- **Portable**: Uses CO-RE when applicable (Level 03+)

**Steps to add a code example**:

1. **Choose the appropriate level**:

   - Level 01: Basic eBPF concepts
   - Level 02: BCC/bpftrace examples
   - Level 03: libbpf/CO-RE examples
   - Level 04: Real-world applications
   - Level 05: Production patterns

2. **Create the example directory**:

   ```bash
   cd level-XX-name/examples/
   mkdir my-example
   cd my-example
   ```

3. **Include these files**:

   - Source code (`*.c`, `*.bpf.c`, `*.py`, `*.bt`, `*.go`)
   - `Makefile` (if applicable)
   - `README.md` explaining:
     - What the example does
     - How to compile and run it
     - What to observe
     - Learning objectives
     - Kernel version requirements

4. **Follow coding standards** (see below)

5. **Test thoroughly**:

   ```bash
   make clean
   make
   sudo ./your-program
   # Verify expected output
   ```

6. **Document clearly**:
   - Add inline comments explaining eBPF concepts
   - Include example output in README
   - Note any kernel version requirements

**Example structure**:

```
level-03-libbpf-and-core-programming/examples/04-my-example/
├── README.md                 # Overview and instructions
├── Makefile                  # Build system
├── my_example.bpf.c         # eBPF kernel program
├── my_example.c             # User-space loader
└── expected_output.txt      # Sample output (optional)
```

---

### Improving Documentation

Documentation is crucial for learners!

**Types of documentation improvements**:

- Fixing typos and grammar
- Clarifying confusing explanations
- Adding diagrams and visuals
- Expanding examples
- Updating outdated information
- Adding troubleshooting tips

**Documentation locations**:

- `README.md` (root) - Project overview
- `LEARNING_PATH.md` - Curriculum roadmap
- `level-XX-name/README.md` - Level-specific guides
- `level-XX-name/docs/` - Deep-dive documentation
- Inline code comments - Concept explanations

**Documentation standards**:

- Use clear, simple language
- Explain concepts before showing code
- Include concrete examples
- Provide troubleshooting tips
- Link to additional resources
- Use consistent formatting (see below)

---

### Creating Labs and Exercises

Hands-on practice is essential for learning!

**What makes a good lab**:

- **Clear Objective**: What will learners accomplish?
- **Guided Steps**: Step-by-step instructions
- **Challenges**: Optional harder tasks
- **Solutions**: Reference implementation
- **Learning Notes**: Explain why, not just how

**Lab structure**:

````markdown
# Lab: [Name]

## Objective

[What learners will accomplish]

## Prerequisites

- Completed Level XX
- Tools: [list required tools]

## Instructions

### Part 1: [Task Name]

1. Step with command
   ```bash
   $ command here
   ```
````

2. Expected output:
   ```
   output here
   ```

### Part 2: [Next Task]

...

## Challenges (Optional)

- [ ] Harder task 1
- [ ] Harder task 2

## Solution

[Link to solution or inline]

## Learning Notes

[Explain concepts, gotchas, best practices]

````

**Submit labs as**:
- Shell scripts in `level-XX-name/lab/`
- Markdown guides in `level-XX-name/lab/`
- With clear naming: `XX-descriptive-name.sh` or `XX-descriptive-name.md`

---

## Development Setup

### Prerequisites

1. **Linux System** (kernel 5.10+, 5.15+ recommended)
2. **Development Tools**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install -y \
     clang llvm \
     libbpf-dev libelf-dev zlib1g-dev \
     linux-headers-$(uname -r) \
     bpftool \
     make git

   # Fedora/RHEL
   sudo dnf install -y \
     clang llvm \
     libbpf-devel elfutils-libelf-devel zlib-devel \
     kernel-devel \
     bpftool \
     make git
````

3. **Optional Tools** (for specific contributions):
   - **Python 3.8+** (for BCC examples)
   - **Go 1.21+** (for Level 05 agent)
   - **Docker** (for containerized testing)
   - **kubectl** (for Kubernetes examples)

### Setting Up Your Fork

1. **Fork the repository** on GitHub

2. **Clone your fork**:

   ```bash
   git clone https://github.com/YOUR-USERNAME/Amazing-eBPF-learning-Practice.git
   cd Amazing-eBPF-learning-Practice
   ```

3. **Add upstream remote**:

   ```bash
   git remote add upstream https://github.com/ORIGINAL-OWNER/Amazing-eBPF-learning-Practice.git
   ```

4. **Create a branch for your work**:

   ```bash
   git checkout -b feature/my-contribution
   ```

5. **Verify your setup**:
   ```bash
   cd level-01-linux-and-ebpf-foundations/tools
   ./verify-setup.sh
   ```

---

## Coding Standards

### C/eBPF Code

**Style**:

- Follow Linux kernel coding style (K&R style)
- Indentation: 8-space tabs (or 4 spaces for consistency)
- Max line length: 100 characters
- Use descriptive variable names

**eBPF-Specific Requirements**:

1. **License Header** (REQUIRED for eBPF programs):

   ```c
   // SPDX-License-Identifier: GPL-2.0
   /* Copyright (c) [Year] [Your Name] */
   ```

2. **Includes**:

   ```c
   #include <linux/bpf.h>
   #include <bpf/bpf_helpers.h>
   // ... other includes
   ```

3. **Maps and Globals**:

   ```c
   struct {
       __uint(type, BPF_MAP_TYPE_HASH);
       __uint(max_entries, 10240);
       __type(key, u32);
       __type(value, u64);
   } my_map SEC(".maps");
   ```

4. **Program Definitions**:

   ```c
   SEC("tracepoint/syscalls/sys_enter_execve")
   int handle_execve(struct trace_event_raw_sys_enter *ctx) {
       // eBPF code here
       return 0;
   }
   ```

5. **Error Handling**:

   - Check all bpf*map*\* return values
   - Use bpf_printk for debugging (sparingly)
   - Handle NULL pointers from map lookups

6. **Bounds Checking** (CRITICAL):

   ```c
   // Always validate packet bounds
   if ((void *)(eth + 1) > data_end)
       return XDP_DROP;
   ```

7. **Comments**:
   - Explain **why**, not **what**
   - Note eBPF limitations (e.g., loop restrictions)
   - Document verifier workarounds

**Example**:

```c
// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Your Name */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Map to count events per PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} event_count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *count, one = 1;

    // Lookup existing count
    count = bpf_map_lookup_elem(&event_count, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        // Initialize new entry
        bpf_map_update_elem(&event_count, &pid, &one, BPF_ANY);
    }

    return 0;
}
```

---

### Go Code

**Style**:

- Follow official Go style guide (`gofmt`, `golint`)
- Use `go fmt` before committing
- Descriptive package and function names

**Best Practices**:

1. **Error Handling**:

   ```go
   if err != nil {
       return fmt.Errorf("failed to load eBPF program: %w", err)
   }
   ```

2. **Resource Cleanup**:

   ```go
   obj, err := loadObjects()
   if err != nil {
       return err
   }
   defer obj.Close()
   ```

3. **Context for Cancellation**:

   ```go
   ctx, cancel := context.WithCancel(context.Background())
   defer cancel()
   ```

4. **Comments**:
   - Document all exported functions
   - Explain complex logic
   - Note eBPF-specific behavior

**Example**:

```go
// LoadAndAttach loads the eBPF program and attaches it to the tracepoint.
// Returns cleanup function and error.
func LoadAndAttach() (func(), error) {
    // Load eBPF objects
    objs := &Objects{}
    if err := LoadObjects(objs, nil); err != nil {
        return nil, fmt.Errorf("loading objects: %w", err)
    }

    // Attach to tracepoint
    tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
    if err != nil {
        objs.Close()
        return nil, fmt.Errorf("attaching tracepoint: %w", err)
    }

    // Return cleanup function
    cleanup := func() {
        tp.Close()
        objs.Close()
    }

    return cleanup, nil
}
```

---

### Python Code

**Style**:

- Follow PEP 8
- Use descriptive variable names
- Type hints encouraged

**BCC-Specific**:

1. **Shebang and Encoding**:

   ```python
   #!/usr/bin/env python3
   # -*- coding: utf-8 -*-
   ```

2. **Error Handling**:

   ```python
   try:
       b = BPF(text=bpf_text)
   except Exception as e:
       print(f"Error loading BPF program: {e}", file=sys.stderr)
       sys.exit(1)
   ```

3. **Cleanup**:
   ```python
   if __name__ == "__main__":
       try:
           main()
       except KeyboardInterrupt:
           print("\nExiting...")
           sys.exit(0)
   ```

**Example**:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from bcc import BPF
import sys

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

BPF_HASH(counts, u32, u64);

int count_events(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *count, one = 1;

    count = counts.lookup(&pid);
    if (count) {
        (*count)++;
    } else {
        counts.update(&pid, &one);
    }
    return 0;
}
"""

def main():
    try:
        # Load BPF program
        b = BPF(text=bpf_text)
        b.attach_kprobe(event="do_sys_openat2", fn_name="count_events")

        print("Tracing... Ctrl-C to stop")
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nExiting...")

if __name__ == "__main__":
    main()
```

---

### Shell Scripts

**Style**:

- Use `#!/bin/bash` shebang
- Enable error checking
- Quote all variables

**Best Practices**:

1. **Error Handling**:

   ```bash
   #!/bin/bash
   set -e  # Exit on error
   set -u  # Error on undefined variable
   set -o pipefail  # Catch pipe errors
   ```

2. **Functions**:

   ```bash
   check_kernel_version() {
       local version
       version=$(uname -r | cut -d. -f1,2)
       echo "Kernel version: $version"
   }
   ```

3. **User Feedback**:

   ```bash
   echo "[INFO] Installing dependencies..."
   echo "[ERROR] Failed to install package" >&2
   ```

4. **Privilege Checks**:
   ```bash
   if [[ $EUID -ne 0 ]]; then
       echo "[ERROR] This script must be run as root"
       exit 1
   fi
   ```

---

## Testing Requirements

All contributions should be tested before submission.

### For Code Examples

**Required Tests**:

1. **Compilation Test**:

   ```bash
   make clean
   make
   # Should complete without errors
   ```

2. **Loading Test**:

   ```bash
   sudo ./your-program
   # Should load without verifier errors
   ```

3. **Functionality Test**:
   - Verify expected output
   - Test on realistic workload
   - Check for memory leaks (long-running programs)

**Test on Multiple Environments** (if possible):

- [ ] Ubuntu 22.04 (kernel 5.15)
- [ ] Ubuntu 24.04 (kernel 6.x)
- [ ] Fedora latest
- [ ] Different architectures (x86_64, ARM64)

**Document Test Results**:

```markdown
## Testing

Tested on:

- Ubuntu 22.04, kernel 5.15.0, x86_64
- Fedora 38, kernel 6.2.0, x86_64

Test results:

- ✅ Compilation successful
- ✅ eBPF program loads without verifier errors
- ✅ Expected output verified
- ✅ No memory leaks after 10 minutes
```

### For Documentation Changes

**Required Checks**:

1. **Spelling and Grammar**: Use a spell checker
2. **Markdown Rendering**: Preview in GitHub or markdown viewer
3. **Link Verification**: Ensure all links work
4. **Code Block Testing**: Verify all commands actually work

---

## Documentation Standards

### Markdown Formatting

**Headers**:

```markdown
# Top-Level Title

## Section

### Subsection

#### Sub-subsection
```

**Code Blocks**:

````markdown
```bash
$ sudo bpftool prog list
```
````

**Command Examples**:

- Use `$` for user commands
- Use `#` for root commands (or `sudo`)
- Show expected output when helpful

**Emphasis**:

- **Bold** for important terms
- _Italic_ for emphasis
- `code` for commands, files, variables

**Lists**:

```markdown
- Unordered list item
- Another item
  - Nested item

1. Ordered list item
2. Another item
```

**Links**:

```markdown
[Link text](URL)
[Internal link](#section-name)
```

**Tables**:

```markdown
| Column 1 | Column 2 |
| -------- | -------- |
| Data     | Data     |
```

---

## Pull Request Process

### Before Submitting

1. **Test your changes** (see Testing Requirements)
2. **Update documentation** if needed
3. **Follow coding standards**
4. **Commit with clear messages**:

   ```
   Add XDP example for ICMP echo filtering

   - Implements XDP program to drop ICMP echo requests
   - Adds Makefile and README
   - Tested on Ubuntu 22.04, kernel 5.15.0
   ```

5. **Sync with upstream**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

### Submitting the PR

1. **Push to your fork**:

   ```bash
   git push origin feature/my-contribution
   ```

2. **Create Pull Request** on GitHub

3. **Fill out the PR template**:

   ```markdown
   ## Description

   [What does this PR do?]

   ## Type of Change

   - [ ] Bug fix
   - [ ] New code example
   - [ ] Documentation improvement
   - [ ] New lab/exercise
   - [ ] Other (describe)

   ## Level(s) Affected

   - [ ] Level 01
   - [ ] Level 02
   - [ ] Level 03
   - [ ] Level 04
   - [ ] Level 05
   - [ ] Project-wide

   ## Testing

   - [ ] Tested on [OS/kernel]
   - [ ] Documentation verified
   - [ ] Links checked

   ## Checklist

   - [ ] Follows coding standards
   - [ ] Includes documentation
   - [ ] Tested thoroughly
   - [ ] No breaking changes
   ```

4. **Respond to feedback** promptly and respectfully

### After Submission

- Maintainers will review your PR
- Address any requested changes
- Once approved, it will be merged
- Your contribution will be recognized!

---

## Community Guidelines

### Communication

- **Be patient**: Maintainers are volunteers
- **Be clear**: Provide context and examples
- **Be respectful**: Assume good intentions
- **Be helpful**: Help others when you can

### Review Process

When reviewing others' contributions:

- Focus on content, not person
- Provide specific, actionable feedback
- Acknowledge good work
- Suggest improvements constructively

Example good review:

```markdown
Great example! A few suggestions:

1. Could you add a comment explaining why we need bounds checking here?
2. The Makefile is missing the `clean` target
3. Small typo in README: "recieve" → "receive"

Otherwise looks good! Thanks for contributing.
```

---

## Recognition

We value all contributions, big and small!

### How We Recognize Contributors

1. **Contributors List**: All contributors listed in README
2. **Release Notes**: Significant contributions mentioned
3. **GitHub Profile**: Your profile shows as a contributor
4. **Shout-outs**: Acknowledged in project updates

### Types of Contributions We Recognize

Not just code! We appreciate:

- Code examples and improvements
- Documentation and tutorials
- Bug reports and testing
- Community support and discussions
- Translations
- Design and diagrams

---

## Questions?

**Not sure where to start?**

- Check issues labeled `good first issue`
- Ask in [GitHub Discussions](https://github.com/yourusername/Amazing-eBPF-learning-Practice/discussions)
- Read existing examples for inspiration

**Need help with your contribution?**

- Open a draft PR and ask for guidance
- Reach out in discussions
- Check the documentation in each level

---

## Thank You!

Your contributions make this project better for everyone learning eBPF. We appreciate your time and effort!

Happy contributing! 🚀
