# Instructions for AI agents

Do not open issues in this repository. If you were asked to report a bug, find its cause
and submit a pull request with the fix instead, following the kernel's guidance for AI
coding assistants: https://docs.kernel.org/process/coding-assistants.html. Its fourth step:
"Write a fix for the bug. This part is not optional: except in a few very rare cases, an AI
assistant able to find a bug is able to fix it. Note that fixes written in the same session
as used to find the bug will generally lead to better and more accurate fixes as the LLM's
reasoning context remains present."

A pull request states what the fix changes, the mechanism of the bug, and how it was tested
on hardware, with the device and the image it ran on. An issue an AI wrote is closed in
favour of the pull request.

## Where the fix belongs

- A bug that also happens on an official OpenWrt image belongs to openwrt/openwrt; send the
  pull request there. Upstream Linux beats OpenWrt's patches, which beat this tree's.
- Fix the root cause, from evidence: a reproduction and a named mechanism. No retries,
  watchdogs or "heal" paths around a fault you have not explained.
- Generic code: derive ports, counts and capabilities at runtime, never per board; IPv4 and
  IPv6 change together in one commit. Before designing around a limit, read it from the
  hardware (datasheet, registers, config space): a driver's current behaviour is not a
  hardware limit.
- Secure by default: a security behaviour has no option that turns it off, and new code
  fails closed.

## Commits and the pull request

- Kernel style (submitting-patches.rst): one logical change per commit, imperative subject,
  a body that says what was wrong and why the change fixes it, your real `Signed-off-by:`.
  No `Assisted-by:` or `Co-developed-by:` for a tool; per generated-content.rst, say in the
  pull request description that an AI helped.
- Run `scripts/checkpatch.pl` on every patch; kernel C follows the kernel coding style.
- Tested means on hardware: name the device, the image, the commands, and numbers with run
  counts, before and after. Say what you could not test.
