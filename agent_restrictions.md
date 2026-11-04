# Agent restrictions

These rules apply to the main agent throughout its work. The dedicated
`dtb-vision` tool agent may analyze the image supplied by `dbg_screenshot`.

1. Never launch the simulator. Testing happens on the physical DTB.
2. Control the stand only through `dbg_*` tools. Do not open serial ports,
   call SSH directly, or use the old `tools/*.py` scripts. The daemon owns the
   hardware and SSH master. Reading and editing `control/` is allowed; competing
   with the daemon for the serial port or the SSH master is not.
3. Never infer state that can be read. Call `dbg_status` first.
4. A timeout is not a failure until the verdict says so: `slow` means wait,
   `wedged` means reset. Do not reset a machine that is still `booting`.
5. Do not test a stale build. `dbg_boot` refuses one; rebuild first.
6. Do not commit secrets, credentials, or absolute host paths.
7. Do not inspect or analyze images manually or attach them to the main agent
   session: image input can corrupt the OpenCode GLM session. All image work
   must use an image-analysis tool. For a DTB screenshot, call `dbg_screenshot`
   with the question; use its returned text. If an appropriate tool is unavailable
   or fails, report the limitation instead of opening the image directly.
   **Exemption:** the `dtb-vision` agent exists solely to describe an image
   supplied to it by `dbg_screenshot`. That is the image-analysis tool, not the
   main session, so this rule does not forbid it from reading the image.
8. Before reading documentation, identify the smallest relevant document using
   `database/index.md`. If four documents are needed for one question, fix the
   documentation as part of the task. Never re-read a document already cited in
   the same session.
9. Debug printing, especially serial output in the hypervisor's hot path, can
   slow the DTB significantly and distort timing-sensitive tests. Keep logging
   minimal and account for its overhead when interpreting slow runs.
