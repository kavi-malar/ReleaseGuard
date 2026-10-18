"""Dockerfile best-practice / security validation."""
import os
import re

from .base import finding, iter_files, read_text, rel, make_result

REC = {
    "tag": "Pin the base image to a specific version, e.g. python:3.12-slim.",
    "user": "Add a non-root user and switch to it with USER before CMD/ENTRYPOINT.",
    "pipe": "Download the script, verify its checksum, then execute it - never pipe curl into a shell.",
}


def _check_file(path, root):
    f = rel(path, root)
    out = []
    lines = read_text(path).splitlines()
    last_user, has_health, stages = None, False, set()
    for no, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        up = line.upper()
        if up.startswith("FROM "):
            parts = line.split()
            image = parts[1]
            if len(parts) >= 4 and parts[2].upper() == "AS":
                stages.add(parts[3].lower())
            last_user = None
            if image.lower() not in stages and image.lower() != "scratch" and "$" not in image:
                if ":" not in image.split("/")[-1] and "@" not in image:
                    out.append(finding("dockerfile", "MEDIUM", f"Base image '{image}' has no tag (implicitly :latest)", f, no, REC["tag"]))
                elif image.endswith(":latest"):
                    out.append(finding("dockerfile", "MEDIUM", f"Base image '{image}' uses the :latest tag", f, no, REC["tag"]))
        elif up.startswith("USER "):
            last_user = line.split()[1]
            if last_user.lower() in ("root", "0"):
                out.append(finding("dockerfile", "HIGH", "Container explicitly runs as root", f, no, REC["user"]))
        elif up.startswith("HEALTHCHECK"):
            has_health = True
        elif up.startswith("ADD ") and re.search(r"https?://", line):
            out.append(finding("dockerfile", "MEDIUM", "ADD used with a remote URL", f, no,
                               "Use COPY for local files, or curl with checksum verification for remote files."))
        elif up.startswith(("ENV ", "ARG ")) and re.search(r"(?i)(password|secret|token|api_?key)\w*\s*=\s*\S+", line):
            out.append(finding("dockerfile", "HIGH", "Secret baked into image via ENV/ARG", f, no,
                               "Pass secrets at runtime (env vars, Docker/BuildKit secrets), not at build time."))
        elif up.startswith("EXPOSE") and re.search(r"\b22\b", line):
            out.append(finding("dockerfile", "MEDIUM", "SSH port 22 exposed", f, no, "Do not run SSH in containers; use docker exec."))
        if re.search(r"(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh", line):
            out.append(finding("dockerfile", "HIGH", "Remote script piped directly into a shell", f, no, REC["pipe"]))
        if "chmod 777" in line or "chmod -R 777" in line:
            out.append(finding("dockerfile", "MEDIUM", "World-writable permissions (chmod 777)", f, no, "Use least-privilege permissions such as 755 or 644."))
        if re.search(r"apt-get install", line) and "--no-install-recommends" not in line:
            out.append(finding("dockerfile", "LOW", "apt-get install without --no-install-recommends", f, no, "Add --no-install-recommends to keep the image small."))
    if last_user is None and not any(fd["title"].startswith("Container explicitly") for fd in out):
        out.append(finding("dockerfile", "MEDIUM", "No USER instruction - container runs as root by default", f, None, REC["user"]))
    if not has_health:
        out.append(finding("dockerfile", "LOW", "No HEALTHCHECK instruction", f, None, "Add a HEALTHCHECK so orchestrators can detect unhealthy containers."))
    return out


def scan(root, **_):
    def _is_dockerfile(p):
        b = os.path.basename(p).lower()
        return b == "dockerfile" or b.startswith("dockerfile.") and not b.endswith((".py", ".md", ".txt")) \
            or b.endswith(".dockerfile")
    files = [p for p in iter_files(root) if _is_dockerfile(p)]
    if not files:
        return make_result("Dockerfile Validation", "builtin-rules", [], status="SKIPPED",
                           note="No Dockerfile found.")
    out = []
    for p in files:
        out += _check_file(p, root)
        d = os.path.dirname(p)
        if not os.path.exists(os.path.join(d, ".dockerignore")):
            out.append(finding("dockerfile", "LOW", "Missing .dockerignore", rel(p, root), None,
                               "Add .dockerignore (.git, .env, node_modules...) to avoid leaking files into the image."))
    return make_result("Dockerfile Validation", "builtin-rules", out)
