"""Container image vulnerability scan using Trivy (optional)."""
import json
import shutil
import subprocess

from .base import finding, make_result


def scan(root, image=None, **_):
    if not image:
        return make_result("Container Image Scan", "trivy", [], status="SKIPPED",
                           note="No image supplied (use --image NAME:TAG).")
    exe = shutil.which("trivy")
    if not exe:
        return make_result("Container Image Scan", "trivy", [], status="SKIPPED",
                           note="Trivy is not installed.")
    try:
        p = subprocess.run([exe, "image", "--quiet", "--format", "json", "--severity", "CRITICAL,HIGH,MEDIUM", image],
                           capture_output=True, text=True, timeout=600)
        data = json.loads(p.stdout or "{}")
    except Exception as e:
        return make_result("Container Image Scan", "trivy", [], status="SKIPPED", note=f"Trivy failed: {e}")
    out = []
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            out.append(finding("image", v.get("Severity", "MEDIUM").upper(),
                               f"{v.get('PkgName')} {v.get('InstalledVersion')} - {v.get('VulnerabilityID')}",
                               res.get("Target"), None,
                               f"Upgrade to {v['FixedVersion']}." if v.get("FixedVersion") else "Rebuild on a patched base image.",
                               tool="trivy", ref=v.get("VulnerabilityID")))
    return make_result("Container Image Scan", "trivy", out)
