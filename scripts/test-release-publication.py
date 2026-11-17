#!/usr/bin/env python3
"""Exercise the real publication shell block without signing keys or GitHub writes."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def publication():
    lines = (ROOT / ".github/workflows/release.yml").read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "- name: publish draft release")
    start = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |") + 1
    script = []
    for line in lines[start:]:
        if line and not line.startswith("          "):
            break
        script.append(line[10:])
    return "\n".join(script)


class PublicationTest(unittest.TestCase):
    def run_publication(self, exists, upload_exit=0):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "dist").mkdir()
            (work / "dist/artifact.apk").write_text("fixture")
            gh = work / "gh"
            gh.write_text("""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["CALLS"], "a") as out:
    out.write(json.dumps(sys.argv[1:]) + "\\n")
command = sys.argv[1:3]
exists = os.environ["EXISTS"] == "1"
if command == ["release", "view"]:
    sys.exit(0 if exists else 1)
if command == ["release", "create"]:
    # GitHub permits a second draft for a tag that already has a published release.
    sys.exit(2 if exists and "--draft" not in sys.argv else 0)
if command == ["release", "upload"]:
    sys.exit(int(os.environ["UPLOAD_EXIT"]))
sys.exit(3)
""")
            gh.chmod(0o700)
            env = dict(os.environ, PATH=str(work) + os.pathsep + os.environ["PATH"],
                       CALLS=str(work / "calls"), EXISTS=str(int(exists)),
                       UPLOAD_EXIT=str(upload_exit), GITHUB_REF_NAME="v0.6.1",
                       TAG="v0.6.1", GITHUB_REPOSITORY="Busnes-app/fixture",
                       RUNNER_TEMP=str(work), DIGEST="0" * 64)
            result = subprocess.run(["bash", "-e", "-c", publication()],
                                    cwd=work, env=env, capture_output=True, text=True)
            calls = [json.loads(line) for line in (work / "calls").read_text().splitlines()]
            return result, calls

    def test_existing_release_receives_assets(self):
        result, calls = self.run_publication(True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[:2] for call in calls],
                         [["release", "view"], ["release", "upload"]])

    def test_new_release_keeps_publication_mode(self):
        result, calls = self.run_publication(False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[-1][:2], ["release", "create"])
        self.assertEqual("--draft" in calls[-1], True)

    def test_asset_collision_fails_without_overwriting_or_creating(self):
        result, calls = self.run_publication(True, upload_exit=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls[-1][:2], ["release", "upload"])
        self.assertNotIn("--clobber", calls[-1])
        self.assertNotIn(["release", "create"], [call[:2] for call in calls])


if __name__ == "__main__":
    unittest.main()

