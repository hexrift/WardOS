#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


class VerifierCacheContract(unittest.TestCase):
    def test_actual_verifier_command_uses_both_cached_stage_targets(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/tamperward.yml').read_text())
        job = workflow['jobs']['tamperward-verify']
        steps = job['steps']
        verify = next(step for step in steps if step.get('name') == 'Tamperward verify (pristine re-execution)')
        cache = next(step for step in steps if step.get('uses', '').startswith('Swatinem/rust-cache@'))
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            workspace = temporary / 'checkout'
            workspace.mkdir()
            binaries = temporary / 'bin'
            binaries.mkdir()
            capture = temporary / 'arguments.json'
            npx = binaries / 'npx'
            npx.write_text('#!/usr/bin/env python3\nimport json, os, sys\nfrom pathlib import Path\nPath(os.environ["CAPTURE"]).write_text(json.dumps(sys.argv[1:]))\n')
            npx.chmod(0o755)
            command = verify['run'].replace('${{ github.event.pull_request.base.sha }}', 'a' * 40)
            environment = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ['PATH'], GITHUB_WORKSPACE=str(workspace), CAPTURE=str(capture))
            subprocess.run(['bash', '-eu', '-c', command], cwd=workspace, env=environment, check=True)
            args = json.loads(capture.read_text())
            self.assertIn('--require-ancestor', args)
            self.assertEqual(args[args.index('--base') + 1], 'a' * 40)
            self.assertIn('--cargo-target-root', args)
            output_root = Path(args[args.index('--cargo-target-root') + 1]).resolve()
            self.assertFalse(output_root.is_relative_to(workspace))
            mappings = cache.get('with', {}).get('workspaces', '').splitlines()
            cached = {(workspace / mapping.split('->')[1].strip()).resolve() for mapping in mappings if '->' in mapping}
            self.assertEqual(cached, {output_root / 'visible', output_root / 'pristine'})
            self.assertEqual(str(cache['with']['cache-workspace-crates']).lower(), 'false')
            self.assertFalse(cache['with'].get('cache-on-failure', False))
        self.assertEqual(job['timeout-minutes'], 75)
        policy = yaml.safe_load((ROOT / '.tamperward.yml').read_text())
        self.assertEqual(policy['verify']['command'], 'bash scripts/verify/tamperward.sh')
        self.assertEqual(policy['verify']['budget'], 3600)


if __name__ == '__main__':
    unittest.main()
