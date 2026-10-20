"""Sans VPS_HOST, publier.py doit refuser avec un message clair (avant tout travail)."""
import os, subprocess, sys, unittest

ICI = os.path.dirname(os.path.abspath(__file__))


class SansVpsHost(unittest.TestCase):
    def test_refus_clair(self):
        env = {k: v for k, v in os.environ.items() if k != "VPS_HOST"}
        r = subprocess.run([sys.executable, os.path.join(ICI, "publier.py")],
                           env=env, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("VPS_HOST non defini", r.stderr)


if __name__ == "__main__":
    unittest.main()
