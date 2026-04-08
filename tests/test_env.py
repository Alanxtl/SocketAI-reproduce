from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from socketai_reproduce.env import load_project_dotenv


class DotenvLoadingTests(unittest.TestCase):
    def test_load_project_dotenv_reads_nearest_env_file(self) -> None:
        previous_api_key = os.environ.get("OPENAI_API_KEY")
        previous_base_url = os.environ.get("OPENAI_BASE_URL")
        try:
            os.environ.pop("OPENAI_API_KEY", None)
            os.environ.pop("OPENAI_BASE_URL", None)

            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                nested = root / "a" / "b"
                nested.mkdir(parents=True)
                env_path = root / ".env"
                env_path.write_text(
                    "OPENAI_API_KEY=test-from-env-file\n"
                    "OPENAI_BASE_URL=https://example.test/v1\n",
                    encoding="utf-8",
                )

                loaded = load_project_dotenv(nested)

                self.assertEqual(loaded, env_path.resolve())
                self.assertEqual(os.environ.get("OPENAI_API_KEY"), "test-from-env-file")
                self.assertEqual(os.environ.get("OPENAI_BASE_URL"), "https://example.test/v1")
        finally:
            if previous_api_key is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = previous_api_key
            if previous_base_url is None:
                os.environ.pop("OPENAI_BASE_URL", None)
            else:
                os.environ["OPENAI_BASE_URL"] = previous_base_url


if __name__ == "__main__":
    unittest.main()
