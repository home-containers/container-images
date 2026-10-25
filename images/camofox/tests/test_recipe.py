"""Source-build packaging contracts, exercised without a container daemon."""
import json
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parents[1]
REVISION = "39c82094013480b373df6600d44c7f036f58356e"


def instructions(text):
    """Join Dockerfile continuations, ignoring standalone comments."""
    text = re.sub(r"(?m)^\s*#.*\n", "", text)
    return [line.strip() for line in text.replace("\\\n", " ").splitlines() if line.strip()]


class RecipeTests(unittest.TestCase):
    def test_source_recipe_preserves_upstream_contract_and_scopes_tools(self):
        text = (HERE / "Dockerfile").read_text()
        lines = instructions(text)
        self.assertEqual([x for x in lines if x.startswith("FROM ")], ["FROM ${NODE_IMAGE}"])
        self.assertIn("ARG NODE_IMAGE=node:22.23.4-trixie-slim", lines)
        self.assertIn(REVISION, text)
        self.assertIn("COPY .container-images/ /usr/local/share/camofox-build/", lines)
        self.assertIn("WORKDIR /app", lines)
        self.assertEqual([x for x in lines if x.startswith(("ENV ", "CMD ", "USER ", "ENTRYPOINT "))], [
            "ENV NODE_ENV=production", "ENV CAMOFOX_PORT=9377",
            'CMD ["sh", "-c", "node --max-old-space-size=${MAX_OLD_SPACE_SIZE:-128} server.js"]'])
        for command in ("COPY package.json package-lock.json ./", "COPY postinstall.js ./",
                        "COPY lib/camoufox-download.js ./lib/", "COPY server.js ./",
                        "COPY camofox.config.json ./", "COPY lib/ ./lib/", "COPY mcp/ ./mcp/",
                        "COPY plugins/ ./plugins/", "COPY scripts/ ./scripts/"):
            self.assertIn(command, lines)
        npm = next(x for x in lines if x.startswith("RUN ") and "npm ci" in x)
        self.assertIn("apt-get install -y", npm)
        self.assertLess(npm.index("build-essential"), npm.index("npm ci --omit=dev"))
        self.assertIn("apt-get purge -y --auto-remove build-essential", npm)
        self.assertIn("rm -rf /var/lib/apt/lists/*", npm)
        self.assertEqual(sum("build-essential" in x for x in lines if x.startswith("RUN ")), 1)
        runtime = next(x for x in lines if x.startswith("RUN ") and "libgtk-3-0" in x)
        self.assertIn("apt-get upgrade", runtime)
        for package in ("libgtk-3-0", "libdbus-glib-1-2", "libxt6", "libasound2", "libx11-xcb1",
                        "libxcomposite1", "libxcursor1", "libxdamage1", "libxfixes3", "libxi6",
                        "libxrandr2", "libxrender1", "libxss1", "libxtst6", "libegl1", "libgl1-mesa-dri",
                        "libgbm1", "xvfb", "fonts-liberation", "fonts-noto-color-emoji", "fontconfig",
                        "ca-certificates", "curl", "unzip", "python3", "libbrotli1", "x11vnc", "novnc",
                        "python3-websockify", "net-tools", "procps"):
            self.assertRegex(runtime, r"\b" + re.escape(package) + r"\b")
        self.assertIn("--install-browser", text)
        self.assertIn("--arch", text)
        self.assertIn("python3 -B -I /usr/local/share/camofox-build/verify_image.py", text)
        self.assertIn("ARG YT_DLP_VERSION=2026.08.19", lines)
        self.assertIn("ARG YT_DLP_SHA256_AMD64=58162f9bfdc27458ea47bfcb311cf47028f17d8154a8bf7d689861d46399230a", lines)
        self.assertIn("ARG YT_DLP_SHA256_ARM64=b16e4dab368a816cd05d477d698a605a6ae87ccee1c8ffd38fa21d7254141fcc", lines)
        self.assertIn("YT_DLP_ASSET=yt-dlp_linux ", text)
        self.assertIn("YT_DLP_ASSET=yt-dlp_linux_aarch64 ", text)
        self.assertIn("sh scripts/install-plugin-deps.sh", text)
        for obsolete in ("BASE_IMAGE", "node-runtime", "--mount", "--apply", "--node-candidate", "camoufox.zip", "|| true"):
            self.assertNotIn(obsolete, text)
        ignore = (HERE / ".dockerignore").read_text()
        self.assertNotIn("**\n", ignore)
        self.assertNotIn(".container-images", ignore)
        self.assertIn("node_modules", ignore)
        self.assertIn(".git", ignore)


if __name__ == "__main__":
    unittest.main()
