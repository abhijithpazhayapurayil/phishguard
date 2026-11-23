"""Stream fixed public benchmark archives into the local PhishGuard evaluator."""
import csv
import hashlib
import io
import json
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

SOURCES = {
    "phiusiil": "https://archive.ics.uci.edu/static/public/967/phiusiil%2Bphishing%2Burl%2Bdataset.zip",
    "sms-spam": "https://archive.ics.uci.edu/static/public/228/sms%2Bspam%2Bcollection.zip",
}

def rows(directory):
    for source, filename in (("phiusiil", "urls.zip"), ("sms-spam", "sms.zip")):
        path = directory / filename
        if not path.exists():
            temporary = path.with_suffix(".partial")
            with urllib.request.urlopen(SOURCES[source], timeout=120) as response, temporary.open("wb") as target:
                shutil.copyfileobj(response, target)
            temporary.replace(path)
        with path.open("rb") as archive:
            digest = hashlib.file_digest(archive, "sha256").hexdigest()
        yield {"source": source, "sha256": digest}
        with zipfile.ZipFile(path) as archive:
            suffix = ".csv" if source == "phiusiil" else "SMSSpamCollection"
            member = next(name for name in archive.namelist() if name.endswith(suffix))
            with archive.open(member) as stream:
                text = io.TextIOWrapper(stream, encoding="utf-8-sig", newline="")
                if source == "phiusiil":
                    for row in csv.DictReader(text):
                        yield {"source": source, "input": row["URL"],
                               "label": {"0": "phishing", "1": "legitimate"}[row["label"]]}
                else:
                    for line in text:
                        label, message = line.rstrip("\r\n").split("\t", 1)
                        yield {"source": source, "input": message, "label": label}

    edge = directory / "edgephish.csv"
    if edge.exists():
        with edge.open("rb") as archive:
            digest = hashlib.file_digest(archive, "sha256").hexdigest()
        yield {"source": "edgephish", "sha256": digest}
        with edge.open(encoding="utf-8-sig", newline="") as stream:
            for row in csv.DictReader(stream):
                yield {"source": "edgephish", "input": row["url"],
                       "label": {"0": "legitimate", "1": "phishing"}[row["label"]]}

def main():
    directory = Path(sys.argv[1])
    directory.mkdir(parents=True, exist_ok=True)
    evaluator = Path(__file__).resolve().with_name("evaluate-corpus.mjs")
    with subprocess.Popen(["node", str(evaluator)], stdin=subprocess.PIPE, encoding="utf-8") as process:
        for row in rows(directory):
            process.stdin.write(json.dumps(row, ensure_ascii=True) + "\n")
        process.stdin.close()
        return process.wait()

if __name__ == "__main__":
    sys.exit(main())

