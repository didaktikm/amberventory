# AmberVentory callback: streams per-host results to the job directory
# so the web UI can show live progress.
import json
import os
import time

from ansible.plugins.callback import CallbackBase

DOCUMENTATION = """
    name: amber
    type: aggregate
    short_description: write per-host results for AmberVentory
    description: Writes results/<host>.json and progress.jsonl into $AMBER_JOB_DIR.
"""


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "amber"
    CALLBACK_NEEDS_ENABLED = True

    def __init__(self):
        super().__init__()
        self.job_dir = os.environ.get("AMBER_JOB_DIR")
        if self.job_dir:
            os.makedirs(os.path.join(self.job_dir, "results"), exist_ok=True)

    def _emit(self, host, status, result):
        if not self.job_dir:
            return
        res = result._result if hasattr(result, "_result") else {}
        data = {
            "host": host,
            "status": status,
            "stdout": res.get("stdout", ""),
            "stderr": res.get("stderr", ""),
            "rc": res.get("rc"),
            "msg": str(res.get("msg", "")) if status != "ok" else "",
            "ts": time.time(),
        }
        safe = host.replace("/", "_")
        tmp = os.path.join(self.job_dir, "results", safe + ".json.tmp")
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, os.path.join(self.job_dir, "results", safe + ".json"))
        with open(os.path.join(self.job_dir, "progress.jsonl"), "a") as f:
            f.write(json.dumps({"host": host, "status": status, "ts": data["ts"],
                                "msg": data["msg"][:500]}) + "\n")

    def v2_runner_on_ok(self, result):
        self._emit(result._host.get_name(), "ok", result)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._emit(result._host.get_name(), "failed", result)

    def v2_runner_on_unreachable(self, result):
        self._emit(result._host.get_name(), "unreachable", result)
