import loggable
import subprocess

class HookChallenge(loggable.Loggable):
    def __init__(self, path):
        self._path = path

    def deploy(self, domain, token):
        cmd = [self._path, "deploy_challenge", domain, token]

        self.log("Trying to deploy challenge for %s" % domain)
        self.log("CMD: " + " ".join(cmd))

        proc = subprocess.Popen([self._path, "deploy_challenge", domain, "default", token], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        ret = proc.poll()
        while not ret:
            ret = proc.poll()
            if ret is not None:
                for line in proc.stdout.readlines():
                    self.log("[HOOK] %s" % line)
                break
            self.log("[HOOK] %s" % proc.stdout.readline())

    def clean(self, domain):
        self.log("Cleaning up for %s" % domain)
        pass
