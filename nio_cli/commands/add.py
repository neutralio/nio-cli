from .base import Base


class Add(Base):

    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)
        self._blocks = self.options['<block-repo>']
        self._upgrade = self.options['--upgrade'] or self.options['-u']
        self._project = self.options['--project']

    def run(self):
        body = {}
        url = self._base_url.format("project/blocks")
        for block in self._blocks:
            body["url"] = block
            try:
                response = self.post(url, json=body)
                print("Cloning '{}' result: {}".format(block, response.text))
            except Exception as e:
                print("Error cloning '{}' result: {}".format(block, str(e)))

        # Upgrade blocks if requested
        # Note: This needs to happen after `submodule update` or else the repos
        # will go back to the previously committed version of the submodules.
        if self._upgrade:
            blocks = ",".join(self._blocks)
            url = "{}?{}".format(
                self._base_url.format("project/blocks"), blocks)
            try:
                response = self.post(url, json={})
                print("Upgrading '{}' result: {}".format(blocks, response.text))
            except Exception as e:
                print("Error upgrading '{}' result: {}".format(blocks, str(e)))
