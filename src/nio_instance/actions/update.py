from .base import Action
from ..util import NIOClient


class UpdateAction(Action):
    
    def perform(self):
        for blk in self.args.block_types:
            NIOClient.update(blk)
