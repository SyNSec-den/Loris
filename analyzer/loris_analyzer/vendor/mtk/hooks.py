from loris_analyzer.util import utils


class SimMsgReceiveExtq(utils.SimProcedure):
    def __init__(self, *args, num_msg_buf: int = 1, **kwargs):
        super().__init__(*args, **kwargs)
        self._num_msg_buf = num_msg_buf

    def run(self, p_qitem):
        self._log_call(p_qitem)
        import IPython

        IPython.embed()


symbol_mappings = [
    {
        "name": "msg_receive_extq",
        "symbol": "msg_receive_extq",
        "simproc": SimMsgReceiveExtq,
    },
]
