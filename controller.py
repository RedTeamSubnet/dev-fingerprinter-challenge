import requests
import bittensor as bt

from redteam_core.challenge_pool.controller import Controller
from redteam_core.config.main import constants
from redteam_core.validator.models import MinerChallengeCommit


class DFPController(Controller):
    """
    A specialized controller for the 'dev_fingerprinter_v1' challenge.
    Inherits from the base Controller and modifies specific logic.
    """

    def __init__(
        self,
        challenge_name: str,
        challenge_info: dict,
        miner_commits: list[MinerChallengeCommit],
        reference_comparison_commits: list[MinerChallengeCommit],
        seed_inputs: list[dict] = [],
    ):
        """
        Initializes the DFPController, extending the original Controller.
        """
        super().__init__(
            challenge_name,
            challenge_info,
            miner_commits,
            reference_comparison_commits,
            seed_inputs,
        )

        comparison_config = self.challenge_info.get("comparison_config", {})
        self.comparison_min_acceptable_score = comparison_config.get(
            "min_acceptable_score", 0.6
        )

    def _score_miner_with_new_inputs(
        self, miner_commit: MinerChallengeCommit, challenge_inputs
    ):
        _scoring_log = miner_commit.scoring_logs[0]
        for i, miner_input in enumerate(challenge_inputs):

            _higest_comparison_score = miner_commit.get_higest_comparison_score()

            if (
                _higest_comparison_score >= self.comparison_min_acceptable_score
                or _higest_comparison_score == 0.0
            ):
                bt.logging.info(
                    f"[CONTROLLER - DFPController] Skipping scoring for miner {miner_commit.miner_hotkey} on task {i} due to high comparison score: {_higest_comparison_score}"
                )
                _scoring_log.score = 0.0
                if _scoring_log.error:
                    _scoring_log.error += (
                        " | Skipped scoring due to high comparison score."
                    )
                else:
                    _scoring_log.error = "Skipped scoring due to high comparison score."
                continue

            score = (
                self._score_challenge(
                    miner_input=miner_input,
                    miner_output=_scoring_log.miner_output,
                    task_id=i,
                )
                if _scoring_log.miner_output is not None
                else 0.0
            )
            scoring_results = self._get_scoring_results()

            _scoring_log.miner_output["scoring_results"] = scoring_results
            _scoring_log.score = score

    def _get_scoring_results(self) -> dict:
        """Retrieve scoring results from the challenge container."""

        _protocol, _ssl_verify = self._check_protocol(is_challenger=True)
        try:
            bt.logging.debug(f"[CONTROLLER] Getting scoring results ...")
            response = requests.get(
                f"{_protocol}://localhost:{constants.CHALLENGE_DOCKER_PORT}/results",
                verify=_ssl_verify,
                headers=self.challenge_info.get("scoring_headers", {}),
            )
            scoring_results = response.json()
        except Exception as ex:
            bt.logging.error(f"Score challenge failed: {str(ex)}")
            scoring_results = {}

        return scoring_results

    def _exclude_output_keys(self, miner_output: dict, reference_output: dict):
        miner_output["fingerprinter_js"] = None
        reference_output["fingerprinter_js"] = None
