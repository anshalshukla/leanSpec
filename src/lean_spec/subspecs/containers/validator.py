"""Validator container for the Lean Ethereum consensus specification."""

from lean_spec.types import Bytes52, Container

from ..xmss.containers import PublicKey
from ..xmss.interface import PROD_SIGNATURE_SCHEME, TEST_SIGNATURE_SCHEME


class Validator(Container):
    """Represents a validator's static metadata."""

    pubkey: Bytes52
    """XMSS one-time signature public key."""

    def get_pubkey(self, test: bool = False) -> PublicKey:
        """Get the XMSS public key from this validator."""
        if test:
            scheme = TEST_SIGNATURE_SCHEME
        else:
            scheme = PROD_SIGNATURE_SCHEME

        return scheme.config.deserialize_public_key(bytes(self.pubkey))
