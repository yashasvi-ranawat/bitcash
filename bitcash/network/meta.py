from __future__ import annotations

from typing import Optional

from bitcash.types import CashTokens, NFTCapability

TX_TRUST_LOW = 1
TX_TRUST_MEDIUM = 6
TX_TRUST_HIGH = 30


class Unspent:
    """
    Represents an unspent transaction output (UTXO) with CashToken

    :param amount: Amount in satoshi
    :param confirmations: Number of confirmations of the UTXO
    :param script: locking bytecode hex of the UTXO, with no cashtoken prefix
    :param txid: txid hex of the transaction of UTXO
    :param txindex: transaction output index of UTXO
    :param category_id: category_id of cashtoken attached to the UTXO
    :param nft_capability: nft_capability of the cashtoken attached
    :param nft_commitment: nft_commitment of the cashtoken attached
    :param token_amount: fungible token amount of the cashtoken attached
    """

    __slots__ = (
        "amount",
        "confirmations",
        "script",
        "txid",
        "txindex",
        "cashtoken",
    )

    def __init__(
        self,
        amount: int,
        confirmations: int,
        script: str,
        txid: str,
        txindex: int,
        category_id: Optional[str] = None,
        nft_capability: Optional[str] = None,
        nft_commitment: Optional[bytes] = None,
        token_amount: Optional[int] = None,
    ):
        self.amount = amount
        self.confirmations = confirmations
        self.script = script
        self.txid = txid
        self.txindex = txindex
        self.cashtoken = CashTokens(
            category_id=category_id,
            nft_capability=NFTCapability[nft_capability]
            if nft_capability is not None
            else None,
            nft_commitment=nft_commitment,
            token_amount=token_amount,
        )

    def to_dict(self) -> dict:
        dict_ = {
            "amount": self.amount,
            "confirmations": self.confirmations,
            "script": self.script,
            "txid": self.txid,
            "txindex": self.txindex,
            "category_id": self.cashtoken.category_id,
            "nft_capability": self.cashtoken.nft_capability.name
            if self.cashtoken.nft_capability
            else None,
            "nft_commitment": self.cashtoken.nft_commitment.hex()
            if self.cashtoken.nft_commitment
            else None,
            "token_amount": self.cashtoken.token_amount,
        }
        return dict_

    @classmethod
    def from_dict(cls, d: dict) -> Unspent:
        nft_commitment = (
            bytes.fromhex(d["nft_commitment"]) if d.get("nft_commitment") else None
        )
        return cls(
            amount=d["amount"],
            confirmations=d["confirmations"],
            script=d["script"],
            txid=d["txid"],
            txindex=d["txindex"],
            category_id=d.get("category_id"),
            nft_capability=d.get("nft_capability"),
            nft_commitment=nft_commitment,
            token_amount=d.get("token_amount"),
        )

    @property
    def has_nft(self) -> bool:
        return self.cashtoken.nft_capability is not None

    @property
    def has_amount(self) -> bool:
        return self.cashtoken.token_amount is not None

    @property
    def has_cashtoken(self) -> bool:
        return self.has_amount or self.has_nft

    def __eq__(self, other) -> bool:
        return self.to_dict() == other.to_dict()

    def __gt__(self, other: Unspent) -> bool:
        """
        Method to help sorting of Unspents during spending
        """
        if self.has_nft:
            assert self.cashtoken.nft_capability is not None
            if not other.has_nft:
                return True
            assert other.cashtoken.nft_capability is not None
            if (
                self.cashtoken.nft_capability.value
                > other.cashtoken.nft_capability.value
            ):
                return True
            if (
                self.cashtoken.nft_capability.value
                < other.cashtoken.nft_capability.value
            ):
                return False
        elif other.has_nft:
            return False
        if self.has_amount:
            assert self.cashtoken.token_amount is not None
            if not other.has_amount:
                return True
            assert other.cashtoken.token_amount is not None
            if self.cashtoken.token_amount > other.cashtoken.token_amount:
                return True
            if self.cashtoken.token_amount < other.cashtoken.token_amount:
                return False
        elif other.has_amount:
            return False
        return self.amount > other.amount

    def __repr__(self) -> str:
        var_list = [
            f"{key}={repr(value)}"
            for key, value in self.to_dict().items()
            if value is not None
        ]
        return "Unspent({})".format(", ".join(var_list))
