from __future__ import annotations

import io
from typing import Optional, Sequence

from bitcash.cashaddress import Address
from bitcash.exceptions import InsufficientFunds, InvalidAddress
from bitcash.network.meta import Unspent
from bitcash.network.rates import currency_to_satoshi_cached
from bitcash.op import OpCodes
from bitcash.types import (
    CashTokens,
    NFTCapability,
    NFTData,
    PreparedOutput,
    TokenData,
    UserOutput,
)
from bitcash.utils import int_to_varint, varint_to_int


def _calculate_dust_value(address: Address, cashtokens: CashTokens) -> int:
    """
    Calculates dust value for output

    :param address: CashAddr address
    :param cashtokens: CashTokens
    """
    output = address.scriptcode + generate_cashtoken_prefix(cashtokens)
    return 444 + (8 + len(int_to_varint(len(output))) + len(output)) * 3


def parse_cashtoken_prefix(script: bytes) -> CashTokens:
    """
    Parses cashtoken prefix

    :param script: Token prefix with OP_TOKENPREFIX
    :returns: :class:~bitcash.types.CashTokens
    """
    # Assumes valid script
    category_id = None
    nft_capability = None
    nft_commitment = None
    token_amount = None

    has_commitment_length = False
    has_nft = False
    has_amount = False

    # make bytestream
    stream = io.BytesIO(script)

    if stream.read(1) != OpCodes.OP_TOKENPREFIX.binary:
        # no token info available
        return CashTokens(None, None, None, None)

    # OP_HASH256 byte order
    category_id = stream.read(32)[::-1].hex()

    token_bitfield = stream.read(1).hex()
    # 4 bit prefix
    prefix = bin(int(token_bitfield[0], 16))[2:]
    prefix = "0" * (4 - len(prefix)) + prefix
    prefix_structure = [bit == "1" for bit in prefix]
    if prefix_structure[1]:
        has_commitment_length = True
    if prefix_structure[2]:
        has_nft = True
    if prefix_structure[3]:
        has_amount = True

    nft_capability_bit = int(token_bitfield[1], 16)
    if has_nft:
        nft_capability = NFTCapability(nft_capability_bit)
    if has_commitment_length:
        commitment_length = varint_to_int(stream)
        nft_commitment = stream.read(commitment_length)
    if has_amount:
        token_amount = varint_to_int(stream)

    return CashTokens(category_id, nft_capability, nft_commitment, token_amount)


def generate_cashtoken_prefix(cashtoken: CashTokens) -> bytes:
    """
    Generates cashtoken prefix from cashtoken data

    :param cashtoken_output: Cashtoken output data
    :returns: Cahstoken prefix
    """
    if cashtoken.category_id is None:
        return b""

    # OP_HASH256 byte order
    script = OpCodes.OP_TOKENPREFIX.binary + bytes.fromhex(cashtoken.category_id)[::-1]
    prefix_structure = 0
    if cashtoken.nft_commitment is not None:
        prefix_structure += 4
    if cashtoken.nft_capability is not None:
        prefix_structure += 2
    if cashtoken.token_amount is not None:
        prefix_structure += 1
    nft_capability = (
        0 if cashtoken.nft_capability is None else cashtoken.nft_capability.value
    )
    # token bitfield
    token_bitfield = hex(prefix_structure)[2:] + hex(nft_capability)[2:]
    script += bytes.fromhex(token_bitfield)
    if cashtoken.nft_commitment is not None:
        script += int_to_varint(len(cashtoken.nft_commitment))
        script += cashtoken.nft_commitment
    if cashtoken.token_amount is not None:
        script += int_to_varint(cashtoken.token_amount)

    return script


def prepare_output(output: UserOutput) -> PreparedOutput:
    """
    Prepares output for sending transaction

    :param output: Output tuple of format: (destination address, amount, currency) or
                   (destination address, amount, currency, category_id, nft_capability,
                   nft_commitment, token_amount)
    :returns: Prepared output tuple of format (scriptcode with token prefix, amount in
              satoshis, category_id, nft_capability, nft_commitment, token_amount)
    """
    if len(output) == 3:
        output = (*output, None, None, None, None)
    elif len(output) == 6 and isinstance(output[0], bytes):
        # already prepared
        return output
    elif len(output) != 7:
        raise RuntimeError(
            "Output does not follow output format: (address, amount, currency) or "
            "(address, amount, currency, category_id, nft_capability, nft_commitment, "
            "token_amount)"
        )

    (
        dest,
        amount,
        currency,
        category_id,
        nft_capability,
        nft_commitment,
        token_amount,
    ) = output

    if not isinstance(dest, Address):
        dest = Address.from_string(dest)

    amount = currency_to_satoshi_cached(amount, currency)
    nft_capability = NFTCapability[nft_capability] if nft_capability else None
    cashtokens = CashTokens(category_id, nft_capability, nft_commitment, token_amount)
    cashtokens.verify()

    # check dust limit
    dust = _calculate_dust_value(dest, cashtokens)
    if amount < dust:
        raise InsufficientFunds(f"{amount=} less than {dust=} limit")

    # check for CashToken signal
    if "CATKN" not in dest.version and category_id is not None:
        raise InvalidAddress(
            f"{dest.cash_address()} does not signal CashToken support."
        )

    scriptcode = generate_cashtoken_prefix(cashtokens) + dest.scriptcode
    return PreparedOutput(scriptcode, amount, cashtokens)


class Unspents:
    """
    Class to count Unspents with cashtokens
    Incoming data is assumed to be valid, tests are performed when making
    outputs

    >>> unspents.tokendata = {
            "category_id": {           (string) token id hex
                "token_amount": "xxx", (int) fungible amount
                "nft" : [{
                  "capability": "xxx", (string) one of "none", "mutable",
                                        "minting"
                  "commitment": b"xxx" (bytes) NFT commitment
                }]
            }
        }
    """

    def __init__(self, unspents: Optional[list[Unspent]] = None):
        self.amount: int = 0
        self.tokendata: dict[str, TokenData] = {}
        # unspent txid that are valid genesis unspent
        self.genesis_unspent_txid: list[str] = []
        if unspents is not None:
            for unspent in unspents:
                self.add_unspent(unspent)

    def to_dict(self) -> dict:
        return {
            "amount": self.amount,
            "tokendata": {
                category_id: tokendata.to_dict()
                for category_id, tokendata in self.tokendata.items()
            },
        }

    @classmethod
    def from_dict(cls, dict_: dict) -> Unspents:
        instance = cls([])
        instance.amount = dict_["amount"]
        tokendata_dict = dict_["tokendata"]
        instance.tokendata = {
            category_id: TokenData.from_dict(tokendata)
            for category_id, tokendata in tokendata_dict.items()
        }
        return instance

    def add_unspent(self, unspent: Unspent) -> None:
        """
        Adds unspent

        :param unspent: An instance of Unspent to add
        :returns: None
        """
        self.amount += unspent.amount
        if unspent.has_cashtoken:
            assert unspent.cashtoken.category_id is not None
            categorydata = self.tokendata.get(
                unspent.cashtoken.category_id, TokenData.get_empty()
            )
            if unspent.has_amount:
                assert unspent.cashtoken.token_amount is not None
                categorydata.token_amount = (
                    categorydata.token_amount or 0
                ) + unspent.cashtoken.token_amount
            if unspent.has_nft:
                assert unspent.cashtoken.nft_capability is not None
                nftdata = NFTData(
                    capability=unspent.cashtoken.nft_capability,
                    commitment=unspent.cashtoken.nft_commitment,
                )
                categorydata.nft = (categorydata.nft or []) + [nftdata]
            self.tokendata.update({unspent.cashtoken.category_id: categorydata})

        # possible cashtoken genesis unspent
        if unspent.txindex == 0:
            self.genesis_unspent_txid.append(unspent.txid)

    def get_outputs(self, leftover: Address) -> tuple[list[PreparedOutput], int]:
        """
        Return sanitized outputs for the remaining cashtokens

        :param leftover: Leftover address to add the outputs
        :returns: List of prepared outputs and leftover amount
        """
        outputs: list[PreparedOutput] = []

        amount = self.amount

        category_id: Optional[str]
        token_amount: Optional[int]
        for category_id, tokendata in self.tokendata.items():
            token_amount = tokendata.token_amount
            if tokendata.nft is not None:
                for nft in tokendata.nft:
                    dust_value = _calculate_dust_value(
                        leftover,
                        CashTokens(
                            category_id,
                            nft.capability,
                            nft.commitment,
                            token_amount,
                        ),
                    )
                    outputs.append(
                        prepare_output(
                            (
                                leftover.cash_address(),
                                dust_value,
                                "satoshi",
                                category_id,
                                nft.capability.name,
                                nft.commitment,
                                token_amount,
                            )
                        )
                    )
                    # add token to first nft
                    token_amount = None
                    amount -= dust_value
            elif token_amount is not None:
                # token_amount but no nft
                dust_value = _calculate_dust_value(
                    leftover, CashTokens(category_id, None, None, token_amount)
                )
                outputs.append(
                    prepare_output(
                        (
                            leftover.cash_address(),
                            dust_value,
                            "satoshi",
                            category_id,
                            None,
                            None,
                            token_amount,
                        )
                    )
                )
                amount -= dust_value

        if len(outputs) == 0:
            # no tokendata
            if amount > 0:
                # add leftover amount
                outputs.append(
                    prepare_output((leftover.cash_address(), amount, "satoshi"))
                )
        else:
            if amount < 0:
                raise InsufficientFunds("Not enough sats")
            # add leftover amount to last out
            outputs[-1] = PreparedOutput(
                outputs[-1].scriptcode,
                outputs[-1].amount + amount,
                outputs[-1].cashtokens,
            )

        return outputs, amount

    def subtract_output(self, output: PreparedOutput) -> None:
        """
        Subtract output from cumulative unspent BCH and cashtoken amounts

        :param output: Prepared output.
        """
        _, amount, cashtokens = output
        category_id, nft_capability, nft_commitment, token_amount = cashtokens
        if self.amount < amount:
            raise InsufficientFunds("Not enough amount")
        self.amount -= amount

        if category_id is not None:
            if category_id in self.genesis_unspent_txid:
                # new token generated
                # only amount to be subtracted, the cashtoken doesn't exist in UTXO
                return
            if category_id not in self.tokendata.keys():
                raise InsufficientFunds("unspent category_id does not exist")
            categorydata = self.tokendata[category_id]
            if token_amount is not None:
                categorydata = _subtract_token_amount(categorydata, token_amount)
            if nft_capability is not None:
                nft = NFTData(capability=nft_capability, commitment=nft_commitment)
                categorydata = _subtract_nft(categorydata, nft)

            # update tokendata
            if categorydata.is_empty():
                self.tokendata.pop(category_id)
            else:
                self.tokendata.update({category_id: categorydata})


def _subtract_token_amount(categorydata: TokenData, token_amount: int) -> TokenData:
    if categorydata.token_amount is None:
        raise InsufficientFunds("No token amount")
    if categorydata.token_amount < token_amount:
        raise InsufficientFunds("Not enough token amount")
    categorydata.token_amount -= token_amount

    return _sanitize(categorydata)


def _subtract_nft(categorydata: TokenData, nft: NFTData) -> TokenData:
    """
    nft: [capability, commitment]
    """
    if categorydata.nft is None or len(categorydata.nft) == 0:
        raise InsufficientFunds("No nft found")
    # if immutable nft is asked, then immutable nft is spent
    # then a mutable nft is made to immutable, then minting
    # mints new nft.
    # if mutable nft is asked, then mutable nft is spent, then
    # minting mints new nft.
    # if minting nft is asked, then minting nft mints new.

    if nft.capability in [NFTCapability.none]:
        # immutable
        try:
            return _subtract_immutable_nft(categorydata, nft.commitment)
        except InsufficientFunds:
            pass

    if nft.capability in [NFTCapability.none, NFTCapability.mutable]:
        try:
            return _subtract_mutable_nft(categorydata)
        except InsufficientFunds:
            pass

    if nft.capability in [
        NFTCapability.none,
        NFTCapability.mutable,
        NFTCapability.minting,
    ]:
        try:
            return _subtract_minting_nft(categorydata)
        except InsufficientFunds:
            # none found
            raise InsufficientFunds("No capable nft found")
    raise RuntimeError("Unreachable code reached")


def _sanitize(categorydata: TokenData) -> TokenData:
    if categorydata.token_amount is not None and categorydata.token_amount <= 0:
        categorydata.token_amount = None
    if categorydata.nft is not None and len(categorydata.nft) == 0:
        categorydata.nft = None
    return categorydata


def _subtract_immutable_nft(categorydata: TokenData, commitment: Optional[bytes]):
    assert categorydata.nft is not None, "nft data must be present"
    # find an immutable to send
    for i, nft in enumerate(categorydata.nft):
        if nft.capability == NFTCapability.none and nft.commitment == commitment:
            # found immutable with same commitment
            categorydata.nft.pop(i)
            return _sanitize(categorydata)

    raise InsufficientFunds("No immutable nft")


def _subtract_mutable_nft(categorydata: TokenData) -> TokenData:
    assert categorydata.nft is not None, "nft data must be present"
    # find a mutable to send
    for i, nft in enumerate(categorydata.nft):
        if nft.capability == NFTCapability.mutable:
            # found mutable
            categorydata.nft.pop(i)
            return _sanitize(categorydata)

    raise InsufficientFunds("No mutable nft")


def _subtract_minting_nft(categorydata: TokenData) -> TokenData:
    assert categorydata.nft is not None, "nft data must be present"
    # find a minting to mint
    for nft in categorydata.nft:
        if nft.capability == NFTCapability.minting:
            # found minting
            return categorydata

    raise InsufficientFunds("No minting nft")


def select_cashtoken_utxo(
    unspents: list[Unspent], outputs: Sequence[PreparedOutput]
) -> tuple[list[Unspent], list[Unspent]]:
    """
    Function to select unspents that cover cashtokens of prepared outputs

    :param unspents: List of unspents to select from
    :param outputs: List of prepared outputs to cover cashtokens of
    :returns: Tuple of leftover unspents and unspents used to cover given outputs
    """
    unspents_used: list[Unspent] = []

    # if category id is txid of genesis unspent, then the unspent is mandatory
    mandatory_unspent_indices: set[int] = set()
    genesis_unspent_txid = {
        unspent.txid: i for i, unspent in enumerate(unspents) if unspent.txindex == 0
    }

    # tokendata in outputs
    tokendata: dict[str, TokenData] = {}

    # calculate needed cashtokens
    for output in outputs:
        category_id, nft_capability, nft_commitment, token_amount = output.cashtokens
        if category_id is not None:
            if category_id in genesis_unspent_txid.keys():
                indx = genesis_unspent_txid[category_id]
                mandatory_unspent_indices.add(indx)
                # not count cashtoken from genesis tx
                # the category id won't be in utxo
                continue
            categorydata = tokendata.get(category_id, TokenData.get_empty())
            if token_amount is not None:
                categorydata.token_amount = (
                    categorydata.token_amount or 0
                ) + token_amount
            if nft_capability is not None:
                nftdata = NFTData(
                    capability=nft_capability,
                    commitment=nft_commitment,
                )
                categorydata.nft = (categorydata.nft or []) + [nftdata]
            tokendata.update({category_id: categorydata})

    # add mandatory unspents, for genesis cashtoken
    for id_ in sorted(mandatory_unspent_indices)[::-1]:
        unspents_used.append(unspents.pop(id_))

    # add utxo that can fund the output tokendata
    # split unspent with cashtoken from rest
    unspents_cashtoken: list[Unspent] = []
    pop_ids: list[int] = []
    for i, unspent in enumerate(unspents):
        if unspent.has_cashtoken:
            unspents_cashtoken.append(unspent)
            pop_ids.append(i)
    for id_ in sorted(pop_ids)[::-1]:
        unspents.pop(id_)

    # sort and use required cashtoken unspents
    # cashtokens are selected with the same criteria as utxo selection for BCH
    # small token_amount is spent first, and for nft the order is to spend an
    # immutable if possible, or then spend a mutable with mutation or then
    # finally use a minting token to mint the output nft.
    unspents_cashtoken = sorted(unspents_cashtoken)
    pop_ids = []
    for i, unspent in enumerate(unspents_cashtoken):
        unspent_used = False

        assert unspent.cashtoken.category_id is not None
        categorydata = tokendata.get(
            unspent.cashtoken.category_id, TokenData.get_empty()
        )
        # check token_amount
        if unspent.has_amount and categorydata.token_amount is not None:
            assert unspent.cashtoken.token_amount is not None
            unspent_used = True
            categorydata.token_amount -= unspent.cashtoken.token_amount
            categorydata = _sanitize(categorydata)

        # check nft
        if unspent.has_nft and categorydata.nft is not None:
            categorydata, nft_used = _subtract_nft_output(unspent, categorydata)
            if nft_used:
                unspent_used = True

        if not unspent_used:
            continue

        # use unspent
        unspents_used.append(unspent)
        pop_ids.append(i)
        # update tokendata
        if categorydata.is_empty():
            tokendata.pop(unspent.cashtoken.category_id)
        else:
            tokendata.update({unspent.cashtoken.category_id: categorydata})
    for id_ in sorted(pop_ids)[::-1]:
        unspents_cashtoken.pop(id_)

    # sort the rest unspents and fund the bch amount
    # __gt__ and __eq__ will sort them with no cashtoken unspents first
    unspents = sorted(unspents + unspents_cashtoken)
    return unspents, unspents_used


def _subtract_nft_output(
    unspent: Unspent, categorydata: TokenData
) -> tuple[TokenData, bool]:
    assert categorydata.nft is not None, "nft data must be present"
    assert (
        unspent.cashtoken.nft_capability is not None
    ), "unspent nft capability must be present"
    if unspent.cashtoken.nft_capability == NFTCapability.minting:
        # minting pays all
        categorydata.nft = None
        return _sanitize(categorydata), True
    elif unspent.cashtoken.nft_capability == NFTCapability.mutable:
        # pays first mutable, or first immutable
        for i, nft in enumerate(categorydata.nft):
            if nft.capability == NFTCapability.mutable:
                categorydata.nft.pop(i)
                return _sanitize(categorydata), True
        else:
            for i, nft in enumerate(categorydata.nft):
                if nft.capability == NFTCapability.none:
                    categorydata.nft.pop(i)
                    return _sanitize(categorydata), True
    else:  # immutable
        for i, nft in enumerate(categorydata.nft):
            if (
                nft.capability == NFTCapability.none
                and nft.commitment == unspent.cashtoken.nft_commitment
            ):
                categorydata.nft.pop(i)
                return _sanitize(categorydata), True
    return categorydata, False
