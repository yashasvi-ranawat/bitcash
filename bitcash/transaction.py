import logging
from collections import namedtuple
from copy import deepcopy

from bitcash.crypto import double_sha256, sha256
from bitcash.exceptions import InsufficientFunds
from bitcash.cashtoken import (
    prepare_cashtoken_aware_output,
    CashTokenUnspents,
    CashTokenOutputs
)
from bitcash.op import OpCodes
from bitcash.utils import (
    bytes_to_hex,
    chunk_data,
    hex_to_bytes,
    int_to_unknown_bytes,
    int_to_varint,
)

VERSION_1 = 0x01.to_bytes(4, byteorder="little")
SEQUENCE = 0xFFFFFFFF.to_bytes(4, byteorder="little")
LOCK_TIME = 0x00.to_bytes(4, byteorder="little")

##
# Python 3 doesn't allow bitwise operators on byte objects...
HASH_TYPE = 0x01.to_bytes(4, byteorder="little")
# BitcoinCash fork ID.
SIGHASH_FORKID = 0x40.to_bytes(4, byteorder="little")
# So we just do this for now. FIXME
HASH_TYPE = 0x41.to_bytes(4, byteorder="little")
##

MESSAGE_LIMIT = 220


class TxIn:
    __slots__ = ("script", "script_len", "txid", "txindex", "amount")

    def __init__(self, script, script_len, txid, txindex, amount):
        self.script = script
        self.script_len = script_len
        self.txid = txid
        self.txindex = txindex
        self.amount = amount

    def __eq__(self, other):
        return (
            self.script == other.script
            and self.script_len == other.script_len
            and self.txid == other.txid
            and self.txindex == other.txindex
            and self.amount == other.amount
        )

    def __repr__(self):
        return (
            f"TxIn({repr(self.script)}, "
            f"{repr(self.script_len)}, "
            f"{repr(self.txid)}, "
            f"{repr(self.txindex)}, "
            f"{repr(self.amount)})"
        )


Output = namedtuple("Output", ("address", "amount", "currency"))


def calc_txid(tx_hex):
    return bytes_to_hex(double_sha256(hex_to_bytes(tx_hex))[::-1])


def estimate_tx_fee(n_in, output_script_list, satoshis, compressed):

    if not satoshis:
        return 0

    n_out = len(output_script_list)

    estimated_size = (
        4  # version
        + len(int_to_unknown_bytes(n_in, byteorder="little"))
        + n_in * (148 if compressed else 180)
        + len(int_to_unknown_bytes(n_out, byteorder="little"))
        + n_out * 9  # satoshi_value + script_len
        + sum([len(script) for script in output_script_list])
        + 4  # time lock
    )

    estimated_fee = estimated_size * satoshis

    logging.debug(
        f"Estimated fee: {estimated_fee}"
        f" satoshis for {estimated_size} bytes"
    )

    return estimated_fee


def get_op_pushdata_code(dest):
    length_data = len(dest)
    if length_data <= 0x4C:  # (https://en.bitcoin.it/wiki/Script)
        return length_data.to_bytes(1, byteorder="little")
    elif length_data <= 0xFF:
        return OpCodes.OP_PUSHDATA1.b + length_data.to_bytes(
            1, byteorder="little"
        )  # OP_PUSHDATA1 format
    elif length_data <= 0xFFFF:
        return OpCodes.OP_PUSHDATA2.b + length_data.to_bytes(
            2, byteorder="little"
        )  # OP_PUSHDATA2 format
    else:
        return OpCodes.OP_PUSHDATA4.b + length_data.to_bytes(
            4, byteorder="little"
        )  # OP_PUSHDATA4 format


def sanitize_tx_data(
    unspents,
    outputs,
    fee,
    leftover,
    combine=True,
    message=None,
    compressed=True,
    custom_pushdata=False,
):
    """
    sanitize_tx_data()

    fee is in satoshis per byte.
    """

    outputs = outputs.copy()

    for i, output in enumerate(outputs):
        # (script, satoshi value, CashTokenOutput)
        outputs[i] = prepare_cashtoken_aware_output(output)

    if not unspents:
        raise ValueError("Transactions must have at least one unspent.")

    # Temporary storage so all outputs precede messages.
    messages = []

    if message and (custom_pushdata is False):
        try:
            message = message.encode("utf-8")
        except AttributeError:
            pass  # assume message is already a bytes-like object

        message_chunks = chunk_data(message, MESSAGE_LIMIT)

        for message in message_chunks:
            script = (
                OpCodes.OP_RETURN.b
                + get_op_pushdata_code(message)
                + message
            )
            messages.append((script, 0, None))

    elif message and (custom_pushdata is True):
        if len(message) >= 220:
            # FIXME add capability for >220 bytes for custom pushdata elements
            raise ValueError(
                "Currently cannot exceed 220 bytes with custom_pushdata."
            )
        else:
            # manual control over number of bytes in each batch of pushdata
            if type(message) != bytes:
                raise TypeError("custom pushdata must be of type: bytes")
            else:
                script = OpCodes.OP_RETURN.b + message
            messages.append((script, 0, None))

    # counting outs, will adjust fee estimate
    output_script_list = [_[0] for _ in outputs]
    output_script_list += [_[0] for _ in messages]

    if combine:
        cashtoken = CashTokenUnspents(unspents)
        for output in outputs:
            cashtoken.subtract_output(output[2])
        leftover_outputs, leftover_amount = cashtoken.get_outputs(leftover)
        output_script_list += [_[0] for _ in leftover_outputs]
        # calculated_fee is in total satoshis.
        calculated_fee = estimate_tx_fee(
            len(unspents),
            output_script_list,
            fee,
            compressed,
        )
        if calculated_fee > leftover_amount:
            raise InsufficientFunds("leftover balance cannot cover fee")
        if calculated_fee:
            last_out = list(leftover_outputs[-1])
            last_out[1] -= calculated_fee
            last_out[2].amount -= calculated_fee
            leftover_outputs[-1] = tuple(last_out)

        outputs += leftover_outputs

    else:
        # split unspent with cashtoken from rest
        unspents_cashtoken = []
        pop_ids = []
        for i, unspent in enumerate(unspents):
            if unspent.has_cashtoken:
                unspents_cashtoken.append(unspent)
                pop_ids.append(i)
        for id_ in sorted(pop_ids)[::-1]:
            unspents.pop(id_)

        # sort and use required cashtoken unspents
        unspents_cashtoken = sorted(unspents_cashtoken)
        unspents_used = []
        pop_ids = []
        cashtokenoutputs = CashTokenOutputs(outputs)
        for i, unspent in enumerate(unspents_cashtoken):
            try:
                cashtokenoutputs.subtract_unspent(unspent)
            except ValueError:
                continue
            unspents_used.append(unspent)
            pop_ids.append(i)
        for id_ in sorted(pop_ids)[::-1]:
            unspents_cashtoken.pop(id_)

        # sort the rest unspents and fund the bch amount
        # __gt__ and __eq__ will sort them with no cashtoken unspents first
        unspents = sorted(unspents + unspents_cashtoken)

        index = 0

        cashtoken = CashTokenUnspents(unspents_used)
        for index, unspent in enumerate(unspents):
            cashtoken.add_unspent(unspent)
            test_token = deepcopy(cashtoken)
            try:
                for output in outputs:
                    test_token.subtract_output(output[2])
            except InsufficientFunds:
                continue

            (leftover_outputs,
             leftover_amount) = test_token.get_outputs(leftover)
            output_script_list += [_[0] for _ in leftover_outputs]

            calculated_fee = estimate_tx_fee(
                len(unspents[: index + 1]),
                output_script_list,
                fee,
                compressed,
            )
            if calculated_fee < leftover_amount:
                break
        else:
            raise InsufficientFunds(f"{cashtoken.amount} is insufficient")

        if calculated_fee:
            last_out = list(leftover_outputs[-1])
            last_out[1] -= calculated_fee
            last_out[2].amount -= calculated_fee
            leftover_outputs[-1] = tuple(last_out)

        unspents[:] = unspents_used + unspents[: index + 1]
        outputs += leftover_outputs

    outputs.extend(messages)

    return unspents, outputs


def construct_output_block(outputs):

    output_block = b""

    for data in outputs:
        script, amount, _ = data

        output_block += amount.to_bytes(8, byteorder="little")

        # Script length in wiki is "Var_int" but there's a note of
        # "modern BitcoinQT" using a more compact "CVarInt"
        # CVarInt is what I believe we have here - No changes made.
        # If incorrect - only breaks if 220 byte limit is increased.
        output_block += int_to_unknown_bytes(len(script), byteorder="little")
        output_block += script

    return output_block


def construct_input_block(inputs):
    input_block = b""
    sequence = SEQUENCE

    for txin in inputs:
        input_block += (
            txin.txid + txin.txindex + txin.script_len + txin.script + sequence
        )

    return input_block


def create_p2pkh_transaction(private_key, unspents, outputs):

    public_key = private_key.public_key
    public_key_len = len(public_key).to_bytes(1, byteorder="little")

    scriptCode = private_key.scriptcode
    scriptCode_len = int_to_varint(len(scriptCode))

    version = VERSION_1
    lock_time = LOCK_TIME
    # sequence = SEQUENCE
    hash_type = HASH_TYPE
    input_count = int_to_unknown_bytes(len(unspents), byteorder="little")
    output_count = int_to_unknown_bytes(len(outputs), byteorder="little")

    output_block = construct_output_block(outputs)

    # Optimize for speed, not memory, by pre-computing values.
    inputs = []
    for unspent in unspents:
        script = hex_to_bytes(unspent.script)
        script_len = int_to_unknown_bytes(len(script), byteorder="little")
        txid = hex_to_bytes(unspent.txid)[::-1]
        txindex = unspent.txindex.to_bytes(4, byteorder="little")
        amount = unspent.amount.to_bytes(8, byteorder="little")

        inputs.append(TxIn(script, script_len, txid, txindex, amount))

    hashPrevouts = double_sha256(b"".join([i.txid + i.txindex
                                           for i in inputs]))
    hashSequence = double_sha256(b"".join([SEQUENCE for i in inputs]))
    hashOutputs = double_sha256(output_block)

    # scriptCode_len is part of the script.
    for i, txin in enumerate(inputs):
        to_be_hashed = (
            version
            + hashPrevouts
            + hashSequence
            + txin.txid
            + txin.txindex
            + scriptCode_len
            + scriptCode
            + txin.amount
            + SEQUENCE
            + hashOutputs
            + lock_time
            + hash_type
        )
        hashed = sha256(to_be_hashed)  # BIP-143: Used for Bitcoin Cash

        # signature = private_key.sign(hashed) + b'\x01'
        signature = private_key.sign(hashed) + b"\x41"

        script_sig = (
            len(signature).to_bytes(1, byteorder="little")
            + signature
            + public_key_len
            + public_key
        )

        inputs[i].script = script_sig
        inputs[i].script_len = int_to_unknown_bytes(len(script_sig),
                                                    byteorder="little")

    return bytes_to_hex(
        version
        + input_count
        + construct_input_block(inputs)
        + output_count
        + output_block
        + lock_time
    )
