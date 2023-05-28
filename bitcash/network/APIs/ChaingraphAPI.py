from bitcash.network.http import session
from bitcash.exceptions import InvalidEndpointURLProvided
from bitcash.network.APIs import BaseAPI
from bitcash.network.meta import Unspent
from bitcash.network.transaction import Transaction, TxPart
from bitcash.cashaddress import Address


class ChaingraphAPI(BaseAPI):
    """ChaingraphAPI API, chaingraph.cash"""

    def __init__(self, network_endpoint: str):
        try:
            assert isinstance(network_endpoint, str)
        except AssertionError:
            raise InvalidEndpointURLProvided(
                f"Provided endpoint '{network_endpoint}' is not a valid URL"
                f" for a Chaingraph-based REST endpoint"
            )

        self.network_endpoint = network_endpoint

    # Default endpoints to use for this interface
    DEFAULT_ENDPOINTS = {
        "mainnet": [
            "https://demo.chaingraph.cash/v1/graphql",
            "https://gql.chaingraph.pat.mn/v1/graphql"
        ],
        "testnet": [],
        "regtest": [],
    }

    def send_request(self, json_request, *args, **kwargs):
        """Send json request and return receiving json"""
        r = session.post(self.network_endpoint, json=json_request,
                         *args, **kwargs)
        r.raise_for_status()
        json = r.json()
        if "errors" in json:
            raise RuntimeError(json)
        return json

    @classmethod
    def get_default_endpoints(cls, network):
        return cls.DEFAULT_ENDPOINTS[network]

    def get_balance(self, address, *args, **kwargs):
        json_request = {
            "query": """
query GetUTXO($lb: _text) {
  search_output(
    args: { locking_bytecode_hex: $lb }
    where: { _not: { spent_by: {} } }
  ) {
    value_satoshis
  }
}
""",
            "variables": {
                "lb": f"{{{Address.from_string(address).scriptcode.hex()}}}"
            }
        }
        json = self.send_request(json_request, *args, **kwargs)
        data = json["data"]["search_output"]
        return sum([int(_["value_satoshis"]) for _ in data])

    def get_transactions(self, address, *args, **kwargs):
        json_request = {
            "query": """
query GetOutputs($lb: _text!) {
  block(
    limit: 1
    order_by: {height: desc}
  ){
    height
  }
  search_output(args: { locking_bytecode_hex: $lb }) {
    transaction_hash
    transaction {
      block_inclusions {
        block {
          height
        }
      }
    }
    spent_by {
      transaction {
        hash
        block_inclusions {
          block {
            height
          }
        }
      }
    }
  }
}
""",
            "variables": {
                "lb": f"{{{Address.from_string(address).scriptcode.hex()}}}"
            }
        }
        json = self.send_request(json_request, *args, **kwargs)
        blockheight = int(json["data"]["block"][0]["height"])
        transactions = []
        for output in json["data"]["search_output"]:
            # outputs
            block_inclusions = output["transaction"]["block_inclusions"]
            if len(block_inclusions) == 0:
                # assume next block confirmation,
                # only needed to sort transactions
                height = blockheight + 1
            else:
                height = int(block_inclusions[0]["block"]["height"])
            transactions.append(
                (output["transaction_hash"][2:], height)
            )
            # inputs
            if len(output["spent_by"]) == 0:
                # unspent
                continue
            input_ = output["spent_by"][0]["transaction"]
            block_inclusions = input_["block_inclusions"]
            if len(block_inclusions) == 0:
                height = blockheight + 1
            else:
                height = int(block_inclusions[0]["block"]["height"])
            transactions.append(
                (input_["hash"][2:], height)
            )
        # sort by block height
        transactions.sort(key=lambda x: x[1])
        transactions = [_[0] for _ in transactions][::-1]
        # remove duplicates, when address pays itself, spending tx and locking
        # tx are same transactions
        transactions = sorted(set(transactions),
                              key=lambda x: transactions.index(x))
        return transactions

    def get_transaction(self, txid, *args, **kwargs):

        response = self.get_raw_transaction(txid, *args, **kwargs)

        block_inclusions = response["block_inclusions"]
        if len(block_inclusions) == 0:
            height = None
        else:
            height = int(block_inclusions[0]["block"]["height"])

        tx = Transaction(
            response["hash"][2:],
            height,
            int(response["input_value_satoshis"]),
            int(response["output_value_satoshis"]),
            int(response["fee_satoshis"]),
        )

        for part_name in ["inputs", "outputs"]:
            for txpart in response[part_name]:
                sats = int(txpart["value_satoshis"])
                data_hex = txpart["{}locking_bytecode".format(
                    "un" if part_name == "inputs" else ""
                )][2:]
                # switching to outpoint for inputs
                if part_name == "inputs":
                    txpart = txpart["outpoint"]
                try:
                    scriptcode = bytes.fromhex(txpart["locking_bytecode"][2:])
                    cashaddress = Address.from_script(scriptcode)
                    cashaddress = cashaddress.cash_address()
                except ValueError:
                    cashaddress = None
                part = TxPart(
                    cashaddress,
                    sats,
                    data_hex=data_hex
                )
                # adding token data
                token_catagory = txpart["token_category"]
                if token_catagory:
                    part.catagory_id = token_catagory[2:]
                part.nft_capability = txpart["nonfungible_token_capability"]
                nft_commitment = txpart["nonfungible_token_commitment"]
                if nft_commitment:
                    part.nft_commitment = nft_commitment[2:].encode() or None
                token_amount = txpart["fungible_token_amount"]
                if token_amount:
                    part.token_amount = int(token_amount) or None
                # adding to transaction
                if part_name == "inputs":
                    tx.add_input(part)
                else:
                    tx.add_output(part)

        return tx

    def get_tx_amount(self, txid, txindex, *args, **kwargs):
        json_request = {
            "query": """
query GetOutput($tx: bytea!, $txind: bigint!) {
  output(
    where: {
      _and: {
        transaction_hash: {_eq: $tx},
        output_index: {_eq: $txind}
      }
    }
  ) {
    value_satoshis
  }
}
""",
            "variables": {
                "tx": f"\\x{txid}",
                "txind": txindex
            }
        }
        json = self.send_request(json_request, *args, **kwargs)
        return int(json["data"]["output"][0]["value_satoshis"])

    def get_unspent(self, address, *args, **kwargs):
        json_request = {
            "query": """
query GetUTXO($lb: _text!) {
  block(
    limit: 1
    order_by: {height: desc}
  ){
    height
  }
  search_output(
    args: { locking_bytecode_hex: $lb }
    where: { _not: { spent_by: {} } }
  ) {
    transaction_hash
    output_index
    value_satoshis
    token_category
    fungible_token_amount
    nonfungible_token_capability
    nonfungible_token_commitment
    locking_bytecode
    transaction {
      block_inclusions {
        block {
          height
        }
      }
    }
  }
}
""",
            "variables": {
                "lb": f"{{{Address.from_string(address).scriptcode.hex()}}}"
            }
        }
        data = self.send_request(json_request, *args, **kwargs)["data"]
        blockheight = int(data["block"][0]["height"])
        unspents = []
        for utxo in data["search_output"]:
            block_inclusions = utxo["transaction"]["block_inclusions"]
            if len(block_inclusions) == 0:
                # unconfirmed
                confirmations = 0
            else:
                confirmations = (-int(block_inclusions[0]["block"]["height"])
                                 + blockheight + 1)
            token_catagory = utxo["token_category"]
            if token_catagory:
                token_catagory = token_catagory[2:]
            nft_commitment = utxo["nonfungible_token_commitment"]
            if nft_commitment:
                nft_commitment = nft_commitment[2:].encode()
            token_amount = utxo["fungible_token_amount"]
            if token_amount:
                token_amount = int(token_amount)
            # add unspent
            unspents.append(Unspent(
                int(utxo["value_satoshis"]),
                confirmations,
                utxo["locking_bytecode"][2:],
                utxo["transaction_hash"][2:],
                int(utxo["output_index"]),
                token_catagory,
                utxo["nonfungible_token_capability"],
                nft_commitment or None,  # b"" is None
                token_amount or None,  # 0 amount is None
            ))
        return unspents

    def get_raw_transaction(self, txid, *args, **kwargs):
        json_request = {
            "query": """
query GetTransactionDetails($tx: bytea!) {
  transaction(where: { hash: { _eq: $tx } }) {
    hash
    fee_satoshis
    input_value_satoshis
    output_value_satoshis
    block_inclusions {
      block {
        height
      }
    }
    inputs(order_by: { input_index: asc }) {
      value_satoshis
      unlocking_bytecode
      outpoint {
        locking_bytecode
        token_category
        nonfungible_token_capability
        nonfungible_token_commitment
        fungible_token_amount
      }
    }
    outputs(order_by: { output_index: asc }) {
      value_satoshis
      locking_bytecode
      token_category
      nonfungible_token_capability
      nonfungible_token_commitment
      fungible_token_amount
    }
  }
}
""",
            "variables": {
                "tx": f"\\x{txid}"
            }
        }
        json = self.send_request(json_request, *args, **kwargs)
        return json["data"]["transaction"][0]

    def broadcast_tx(self, tx_hex, *args, **kwargs):  # pragma: no cover
        json_request = {
            "query": """
query GetNodeId{
  node{
    internal_id
  }
}
"""
        }
        node_ids = self.send_request(json_request,
                                     *args, **kwargs)["data"]["node"]

        json_request = {
            "query": """
mutation BroadcastTx($tx_hex: String!, $node: bigint!){
  send_transaction (
    request: { encoded_hex: $tx_hex, node_internal_id:$node}
  ){
    validation_success
    validation_error_message
    transmission_success
    transmission_error_message
  }
}
""",
            "variables": {
                "tx_hex": tx_hex,
                "node": None
            }
        }
        for node_id in [_["internal_id"] for _ in node_ids]:
            json_request["variables"]["node"] = node_id
            json = self.send_request(json_request, *args,
                                     **kwargs)["data"]["send_transaction"]
            print(json)
            if json["transmission_success"] and json["validation_success"]:
                return True
        return False
