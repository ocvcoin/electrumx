# Copyright (c) 2016-2017, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

'''Module providing coin abstraction.

Anything coin-specific should go in this file and be subclassed where
necessary for appropriate handling.
'''

'''
import cv2
import numpy as np
import hashlib
'''

import re
import struct
from dataclasses import dataclass
from decimal import Decimal
from functools import partial
from hashlib import sha256
from typing import Sequence, Tuple

import electrumx.lib.util as util
from electrumx.lib.hash import Base58, double_sha256, hash_to_hex_str
from electrumx.lib.hash import HASHX_LEN, hex_str_to_hash
from electrumx.lib.script import (_match_ops, Script, ScriptError,
                                  ScriptPubKey, OpCodes)
import electrumx.lib.tx as lib_tx
from electrumx.lib.tx import Tx
import electrumx.lib.tx_dash as lib_tx_dash
import electrumx.lib.tx_axe as lib_tx_axe
import electrumx.server.block_processor as block_proc
import electrumx.server.daemon as daemon
from electrumx.server.session import (ElectrumX, DashElectrumX,
                                      SmartCashElectrumX, AuxPoWElectrumX)
import ctypes
import os

if os.name == 'nt':
  libocv2 = ctypes.CDLL("libocv2.dll")
else:
  libocv2 = ctypes.CDLL("libocv2.so")


if not libocv2.ocv2_test_algo():
    exit("Error!! ocv2_test_algo() failed.");

@dataclass
class Block:
    __slots__ = "raw", "header", "transactions"
    raw: bytes
    header: bytes
    transactions: Sequence[Tuple[Tx, bytes]]


class CoinError(Exception):
    '''Exception raised for coin-related errors.'''


class Coin:
    '''Base class of coin hierarchy.'''

    REORG_LIMIT = 200
    # Not sure if these are coin-specific
    RPC_URL_REGEX = re.compile('.+@(\\[[0-9a-fA-F:]+\\]|[^:]+)(:[0-9]+)?')
    VALUE_PER_COIN = 100000000
    CHUNK_SIZE = 2016
    BASIC_HEADER_SIZE = 80
    STATIC_BLOCK_HEADERS = True
    SESSIONCLS = ElectrumX
    DEFAULT_MAX_SEND = 1000000
    DESERIALIZER = lib_tx.Deserializer
    DAEMON = daemon.Daemon
    BLOCK_PROCESSOR = block_proc.BlockProcessor
    HEADER_VALUES = ('version', 'prev_block_hash', 'merkle_root', 'timestamp',
                     'bits', 'nonce')
    HEADER_UNPACK = struct.Struct('< I 32s 32s I I I').unpack_from
    P2PKH_VERBYTE = bytes.fromhex("00")
    P2SH_VERBYTES = (bytes.fromhex("05"),)
    XPUB_VERBYTES = bytes('????', 'utf-8')
    XPRV_VERBYTES = bytes('????', 'utf-8')
    WIF_BYTE = bytes.fromhex("80")
    ENCODE_CHECK = Base58.encode_check
    DECODE_CHECK = Base58.decode_check
    GENESIS_HASH = ('000000000019d6689c085ae165831e93'
                    '4ff763ae46a2a6c172b3f1b60a8ce26f')
    GENESIS_ACTIVATION = 100_000_000

    MEMPOOL_HISTOGRAM_REFRESH_SECS = 500
    # first bin size in vbytes. smaller bins mean more precision but also bandwidth:
    MEMPOOL_COMPACT_HISTOGRAM_BINSIZE = 30_000

    # Peer discovery
    PEER_DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    PEERS = []
    CRASH_CLIENT_VER = None
    BLACKLIST_URL = None
    ESTIMATEFEE_MODES = (None, 'CONSERVATIVE', 'ECONOMICAL')

    RPC_PORT: int
    NAME: str
    NET: str

    # only used for initial db sync ETAs:
    TX_COUNT_HEIGHT: int  # at a given snapshot of the chain,
    TX_COUNT: int         # there have been this many txs so far,
    TX_PER_BLOCK: int     # and from that height onwards, we guess this many txs per block

    @classmethod
    def lookup_coin_class(cls, name, net):
        '''Return a coin class given name and network.

        Raise an exception if unrecognised.'''
        req_attrs = ('TX_COUNT', 'TX_COUNT_HEIGHT', 'TX_PER_BLOCK')
        for coin in util.subclasses(Coin):
            if (coin.NAME.lower() == name.lower() and
                    coin.NET.lower() == net.lower()):
                missing = [
                    attr
                    for attr in req_attrs
                    if not hasattr(coin, attr)
                ]
                if missing:
                    raise CoinError(
                        f'coin {name} missing {missing} attributes'
                    )
                return coin
        raise CoinError(f'unknown coin {name} and network {net} combination')

    @classmethod
    def sanitize_url(cls, url):
        # Remove surrounding ws and trailing /s
        url = url.strip().rstrip('/')
        match = cls.RPC_URL_REGEX.match(url)
        if not match:
            raise CoinError(f'invalid daemon URL: "{url}"')
        if match.groups()[1] is None:
            url = f'{url}:{cls.RPC_PORT:d}'
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'
        return url + '/'

    @classmethod
    def max_fetch_blocks(cls, height):
        if height < 130000:
            return 1000
        return 100

    @classmethod
    def genesis_block(cls, block):
        '''Check the Genesis block is the right one for this coin.

        Return the block less its unspendable coinbase.
        '''
        header = cls.block_header(block, 0)
        header_hex_hash = hash_to_hex_str(cls.header_hash(header))
        if header_hex_hash != cls.GENESIS_HASH:
            raise CoinError(f'genesis block has hash {header_hex_hash} '
                            f'expected {cls.GENESIS_HASH}')

        return header + b'\0'

    @classmethod
    def hashX_from_script(cls, script):
        '''Returns a hashX from a script.'''
        return sha256(script).digest()[:HASHX_LEN]

    @staticmethod
    def lookup_xverbytes(verbytes):
        '''Return a (is_xpub, coin_class) pair given xpub/xprv verbytes.'''
        # Order means BTC testnet will override NMC testnet
        for coin in util.subclasses(Coin):
            if verbytes == coin.XPUB_VERBYTES:
                return True, coin
            if verbytes == coin.XPRV_VERBYTES:
                return False, coin
        raise CoinError('version bytes unrecognised')

    @classmethod
    def address_to_hashX(cls, address):
        '''Return a hashX given a coin address.'''
        return cls.hashX_from_script(cls.pay_to_address_script(address))

    @classmethod
    def hash160_to_P2PKH_script(cls, hash160):
        return ScriptPubKey.P2PKH_script(hash160)

    @classmethod
    def hash160_to_P2PKH_hashX(cls, hash160):
        return cls.hashX_from_script(cls.hash160_to_P2PKH_script(hash160))

    @classmethod
    def pay_to_address_script(cls, address):
        '''Return a pubkey script that pays to a pubkey hash.

        Pass the address (either P2PKH or P2SH) in base58 form.
        '''
        raw = cls.DECODE_CHECK(address)

        # Require version byte(s) plus hash160.
        verbyte = -1
        verlen = len(raw) - 20
        if verlen > 0:
            verbyte, hash160 = raw[:verlen], raw[verlen:]

        if verbyte == cls.P2PKH_VERBYTE:
            return cls.hash160_to_P2PKH_script(hash160)
        if verbyte in cls.P2SH_VERBYTES:
            return ScriptPubKey.P2SH_script(hash160)

        raise CoinError(f'invalid address: {address}')

    @classmethod
    def privkey_WIF(cls, privkey_bytes, compressed):
        '''Return the private key encoded in Wallet Import Format.'''
        payload = bytearray(cls.WIF_BYTE + privkey_bytes)
        if compressed:
            payload.append(0x01)
        return cls.ENCODE_CHECK(payload)

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header)

    @classmethod
    def header_prevhash(cls, header):
        '''Given a header return previous hash'''
        return header[4:36]

    @classmethod
    def static_header_offset(cls, height):
        '''Given a header height return its offset in the headers file.

        If header sizes change at some point, this is the only code
        that needs updating.'''
        assert cls.STATIC_BLOCK_HEADERS
        return height * cls.BASIC_HEADER_SIZE

    @classmethod
    def static_header_len(cls, height):
        '''Given a header height return its length.'''
        return (cls.static_header_offset(height + 1)
                - cls.static_header_offset(height))

    @classmethod
    def block_header(cls, block, height):
        '''Returns the block header given a block and its height.'''
        return block[:cls.static_header_len(height)]

    @classmethod
    def block(cls, raw_block, height):
        '''Return a Block namedtuple given a raw block and its height.'''
        header = cls.block_header(raw_block, height)
        txs = cls.DESERIALIZER(raw_block, start=len(header)).read_tx_block()
        return Block(raw_block, header, txs)

    @classmethod
    def decimal_value(cls, value):
        '''Return the number of standard coin units as a Decimal given a
        quantity of smallest units.

        For example 1 BTC is returned for 100 million satoshis.
        '''
        return Decimal(value) / cls.VALUE_PER_COIN

    @classmethod
    def warn_old_client_on_tx_broadcast(cls, _client_ver):
        return False

    @classmethod
    def bucket_estimatefee_block_target(cls, n: int) -> int:
        '''For caching purposes, it might be desirable to restrict the
        set of values that can be queried as an estimatefee block target.
        '''
        return n


class AuxPowMixin:
    STATIC_BLOCK_HEADERS = False
    DESERIALIZER = lib_tx.DeserializerAuxPow
    SESSIONCLS = AuxPoWElectrumX
    TRUNCATED_HEADER_SIZE = 80
    # AuxPoW headers are significantly larger, so the DEFAULT_MAX_SEND from
    # Bitcoin is insufficient.  In Namecoin mainnet, 5 MB wasn't enough to
    # sync, while 10 MB worked fine.
    DEFAULT_MAX_SEND = 10000000

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header[:cls.BASIC_HEADER_SIZE])

    @classmethod
    def block_header(cls, block, height):
        '''Return the AuxPow block header bytes'''
        deserializer = cls.DESERIALIZER(block)
        return deserializer.read_header(cls.BASIC_HEADER_SIZE)


class EquihashMixin:
    STATIC_BLOCK_HEADERS = False
    BASIC_HEADER_SIZE = 140  # Excluding Equihash solution
    DESERIALIZER = lib_tx.DeserializerEquihash
    HEADER_VALUES = ('version', 'prev_block_hash', 'merkle_root', 'reserved',
                     'timestamp', 'bits', 'nonce')
    HEADER_UNPACK = struct.Struct('< I 32s 32s 32s I I 32s').unpack_from

    @classmethod
    def block_header(cls, block, height):
        '''Return the block header bytes'''
        deserializer = cls.DESERIALIZER(block)
        return deserializer.read_header(cls.BASIC_HEADER_SIZE)


class ScryptMixin:

    DESERIALIZER = lib_tx.DeserializerTxTime
    HEADER_HASH = None

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        if cls.HEADER_HASH is None:
            # Requires OpenSSL 1.1.0+
            from hashlib import scrypt
            cls.HEADER_HASH = lambda x: scrypt(x, salt=x, n=1024, r=1, p=1, dklen=32)

        version, = util.unpack_le_uint32_from(header)
        if version > 6:
            return super().header_hash(header)
        else:
            return cls.HEADER_HASH(header)


class KomodoMixin:
    P2PKH_VERBYTE = bytes.fromhex("3C")
    P2SH_VERBYTES = (bytes.fromhex("55"),)
    WIF_BYTE = bytes.fromhex("BC")
    GENESIS_HASH = ('027e3758c3a65b12aa1046462b486d0a'
                    '63bfa1beae327897f56c5cfb7daaae71')
    DESERIALIZER = lib_tx.DeserializerZcash


class BitcoinMixin:
    SHORTNAME = "BTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    RPC_PORT = 8332


class NameMixin:
    DATA_PUSH_MULTIPLE = -2

    @classmethod
    def interpret_name_prefix(cls, script, possible_ops):
        """Interprets a potential name prefix

        Checks if the given script has a name prefix.  If it has, the
        name prefix is split off the actual address script, and its parsed
        fields (e.g. the name) returned.

        possible_ops must be an array of arrays, defining the structures
        of name prefixes to look out for.  Each array can consist of
        actual opcodes, -1 for ignored data placeholders, -2 for
        multiple ignored data placeholders and strings for named placeholders.
        Whenever a data push matches a named placeholder,
        the corresponding value is put into a dictionary the placeholder name
        as key, and the dictionary of matches is returned."""

        try:
            ops = Script.get_ops(script)
        except ScriptError:
            return None, script

        name_op_count = None
        for pops in possible_ops:
            # Start by translating named placeholders to -1 values, and
            # keeping track of which op they corresponded to.
            template = []
            named_index = {}

            n = len(pops)
            offset = 0
            for i, op in enumerate(pops):
                if op == cls.DATA_PUSH_MULTIPLE:
                    # Emercoin stores value in multiple placeholders
                    # Script structure: https://git.io/fjuRu
                    added, template = cls._add_data_placeholders_to_template(ops[i:], template)
                    offset += added - 1  # subtract the "DATA_PUSH_MULTIPLE" opcode
                elif type(op) == str:
                    template.append(-1)
                    named_index[op] = i + offset
                else:
                    template.append(op)
            n += offset

            if not _match_ops(ops[:n], template):
                continue

            name_op_count = n
            named_values = {key: ops[named_index[key]] for key in named_index}
            break

        if name_op_count is None:
            return None, script

        name_end_pos = cls.find_end_position_of_name(script, name_op_count)

        address_script = script[name_end_pos:]
        return named_values, address_script

    @classmethod
    def _add_data_placeholders_to_template(cls, opcodes, template):
        num_dp = cls._read_data_placeholders_count(opcodes)
        num_2drop = num_dp // 2
        num_drop = num_dp % 2

        two_drops = [OpCodes.OP_2DROP] * num_2drop
        one_drops = [OpCodes.OP_DROP] * num_drop

        elements_added = num_dp + num_2drop + num_drop
        placeholders = [-1] * num_dp
        drops = two_drops + one_drops

        return elements_added, template + placeholders + drops

    @classmethod
    def _read_data_placeholders_count(cls, opcodes):
        data_placeholders = 0

        for opcode in opcodes:
            if type(opcode) == tuple:
                data_placeholders += 1
            else:
                break

        return data_placeholders

    @staticmethod
    def find_end_position_of_name(script, length):
        """Finds the end position of the name data

        Given the number of opcodes in the name prefix (length), returns the
        index into the byte array of where the name prefix ends."""
        n = 0
        for _i in range(length):
            # Content of this loop is copied from Script.get_ops's loop
            op = script[n]
            n += 1

            if op <= OpCodes.OP_PUSHDATA4:
                # Raw bytes follow
                if op < OpCodes.OP_PUSHDATA1:
                    dlen = op
                elif op == OpCodes.OP_PUSHDATA1:
                    dlen = script[n]
                    n += 1
                elif op == OpCodes.OP_PUSHDATA2:
                    dlen, = struct.unpack('<H', script[n: n + 2])
                    n += 2
                else:
                    dlen, = struct.unpack('<I', script[n: n + 4])
                    n += 4
                if n + dlen > len(script):
                    raise IndexError
                n += dlen

        return n


class NameIndexMixin(NameMixin):
    """Shared definitions for coins that have a name index

    This class defines common functions and logic for coins that have
    a name index in addition to the index by address / script."""

    BLOCK_PROCESSOR = block_proc.NameIndexBlockProcessor

    @classmethod
    def build_name_index_script(cls, name):
        """Returns the script by which names are indexed"""

        from electrumx.lib.script import Script

        res = bytearray()
        res.append(cls.OP_NAME_UPDATE)
        res += Script.push_data(name)
        res += Script.push_data(b'')
        res.append(OpCodes.OP_2DROP)
        res.append(OpCodes.OP_DROP)
        res.append(OpCodes.OP_RETURN)

        return bytes(res)

    @classmethod
    def split_name_script(cls, script):
        named_values, address_script = cls.interpret_name_prefix(script, cls.NAME_OPERATIONS)
        if named_values is None or "name" not in named_values:
            return None, address_script

        name_index_script = cls.build_name_index_script(named_values["name"][1])
        return name_index_script, address_script

    @classmethod
    def hashX_from_script(cls, script):
        _, address_script = cls.split_name_script(script)
        return super().hashX_from_script(address_script)

    @classmethod
    def address_from_script(cls, script):
        _, address_script = cls.split_name_script(script)
        return super().address_from_script(address_script)

    @classmethod
    def name_hashX_from_script(cls, script):
        name_index_script, _ = cls.split_name_script(script)
        if name_index_script is None:
            return None

        return super().hashX_from_script(name_index_script)


class PrimeChainPowMixin:
    STATIC_BLOCK_HEADERS = False
    DESERIALIZER = lib_tx.DeserializerPrimecoin

    @classmethod
    def block_header(cls, block, height):
        '''Return the block header bytes'''
        deserializer = cls.DESERIALIZER(block)
        return deserializer.read_header(cls.BASIC_HEADER_SIZE)


class Verge(Coin):
    NAME = "Verge"
    SHORTNAME = "XVG"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("022d2533")
    XPRV_VERBYTES = bytes.fromhex("0221312b")
    P2PKH_VERBYTE = bytes.fromhex("30")
    P2SH_VERBYTES = [bytes.fromhex("33")]
    WIF_BYTE = bytes.fromhex("9E")
    GENESIS_HASH = ('00000fc63692467faeb20cdb3b53200d'
                    'c601d75bdfa1001463304cc790d77278')
    RPC_PORT = 20102
    TX_COUNT = 500000
    TX_COUNT_HEIGHT = 3082138
    TX_PER_BLOCK = 1
    DESERIALIZER = lib_tx.DeserializerVerge

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import scrypt
        return scrypt.hash(header, header, 1024, 1, 1, 32)


class HOdlcoin(Coin):
    NAME = "HOdlcoin"
    SHORTNAME = "HODLC"
    NET = "mainnet"
    BASIC_HEADER_SIZE = 88
    P2PKH_VERBYTE = bytes.fromhex("28")
    WIF_BYTE = bytes.fromhex("a8")
    GENESIS_HASH = ('008872e5582924544e5c707ee4b839bb'
                    '82c28a9e94e917c94b40538d5658c04b')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 258858
    TX_COUNT_HEIGHT = 382138
    TX_PER_BLOCK = 5


class BitcoinSV(BitcoinMixin, Coin):
    NAME = "BitcoinSV"
    SHORTNAME = "BSV"
    TX_COUNT = 267318795
    TX_COUNT_HEIGHT = 557037
    TX_PER_BLOCK = 400
    PEERS = [
        'electrumx.bitcoinsv.io s',
        'satoshi.vision.cash s',
        'sv.usebsv.com s t',
        'sv.jochen-hoenicke.de s t',
        'sv.satoshi.io s t',
    ]
    GENESIS_ACTIVATION = 620_538


class BitcoinCash(BitcoinMixin, Coin):
    NAME = "BitcoinCash"
    SHORTNAME = "BCH"
    TX_COUNT = 265479628
    TX_COUNT_HEIGHT = 556592
    TX_PER_BLOCK = 400
    PEERS = [
        'bch.imaginary.cash s t',
        'electroncash.dk s t',
        'electrum.imaginary.cash s t',
        'bch.loping.net s t',
        'electroncash.de s t',
        'blackie.c3-soft.com s t',
    ]
    BLOCK_PROCESSOR = block_proc.LTORBlockProcessor

    @classmethod
    def warn_old_client_on_tx_broadcast(cls, client_ver):
        if client_ver < (3, 3, 4):
            return ('<br/><br/>'
                    'Your transaction was successfully broadcast.<br/><br/>'
                    'However, you are using a VULNERABLE version of Electron Cash.<br/>'
                    'Download the latest version from this web site ONLY:<br/>'
                    'https://electroncash.org/'
                    '<br/><br/>')
        return False


class Bitcoin(BitcoinMixin, Coin):
    NAME = "Bitcoin"
    DESERIALIZER = lib_tx.DeserializerSegWit
    MEMPOOL_HISTOGRAM_REFRESH_SECS = 120
    TX_COUNT = 565436782
    TX_COUNT_HEIGHT = 646855
    TX_PER_BLOCK = 2200
    CRASH_CLIENT_VER = (3, 2, 3)
    BLACKLIST_URL = 'https://electrum.org/blacklist.json'
    PEERS = [
        'electrum.vom-stausee.de s t',
        'electrum.hsmiths.com s t',
        'helicarrier.bauerj.eu s t',
        'hsmiths4fyqlw5xw.onion s t',
        'ozahtqwp25chjdjd.onion s t',
        'electrum.hodlister.co s',
        'electrum3.hodlister.co s',
        'btc.usebsv.com s50006',
        'fortress.qtornado.com s443 t',
        'ecdsa.net s110 t',
        'e2.keff.org s t',
        'currentlane.lovebitco.in s t',
        'electrum.jochen-hoenicke.de s50005 t50003',
        'vps5.hsmiths.com s',
        'electrum.emzy.de s',
    ]

    @classmethod
    def warn_old_client_on_tx_broadcast(cls, client_ver):
        if client_ver < (3, 3, 3):
            return ('<br/><br/>'
                    'Your transaction was successfully broadcast.<br/><br/>'
                    'However, you are using a VULNERABLE version of Electrum.<br/>'
                    'Download the new version from the usual place:<br/>'
                    'https://electrum.org/'
                    '<br/><br/>')
        return False

    @classmethod
    def bucket_estimatefee_block_target(cls, n: int) -> int:
        # values based on https://github.com/bitcoin/bitcoin/blob/af05bd9e1e362c3148e3b434b7fac96a9a5155a1/src/policy/fees.h#L131  # noqa
        if n <= 1:
            return 1
        if n <= 12:
            return n
        if n == 25:  # so common that we make an exception for it
            return n
        if n <= 48:
            return n // 2 * 2
        if n <= 1008:
            return n // 24 * 24
        return 1008


class BitcoinSegwit(Bitcoin):
    NAME = "BitcoinSegwit"  # support legacy name


class BitcoinGold(EquihashMixin, BitcoinMixin, Coin):
    CHUNK_SIZE = 252
    NAME = "BitcoinGold"
    SHORTNAME = "BTG"
    FORK_HEIGHT = 491407
    P2PKH_VERBYTE = bytes.fromhex("26")
    P2SH_VERBYTES = (bytes.fromhex("17"),)
    DESERIALIZER = lib_tx.DeserializerEquihashSegWit
    TX_COUNT = 265026255
    TX_COUNT_HEIGHT = 499923
    TX_PER_BLOCK = 50
    REORG_LIMIT = 1000
    RPC_PORT = 8332
    PEERS = [
        'electrumx-eu.bitcoingold.org s50002 t50001',
        'electrumx-us.bitcoingold.org s50002 t50001'
    ]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        height, = util.unpack_le_uint32_from(header, 68)
        if height >= cls.FORK_HEIGHT:
            return double_sha256(header)
        else:
            return double_sha256(header[:68] + header[100:112])


class BitcoinGoldTestnet(BitcoinGold):
    FORK_HEIGHT = 1
    SHORTNAME = "TBTG"
    XPUB_VERBYTES = bytes.fromhex("043587CF")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6F")
    P2SH_VERBYTES = (bytes.fromhex("C4"),)
    WIF_BYTE = bytes.fromhex("EF")
    TX_COUNT = 0
    TX_COUNT_HEIGHT = 1
    NET = 'testnet'
    RPC_PORT = 18332
    GENESIS_HASH = ('00000000e0781ebe24b91eedc293adfe'
                    'a2f557b53ec379e78959de3853e6f9f6')
    PEERS = [
        'test-node1.bitcoingold.org s50002',
        'test-node2.bitcoingold.org s50002',
        'test-node3.bitcoingold.org s50002'
    ]


class BitcoinGoldRegtest(BitcoinGold):
    FORK_HEIGHT = 2000
    SHORTNAME = "TBTG"
    XPUB_VERBYTES = bytes.fromhex("043587CF")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6F")
    P2SH_VERBYTES = (bytes.fromhex("C4"),)
    WIF_BYTE = bytes.fromhex("EF")
    TX_COUNT = 0
    TX_COUNT_HEIGHT = 1
    NET = 'regtest'
    RPC_PORT = 18444
    GENESIS_HASH = ('0f9188f13cb7b2c71f2a335e3a4fc328'
                    'bf5beb436012afca590b1a11466e2206')
    PEERS = []


class BitcoinDiamond(Bitcoin, Coin):
    NAME = "BitcoinDiamond"
    SHORTNAME = "BCD"
    TX_VERSION = 12
    TX_COUNT = 274277819
    TX_COUNT_HEIGHT = 498678
    TX_PER_BLOCK = 50
    REORG_LIMIT = 1000
    PEERS = []
    VALUE_PER_COIN = 10000000
    DESERIALIZER = lib_tx.DeserializerBitcoinDiamondSegWit


class Emercoin(NameMixin, Coin):
    NAME = "Emercoin"
    SHORTNAME = "EMC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("21")
    P2SH_VERBYTES = (bytes.fromhex("5c"),)
    GENESIS_HASH = ('00000000bcccd459d036a588d1008fce'
                    '8da3754b205736f32ddfd35350e84c2d')
    TX_COUNT = 217380620
    TX_COUNT_HEIGHT = 464000
    TX_PER_BLOCK = 1700
    VALUE_PER_COIN = 1000000
    RPC_PORT = 6662

    DESERIALIZER = lib_tx.DeserializerEmercoin

    PEERS = []

    # Name opcodes
    OP_NAME_NEW = OpCodes.OP_1
    OP_NAME_UPDATE = OpCodes.OP_2
    OP_NAME_DELETE = OpCodes.OP_3

    # Valid name prefixes.
    NAME_NEW_OPS = (OP_NAME_NEW, OpCodes.OP_DROP, "name", "days",
                    OpCodes.OP_2DROP, NameMixin.DATA_PUSH_MULTIPLE)
    NAME_UPDATE_OPS = (OP_NAME_UPDATE, OpCodes.OP_DROP, "name", "days",
                       OpCodes.OP_2DROP, NameMixin.DATA_PUSH_MULTIPLE)
    NAME_DELETE_OPS = (OP_NAME_DELETE, OpCodes.OP_DROP, "name",
                       OpCodes.OP_DROP)
    NAME_OPERATIONS = (
        NAME_NEW_OPS,
        NAME_UPDATE_OPS,
        NAME_DELETE_OPS,
    )

    @classmethod
    def block_header(cls, block, height):
        '''Returns the block header given a block and its height.'''
        deserializer = cls.DESERIALIZER(block)

        if deserializer.is_merged_block():
            return deserializer.read_header(cls.BASIC_HEADER_SIZE)
        return block[:cls.static_header_len(height)]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header[:cls.BASIC_HEADER_SIZE])

    @classmethod
    def hashX_from_script(cls, script):
        _, address_script = cls.interpret_name_prefix(script, cls.NAME_OPERATIONS)

        return super().hashX_from_script(address_script)


class BitcoinTestnetMixin:
    SHORTNAME = "XTN"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = (bytes.fromhex("c4"),)
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('000000000933ea01ad0ee984209779ba'
                    'aec3ced90fa3f408719526f8d77f4943')
    REORG_LIMIT = 8000
    TX_COUNT = 12242438
    TX_COUNT_HEIGHT = 1035428
    TX_PER_BLOCK = 21
    RPC_PORT = 18332
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}


class BitcoinSVTestnet(BitcoinTestnetMixin, Coin):
    '''Bitcoin Testnet for Bitcoin SV daemons.'''
    NAME = "BitcoinSV"
    PEERS = [
        'electrontest.cascharia.com t51001 s51002',
    ]
    GENESIS_ACTIVATION = 1_344_302


class BitcoinSVScalingTestnet(BitcoinSVTestnet):
    NET = "scalingtest"
    PEERS = [
        'stn-server.electrumsv.io t51001 s51002',
    ]
    TX_COUNT = 2015
    TX_COUNT_HEIGHT = 5711
    TX_PER_BLOCK = 5000
    GENESIS_ACTIVATION = 14_896

    @classmethod
    def max_fetch_blocks(cls, height):
        if height <= 10:
            return 100
        return 3


class BitcoinCashTestnet(BitcoinTestnetMixin, Coin):
    '''Bitcoin Testnet for Bitcoin Cash daemons.'''
    NAME = "BitcoinCash"
    PEERS = [
        'bch0.kister.net t s',
        'testnet.imaginary.cash t50001 s50002',
        'blackie.c3-soft.com t60001 s60002',
    ]
    BLOCK_PROCESSOR = block_proc.LTORBlockProcessor

    @classmethod
    def warn_old_client_on_tx_broadcast(cls, client_ver):
        if client_ver < (3, 3, 4):
            return ('<br/><br/>'
                    'Your transaction was successfully broadcast.<br/><br/>'
                    'However, you are using a VULNERABLE version of Electron Cash.<br/>'
                    'Download the latest version from this web site ONLY:<br/>'
                    'https://electroncash.org/'
                    '<br/><br/>')
        return False


class BitcoinSVRegtest(BitcoinSVTestnet):
    NET = "regtest"
    GENESIS_HASH = ('0f9188f13cb7b2c71f2a335e3a4fc328'
                    'bf5beb436012afca590b1a11466e2206')
    PEERS = []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    GENESIS_ACTIVATION = 10_000


class BitcoinTestnet(BitcoinTestnetMixin, Coin):
    '''Bitcoin Testnet for Core bitcoind >= 0.13.1.'''
    NAME = "Bitcoin"
    DESERIALIZER = lib_tx.DeserializerSegWit
    CRASH_CLIENT_VER = (3, 2, 3)
    PEERS = [
        'testnet.hsmiths.com t53011 s53012',
        'hsmithsxurybd7uh.onion t53011 s53012',
        'testnet.qtornado.com s t',
        'testnet1.bauerj.eu t50001 s50002',
        'tn.not.fyi t55001 s55002',
        'bitcoin.cluelessperson.com s t',
    ]

    @classmethod
    def warn_old_client_on_tx_broadcast(cls, client_ver):
        if client_ver < (3, 3, 3):
            return ('<br/><br/>'
                    'Your transaction was successfully broadcast.<br/><br/>'
                    'However, you are using a VULNERABLE version of Electrum.<br/>'
                    'Download the new version from the usual place:<br/>'
                    'https://electrum.org/'
                    '<br/><br/>')
        return False


class BitcoinSegwitTestnet(BitcoinTestnet):
    NAME = "BitcoinSegwit"  # support legacy name


class BitcoinRegtest(BitcoinTestnet):
    NAME = "Bitcoin"
    NET = "regtest"
    GENESIS_HASH = ('0f9188f13cb7b2c71f2a335e3a4fc328'
                    'bf5beb436012afca590b1a11466e2206')
    PEERS = []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1


class BitcoinSegwitRegtest(BitcoinRegtest):
    NAME = "BitcoinSegwit"  # support legacy name


class BitcoinSignet(BitcoinTestnet):
    NAME = "Bitcoin"
    NET = "signet"
    GENESIS_HASH = ('00000008819873e925422c1ff0f99f7c'
                    'c9bbb232af63a077a480a3633bee1ef6')
    PEERS = []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1


class BitcoinSegwitSignet(BitcoinSignet):
    NAME = "BitcoinSegwit"  # support legacy name


class BitcoinNolnet(BitcoinCash):
    '''Bitcoin Unlimited nolimit testnet.'''
    NET = "nolnet"
    GENESIS_HASH = ('0000000057e31bd2066c939a63b7b862'
                    '3bd0f10d8c001304bdfc1a7902ae6d35')
    PEERS = []
    REORG_LIMIT = 8000
    TX_COUNT = 583589
    TX_COUNT_HEIGHT = 8617
    TX_PER_BLOCK = 50
    RPC_PORT = 28332
    PEER_DEFAULT_PORTS = {'t': '52001', 's': '52002'}


# Source: https://github.com/sumcoinlabs/sumcoin
class Sumcoin(Coin):
    NAME = "Sumcoin"
    SHORTNAME = "SUM"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b41c")
    XPRV_VERBYTES = bytes.fromhex("0488abe6")
    P2PKH_VERBYTE = bytes.fromhex("3f")
    P2SH_VERBYTES = (bytes.fromhex("c8"), bytes.fromhex("05"))
    WIF_BYTE = bytes.fromhex("bf")
    GENESIS_HASH = ('37d4696c5072cd012f3b7c651e5ce56a'
                    '1383577e4edacc2d289ec9b25eebfd5e')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 976394
    TX_COUNT_HEIGHT = 659520
    TX_PER_BLOCK = 2
    REORG_LIMIT = 800
    RPC_PORT = 3332
    PEER_DEFAULT_PORTS = {'t': '53332', 's': '53333'}
    PEERS = []


class Litecoin(Coin):
    NAME = "Litecoin"
    SHORTNAME = "LTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("30")
    P2SH_VERBYTES = (bytes.fromhex("32"), bytes.fromhex("05"))
    WIF_BYTE = bytes.fromhex("b0")
    GENESIS_HASH = ('12a765e31ffd4059bada1e25190f6e98'
                    'c99d9714d334efa41a195a7e7e04bfe2')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 8908766
    TX_COUNT_HEIGHT = 1105256
    TX_PER_BLOCK = 10
    RPC_PORT = 9332
    REORG_LIMIT = 800
    PEERS = [
        'ex.lug.gs s444',
        'electrum-ltc.bysh.me s t',
        'electrum-ltc.ddns.net s t',
        'electrum-ltc.wilv.in s t',
        'electrum.cryptomachine.com p1000 s t',
        'electrum.ltc.xurious.com s t',
        'eywr5eubdbbe2laq.onion s50008 t50007',
    ]


class LitecoinTestnet(Litecoin):
    SHORTNAME = "XLT"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = (bytes.fromhex("3a"), bytes.fromhex("c4"))
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('4966625a4b2851d9fdee139e56211a0d'
                    '88575f59ed816ff5e6a63deb4e3e29a0')
    TX_COUNT = 21772
    TX_COUNT_HEIGHT = 20800
    TX_PER_BLOCK = 2
    RPC_PORT = 19332
    REORG_LIMIT = 4000
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    PEERS = [
        'electrum-ltc.bysh.me s t',
        'electrum.ltc.xurious.com s t',
        'ipv6-only.electrum.random.re s t',
    ]


class LitecoinRegtest(LitecoinTestnet):
    NET = "regtest"
    GENESIS_HASH = ('530827f38f93b43ed12af0b3ad25a288'
                    'dc02ed74d6d7857862df51fc56c416f9')
    PEERS = []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1


class BitcoinCashRegtest(BitcoinTestnetMixin, Coin):
    NAME = "BitcoinCash"
    NET = "regtest"
    PEERS = []
    GENESIS_HASH = ('0f9188f13cb7b2c71f2a335e3a4fc328'
                    'bf5beb436012afca590b1a11466e2206')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    BLOCK_PROCESSOR = block_proc.LTORBlockProcessor


class Viacoin(AuxPowMixin, Coin):
    NAME = "Viacoin"
    SHORTNAME = "VIA"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("47")
    P2SH_VERBYTES = (bytes.fromhex("21"),)
    WIF_BYTE = bytes.fromhex("c7")
    GENESIS_HASH = ('4e9b54001f9976049830128ec0331515'
                    'eaabe35a70970d79971da1539a400ba1')
    TX_COUNT = 113638
    TX_COUNT_HEIGHT = 3473674
    TX_PER_BLOCK = 30
    RPC_PORT = 5222
    REORG_LIMIT = 5000
    DESERIALIZER = lib_tx.DeserializerAuxPowSegWit
    PEERS = [
        'vialectrum.bitops.me s t',
        'server.vialectrum.org s t',
        'vialectrum.viacoin.net s t',
        'viax1.bitops.me s t',
    ]


class ViacoinTestnet(Viacoin):
    SHORTNAME = "TVI"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("7f")
    P2SH_VERBYTES = (bytes.fromhex("c4"),)
    WIF_BYTE = bytes.fromhex("ff")
    GENESIS_HASH = ('00000007199508e34a9ff81e6ec0c477'
                    'a4cccff2a4767a8eee39c11db367b008')
    RPC_PORT = 25222
    REORG_LIMIT = 2500
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    PEERS = [
        'vialectrum.bysh.me s t',
    ]


class ViacoinTestnetSegWit(ViacoinTestnet):
    NET = "testnet-segwit"
    DESERIALIZER = lib_tx.DeserializerSegWit


# Source: https://github.com/GravityCoinOfficial/GravityCoin/
class GravityCoin(Coin):
    NAME = "GravityCoin"
    SHORTNAME = "GXX"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("28")
    P2SH_VERBYTES = (bytes.fromhex("0a"),)
    WIF_BYTE = bytes.fromhex("d2")
    GENESIS_HASH = '322bad477efb4b33fa4b1f0b2861eaf543c61068da9898a95062fdb02ada486f'
    TX_COUNT = 446050
    TX_COUNT_HEIGHT = 547346
    TX_PER_BLOCK = 2
    PEER_DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    RPC_PORT = 29200
    REORG_LIMIT = 5000
    PEERS = []


# Source: https://github.com/BitcoinZeroOfficial/bitcoinzero
class Bitcoinzero(Coin):
    NAME = "Bitcoinzero"
    SHORTNAME = "BZX"
    TX_COUNT = 43798
    TX_COUNT_HEIGHT = 44
    TX_PER_BLOCK = 576
    NET = "mainnet"
    GENESIS_HASH = '322bad477efb4b33fa4b1f0b2861eaf543c61068da9898a95062fdb02ada486f'
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("4b")
    P2SH_VERBYTES = (bytes.fromhex("22"),)
    WIF_BYTE = bytes.fromhex("d2")
    RPC_PORT = 29202
    REORG_LIMIT = 5000
    PEERS = []


class Unitus(Coin):
    NAME = "Unitus"
    SHORTNAME = "UIS"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("44")
    P2SH_VERBYTES = (bytes.fromhex("0A"),)
    WIF_BYTE = bytes.fromhex("84")
    GENESIS_HASH = ('d8a2b2439d013a59f3bfc626a33487a3'
                    'd7d27e42a3c9e0b81af814cd8e592f31')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 3484561
    TX_COUNT_HEIGHT = 1697605
    TX_PER_BLOCK = 3
    RPC_PORT = 50604
    REORG_LIMIT = 2000
    PEERS = [
        'electrumx.unituscurrency.com s t',
    ]


# Source: namecoin.org
class Namecoin(NameIndexMixin, AuxPowMixin, Coin):
    NAME = "Namecoin"
    SHORTNAME = "NMC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("d7dd6370")
    XPRV_VERBYTES = bytes.fromhex("d7dc6e31")
    P2PKH_VERBYTE = bytes.fromhex("34")
    P2SH_VERBYTES = (bytes.fromhex("0d"),)
    WIF_BYTE = bytes.fromhex("e4")
    GENESIS_HASH = ('000000000062b72c5e2ceb45fbc8587e'
                    '807c155b0da735e6483dfba2f0a9c770')
    DESERIALIZER = lib_tx.DeserializerAuxPowSegWit
    TX_COUNT = 4415768
    TX_COUNT_HEIGHT = 329065
    TX_PER_BLOCK = 10
    RPC_PORT = 8336
    PEERS = [
        '188.167.144.126 s50002',
        '46.229.238.187 s57002',
        '82.119.233.36 s50002',
        'electrum-nmc.le-space.de s50002',
        'ex.lug.gs s446',
        'luggscoqbymhvnkp.onion t82',
        'nmc.bitcoins.sk s50002',
        'nmc2.bitcoins.sk s57002',
        'ulrichard.ch s50006 t50005',
    ]
    BLOCK_PROCESSOR = block_proc.NameIndexBlockProcessor

    # Name opcodes
    OP_NAME_NEW = OpCodes.OP_1
    OP_NAME_FIRSTUPDATE = OpCodes.OP_2
    OP_NAME_UPDATE = OpCodes.OP_3

    # Valid name prefixes.
    NAME_NEW_OPS = [OP_NAME_NEW, -1, OpCodes.OP_2DROP]
    NAME_FIRSTUPDATE_OPS = [OP_NAME_FIRSTUPDATE, "name", -1, -1,
                            OpCodes.OP_2DROP, OpCodes.OP_2DROP]
    NAME_UPDATE_OPS = [OP_NAME_UPDATE, "name", -1, OpCodes.OP_2DROP,
                       OpCodes.OP_DROP]
    NAME_OPERATIONS = (
        NAME_NEW_OPS,
        NAME_FIRSTUPDATE_OPS,
        NAME_UPDATE_OPS,
    )


class NamecoinTestnet(Namecoin):
    NAME = "Namecoin"
    SHORTNAME = "XNM"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = (bytes.fromhex("c4"),)
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('00000007199508e34a9ff81e6ec0c477'
                    'a4cccff2a4767a8eee39c11db367b008')


class NamecoinRegtest(NamecoinTestnet):
    NAME = "Namecoin"
    NET = "regtest"
    GENESIS_HASH = ('0f9188f13cb7b2c71f2a335e3a4fc328'
                    'bf5beb436012afca590b1a11466e2206')
    PEERS = []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1


class Dogecoin(AuxPowMixin, Coin):
    NAME = "Dogecoin"
    SHORTNAME = "DOGE"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("02facafd")
    XPRV_VERBYTES = bytes.fromhex("02fac398")
    P2PKH_VERBYTE = bytes.fromhex("1e")
    P2SH_VERBYTES = (bytes.fromhex("16"),)
    WIF_BYTE = bytes.fromhex("9e")
    GENESIS_HASH = ('1a91e3dace36e2be3bf030a65679fe82'
                    '1aa1d6ef92e7c9902eb318182c355691')
    TX_COUNT = 27583427
    TX_COUNT_HEIGHT = 1604979
    TX_PER_BLOCK = 20
    REORG_LIMIT = 2000
    DESERIALIZER = lib_tx.DeserializerAuxPowSegWit


class DogecoinTestnet(Dogecoin):
    NAME = "Dogecoin"
    SHORTNAME = "XDT"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("71")
    P2SH_VERBYTES = (bytes.fromhex("c4"),)
    WIF_BYTE = bytes.fromhex("f1")
    GENESIS_HASH = ('bb0a78264637406b6360aad926284d54'
                    '4d7049f45189db5664f3c4d07350559e')


# Source: https://github.com/dashpay/dash
class Dash(Coin):
    NAME = "Dash"
    SHORTNAME = "DASH"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("02fe52cc")
    XPRV_VERBYTES = bytes.fromhex("02fe52f8")
    GENESIS_HASH = ('00000ffd590b1485b3caadc19b22e637'
                    '9c733355108f107a430458cdf3407ab6')
    P2PKH_VERBYTE = bytes.fromhex("4c")
    P2SH_VERBYTES = (bytes.fromhex("10"),)
    WIF_BYTE = bytes.fromhex("cc")
    TX_COUNT_HEIGHT = 569399
    TX_COUNT = 2157510
    TX_PER_BLOCK = 4
    RPC_PORT = 9998
    PEERS = [
        'electrum.dash.org s t',
        'electrum.masternode.io s t',
        'electrum-drk.club s t',
        'dashcrypto.space s t',
        'electrum.dash.siampm.com s t',
        'wl4sfwq2hwxnodof.onion s t',
    ]
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon
    DESERIALIZER = lib_tx_dash.DeserializerDash

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x11_hash
        return x11_hash.getPoWHash(header)


class DashTestnet(Dash):
    SHORTNAME = "tDASH"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("3a805837")
    XPRV_VERBYTES = bytes.fromhex("3a8061a0")
    GENESIS_HASH = ('00000bafbc94add76cb75e2ec9289483'
                    '7288a481e5c005f6563d91623bf8bc2c')
    P2PKH_VERBYTE = bytes.fromhex("8c")
    P2SH_VERBYTES = (bytes.fromhex("13"),)
    WIF_BYTE = bytes.fromhex("ef")
    TX_COUNT_HEIGHT = 101619
    TX_COUNT = 132681
    TX_PER_BLOCK = 1
    RPC_PORT = 19998
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    PEERS = [
        'electrum.dash.siampm.com s t',
        'dasht.random.re s54002 t54001',
    ]


class DashRegtest(DashTestnet):
    NET = "regtest"
    GENESIS_HASH = ('000008ca1832a4baf228eb1553c03d3a'
                    '2c8e02399550dd6ea8d65cec3ef23d2e')
    PEERS = []
    TX_COUNT_HEIGHT = 1
    TX_COUNT = 1


class Argentum(AuxPowMixin, Coin):
    NAME = "Argentum"
    SHORTNAME = "ARG"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("17")
    WIF_BYTE = bytes.fromhex("97")
    GENESIS_HASH = ('88c667bc63167685e4e4da058fffdfe8'
                    'e007e5abffd6855de52ad59df7bb0bb2')
    TX_COUNT = 2263089
    TX_COUNT_HEIGHT = 2050260
    TX_PER_BLOCK = 2000
    RPC_PORT = 13581


class ArgentumTestnet(Argentum):
    SHORTNAME = "XRG"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = (bytes.fromhex("c4"),)
    WIF_BYTE = bytes.fromhex("ef")
    REORG_LIMIT = 2000


class DigiByte(Coin):
    NAME = "DigiByte"
    SHORTNAME = "DGB"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1E")
    GENESIS_HASH = ('7497ea1b465eb39f1c8f507bc877078f'
                    'e016d6fcb6dfad3a64c98dcc6e1e8496')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1046018
    TX_COUNT_HEIGHT = 1435000
    TX_PER_BLOCK = 1000
    RPC_PORT = 12022


class DigiByteTestnet(DigiByte):
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = (bytes.fromhex("c4"),)
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('b5dca8039e300198e5fe7cd23bdd1728'
                    'e2a444af34c447dbd0916fa3430a68c2')
    RPC_PORT = 15022
    REORG_LIMIT = 2000


class FairCoin(Coin):
    NAME = "FairCoin"
    SHORTNAME = "FAIR"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("5f")
    P2SH_VERBYTES = (bytes.fromhex("24"),)
    WIF_BYTE = bytes.fromhex("df")
    GENESIS_HASH = ('beed44fa5e96150d95d56ebd5d262578'
                    '1825a9407a5215dd7eda723373a0a1d7')
    BASIC_HEADER_SIZE = 108
    HEADER_VALUES = ('version', 'prev_block_hash', 'merkle_root',
                     'payload_hash', 'timestamp', 'creatorId')
    HEADER_UNPACK = struct.Struct('< I 32s 32s 32s I I').unpack_from
    TX_COUNT = 505
    TX_COUNT_HEIGHT = 470
    TX_PER_BLOCK = 1
    RPC_PORT = 40405
    PEER_DEFAULT_PORTS = {'t': '51811', 's': '51812'}
    PEERS = [
        'electrum.faircoin.world s',
        'electrumfair.punto0.org s',
    ]

    @classmethod
    def block(cls, raw_block, height):
        '''Return a Block given a raw block and its height.'''
        if height > 0:
            return super().block(raw_block, height)
        else:
            return Block(raw_block, cls.block_header(raw_block, height), [])


class Zcash(EquihashMixin, Coin):
    NAME = "Zcash"
    SHORTNAME = "ZEC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1CB8")
    P2SH_VERBYTES = (bytes.fromhex("1CBD"),)
    GENESIS_HASH = ('00040fe8ec8471911baa1db1266ea15d'
                    'd06b4a8a5c453883c000b031973dce08')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 329196
    TX_COUNT_HEIGHT = 68379
    TX_PER_BLOCK = 5
    RPC_PORT = 8232
    REORG_LIMIT = 800


class ZcashTestnet(Zcash):
    SHORTNAME = "TAZ"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("1D25")
    P2SH_VERBYTES = (bytes.fromhex("1CBA"),)
    WIF_BYTE = bytes.fromhex("EF")
    GENESIS_HASH = ('05a60a92d99d85997cce3b87616c089f'
                    '6124d7342af37106edc76126334a2c38')
    TX_COUNT = 242312
    TX_COUNT_HEIGHT = 321685
    TX_PER_BLOCK = 2
    RPC_PORT = 18232


class SnowGem(EquihashMixin, Coin):
    NAME = "SnowGem"
    SHORTNAME = "XSG"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1C28")
    P2SH_VERBYTES = (bytes.fromhex("1C2D"),)
    GENESIS_HASH = ('00068b35729d9d2b0c294ff1fe9af009'
                    '4740524311a131de40e7f705e4c29a5b')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 1680878
    TX_COUNT_HEIGHT = 627250
    TX_PER_BLOCK = 2
    RPC_PORT = 16112
    REORG_LIMIT = 800
    CHUNK_SIZE = 200


class Zero(EquihashMixin, Coin):
    NAME = "Zero"
    SHORTNAME = "ZER"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1CB8")
    P2SH_VERBYTES = (bytes.fromhex("1CBD"),)
    GENESIS_HASH = ('068cbb5db6bc11be5b93479ea4df41fa'
                    '7e012e92ca8603c315f9b1a2202205c6')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 329998
    TX_COUNT_HEIGHT = 847425
    TX_PER_BLOCK = 2
    RPC_PORT = 23811
    REORG_LIMIT = 800


class BitcoinZ(EquihashMixin, Coin):
    NAME = "BitcoinZ"
    SHORTNAME = "BTCZ"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1CB8")
    P2SH_VERBYTES = (bytes.fromhex("1CBD"),)
    GENESIS_HASH = ('f499ee3d498b4298ac6a64205b8addb7'
                    'c43197e2a660229be65db8a4534d75c1')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 171976
    TX_COUNT_HEIGHT = 81323
    TX_PER_BLOCK = 3
    RPC_PORT = 1979
    REORG_LIMIT = 800


class ZelCash(EquihashMixin, Coin):
    NAME = "ZelCash"
    SHORTNAME = "ZEL"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1CB8")
    P2SH_VERBYTES = (bytes.fromhex("1CBD"),)
    GENESIS_HASH = ('00052461a5006c2e3b74ce48992a0869'
                    '5607912d5604c3eb8da25749b0900444')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 450539
    TX_COUNT_HEIGHT = 167114
    TX_PER_BLOCK = 3
    RPC_PORT = 16124
    REORG_LIMIT = 800


class Zclassic(EquihashMixin, Coin):
    NAME = "Zclassic"
    SHORTNAME = "ZCL"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1CB8")
    P2SH_VERBYTES = (bytes.fromhex("1CBD"),)
    GENESIS_HASH = ('0007104ccda289427919efc39dc9e4d4'
                    '99804b7bebc22df55f8b834301260602')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 329196
    TX_COUNT_HEIGHT = 68379
    TX_PER_BLOCK = 5
    RPC_PORT = 8023
    REORG_LIMIT = 800


class Koto(Coin):
    NAME = "Koto"
    SHORTNAME = "KOTO"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1836")
    P2SH_VERBYTES = (bytes.fromhex("183B"),)
    GENESIS_HASH = ('6d424c350729ae633275d51dc3496e16'
                    'cd1b1d195c164da00f39c499a2e9959e')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 158914
    TX_COUNT_HEIGHT = 67574
    TX_PER_BLOCK = 3
    RPC_PORT = 8432
    REORG_LIMIT = 800
    PEERS = [
        'fr.kotocoin.info s t',
        'electrum.kotocoin.info s t',
    ]


class KotoTestnet(Koto):
    SHORTNAME = "TOKO"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("18A4")
    P2SH_VERBYTES = (bytes.fromhex("1839"),)
    WIF_BYTE = bytes.fromhex("EF")
    GENESIS_HASH = ('bf84afbde20c2d213b68b231ddb585ab'
                    '616ef7567226820f00d9b397d774d2f0')
    TX_COUNT = 91144
    TX_COUNT_HEIGHT = 89662
    TX_PER_BLOCK = 1
    RPC_PORT = 18432
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    PEERS = [
        'testnet.kotocoin.info s t',
    ]


class Komodo(KomodoMixin, EquihashMixin, Coin):
    NAME = "Komodo"
    SHORTNAME = "KMD"
    NET = "mainnet"
    TX_COUNT = 693629
    TX_COUNT_HEIGHT = 491777
    TX_PER_BLOCK = 2
    RPC_PORT = 7771
    REORG_LIMIT = 800
    PEERS = []


class Hush(KomodoMixin, EquihashMixin, Coin):
    NAME = "Hush"
    SHORTNAME = "HUSH"
    NET = "mainnet"
    TX_COUNT = 111317
    TX_COUNT_HEIGHT = 169280
    TX_PER_BLOCK = 2
    RPC_PORT = 18031
    REORG_LIMIT = 800


class Monaize(KomodoMixin, EquihashMixin, Coin):
    NAME = "Monaize"
    SHORTNAME = "MNZ"
    NET = "mainnet"
    TX_COUNT = 256
    TX_COUNT_HEIGHT = 128
    TX_PER_BLOCK = 2
    RPC_PORT = 14337
    REORG_LIMIT = 800
    PEERS = []


class Verus(KomodoMixin, EquihashMixin, Coin):
    NAME = "Verus"
    SHORTNAME = "VRSC"
    NET = "mainnet"
    TX_COUNT = 55000
    TX_COUNT_HEIGHT = 42000
    TX_PER_BLOCK = 2
    RPC_PORT = 27486
    REORG_LIMIT = 800
    PEERS = []

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        import verushash
        # if this may be the genesis block, use sha256, otherwise, VerusHash
        if cls.header_prevhash(header) == bytes(32):
            return double_sha256(header)
        else:
            if header[0] == 4 and header[2] >= 1:
                if len(header) < 144 or header[143] < 3:
                    return verushash.verushash_v2b(header)
                elif header[143] < 4:
                    return verushash.verushash_v2b1(header)
                else:
                    return verushash.verushash_v2b2(header)
            else:
                return verushash.verushash(header)


class Einsteinium(Coin):
    NAME = "Einsteinium"
    SHORTNAME = "EMC2"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("21")
    WIF_BYTE = bytes.fromhex("b0")
    GENESIS_HASH = ('4e56204bb7b8ac06f860ff1c845f03f9'
                    '84303b5b97eb7b42868f714611aed94b')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 2087559
    TX_COUNT_HEIGHT = 1358517
    TX_PER_BLOCK = 2
    RPC_PORT = 41879
    REORG_LIMIT = 2000


class Blackcoin(ScryptMixin, Coin):
    NAME = "Blackcoin"
    SHORTNAME = "BLK"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = (bytes.fromhex("55"),)
    WIF_BYTE = bytes.fromhex("99")
    GENESIS_HASH = ('000001faef25dec4fbcf906e6242621d'
                    'f2c183bf232f263d0ba5b101911e4563')
    DAEMON = daemon.LegacyRPCDaemon
    TX_COUNT = 4594999
    TX_COUNT_HEIGHT = 1667070
    TX_PER_BLOCK = 3
    RPC_PORT = 15715
    REORG_LIMIT = 5000


class Bitbay(ScryptMixin, Coin):
    NAME = "Bitbay"
    SHORTNAME = "BAY"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = (bytes.fromhex("55"),)
    WIF_BYTE = bytes.fromhex("99")
    GENESIS_HASH = ('0000075685d3be1f253ce777174b1594'
                    '354e79954d2a32a6f77fe9cba00e6467')
    TX_COUNT = 4594999
    TX_COUNT_HEIGHT = 1667070
    TX_PER_BLOCK = 3
    RPC_PORT = 19914
    REORG_LIMIT = 5000


class DeepOnion(Coin):
    NAME = "DeepOnion"
    SHORTNAME = "ONION"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1F")
    P2SH_VERBYTES = (bytes.fromhex("4E"),)
    WIF_BYTE = bytes.fromhex("9f")
    GENESIS_HASH = ('000004e29458ef4f2e0abab544737b07'
                    '344e6ff13718f7c2d12926166db07b5e')
    DESERIALIZER = lib_tx.DeserializerTxTime
    DAEMON = daemon.LegacyRPCDaemon
    TX_COUNT = 1194707
    TX_COUNT_HEIGHT = 530000
    TX_PER_BLOCK = 2
    RPC_PORT = 18580
    REORG_LIMIT = 200
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    PEERS = []

    @classmethod
    def header_hash(cls, header):
        '''
        Given a header return the hash for DeepOnion.
        Need to download `x13_hash` module
        Source code: https://github.com/MaruCoinOfficial/x13-hash
        '''
        import x13_hash
        return x13_hash.getPoWHash(header)


class Peercoin(Coin):
    NAME = "Peercoin"
    SHORTNAME = "PPC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("37")
    P2SH_VERBYTES = (bytes.fromhex("75"),)
    WIF_BYTE = bytes.fromhex("b7")
    GENESIS_HASH = ('0000000032fe677166d54963b62a4677'
                    'd8957e87c508eaa4fd7eb1c880cd27e3')
    DESERIALIZER = lib_tx.DeserializerTxTimeSegWit
    DAEMON = daemon.FakeEstimateFeeDaemon
    ESTIMATE_FEE = 0.001
    RELAY_FEE = 0.01
    TX_COUNT = 1691771
    TX_COUNT_HEIGHT = 455409
    TX_PER_BLOCK = 4
    RPC_PORT = 9902
    REORG_LIMIT = 5000

    PEERS = [
        "electrum.peercoinexplorer.net s"
    ]

    VALUE_PER_COIN = 1000000


class PeercoinTestnet(Peercoin):
    NAME = "PeercoinTestnet"
    SHORTNAME = "tPPC"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = (bytes.fromhex("c4"),)
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('00000001f757bb737f6596503e17cd17'
                    'b0658ce630cc727c0cca81aec47c9f06')
    ESTIMATE_FEE = 0.001
    PEERS = [
        "testnet-electrum.peercoinexplorer.net s"
    ]


class Trezarcoin(Coin):
    NAME = "Trezarcoin"
    SHORTNAME = "TZC"
    NET = "mainnet"
    VALUE_PER_COIN = 1000000
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("42")
    P2SH_VERBYTES = (bytes.fromhex("08"),)
    WIF_BYTE = bytes.fromhex("c2")
    GENESIS_HASH = ('24502ba55d673d2ee9170d83dae2d1ad'
                    'b3bfb4718e4f200db9951382cc4f6ee6')
    DESERIALIZER = lib_tx.DeserializerTrezarcoin
    HEADER_HASH = lib_tx.DeserializerTrezarcoin.blake2s
    HEADER_HASH_GEN = lib_tx.DeserializerTrezarcoin.blake2s_gen
    BASIC_HEADER_SIZE = 80
    TX_COUNT = 742886
    TX_COUNT_HEIGHT = 643128
    TX_PER_BLOCK = 2
    RPC_PORT = 17299
    REORG_LIMIT = 2000
    PEERS = [
        'electrumx1.trezarcoin.com s t',
    ]

    @classmethod
    def genesis_block(cls, block):
        '''Check the Genesis block is the right one for this coin.

        Return the block less its unspendable coinbase.
        '''
        header = cls.block_header(block, 0)
        header_hex_hash = cls.HEADER_HASH_GEN(header)
        if header_hex_hash != cls.GENESIS_HASH:
            raise CoinError(f'genesis block has hash {header_hex_hash} '
                            f'expected {cls.GENESIS_HASH}')
        return header + b'\0'

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        return cls.HEADER_HASH(header)


class Reddcoin(Coin):
    NAME = "Reddcoin"
    SHORTNAME = "RDD"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("3d")
    WIF_BYTE = bytes.fromhex("bd")
    GENESIS_HASH = ('b868e0d95a3c3c0e0dadc67ee587aaf9'
                    'dc8acbf99e3b4b3110fad4eb74c1decc')
    DESERIALIZER = lib_tx.DeserializerReddcoin
    TX_COUNT = 5413508
    TX_COUNT_HEIGHT = 1717382
    TX_PER_BLOCK = 3
    RPC_PORT = 45443


class TokenPay(ScryptMixin, Coin):
    NAME = "TokenPay"
    SHORTNAME = "TPAY"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("41")
    P2SH_VERBYTES = (bytes.fromhex("7e"),)
    WIF_BYTE = bytes.fromhex("b3")
    GENESIS_HASH = ('000008b71ab32e585a23f0de642dc113'
                    '740144e94c0ece047751e9781f953ae9')
    DESERIALIZER = lib_tx.DeserializerTokenPay
    DAEMON = daemon.LegacyRPCDaemon
    TX_COUNT = 147934
    TX_COUNT_HEIGHT = 73967
    TX_PER_BLOCK = 100
    RPC_PORT = 8800
    REORG_LIMIT = 500
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")

    PEERS = [
        "electrum-us.tpay.ai s",
        "electrum-eu.tpay.ai s",
    ]


class Vertcoin(Coin):
    NAME = "Vertcoin"
    SHORTNAME = "VTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("47")
    GENESIS_HASH = ('4d96a915f49d40b1e5c2844d1ee2dccb'
                    '90013a990ccea12c492d22110489f0c4')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 2383423
    TX_COUNT_HEIGHT = 759076
    TX_PER_BLOCK = 3
    RPC_PORT = 5888
    REORG_LIMIT = 1000


class Monacoin(Coin):
    NAME = "Monacoin"
    SHORTNAME = "MONA"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("32")
    P2SH_VERBYTES = (bytes.fromhex("37"), bytes.fromhex("05"))
    WIF_BYTE = bytes.fromhex("B0")
    GENESIS_HASH = ('ff9f1c0116d19de7c9963845e129f9ed'
                    '1bfc0b376eb54fd7afa42e0d418c8bb6')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 2568580
    TX_COUNT_HEIGHT = 1029766
    TX_PER_BLOCK = 2
    RPC_PORT = 9402
    REORG_LIMIT = 1000
    BLACKLIST_URL = 'https://electrum-mona.org/blacklist.json'
    PEERS = [
        'electrumx.tamami-foundation.org s t',
        'electrumx3.monacoin.nl s t',
        'electrumx1.monacoin.ninja s t',
        'electrumx2.movsign.info s t',
        'electrum-mona.bitbank.cc s t',
        'ri7rzlmdaf4eqbza.onion s t',
    ]


class MonacoinTestnet(Monacoin):
    SHORTNAME = "XMN"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587CF")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6F")
    P2SH_VERBYTES = (bytes.fromhex("75"), bytes.fromhex("C4"))
    WIF_BYTE = bytes.fromhex("EF")
    GENESIS_HASH = ('a2b106ceba3be0c6d097b2a6a6aacf9d'
                    '638ba8258ae478158f449c321061e0b2')
    TX_COUNT = 83602
    TX_COUNT_HEIGHT = 83252
    TX_PER_BLOCK = 1
    RPC_PORT = 19402
    REORG_LIMIT = 1000
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    PEERS = [
        'electrumx1.testnet.monacoin.ninja s t',
        'electrumx1.testnet.monacoin.nl s t',
    ]


class MonacoinRegtest(MonacoinTestnet):
    NET = "regtest"
    GENESIS_HASH = ('7543a69d7c2fcdb29a5ebec2fc064c07'
                    '4a35253b6f3072c8a749473aa590a29c')
    PEERS = []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1


class Crown(AuxPowMixin, Coin):
    NAME = "Crown"
    SHORTNAME = "CRW"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2SH_VERBYTES = (bytes.fromhex("1c"),)
    GENESIS_HASH = ('0000000085370d5e122f64f4ab19c686'
                    '14ff3df78c8d13cb814fd7e69a1dc6da')
    TX_COUNT = 13336629
    TX_COUNT_HEIGHT = 1268206
    TX_PER_BLOCK = 10
    RPC_PORT = 9341
    REORG_LIMIT = 1000
    PEERS = [
        'sgp-crwseed.crowndns.info s t',
        'blr-crwseed.crowndns.info s t',
        'sfo-crwseed.crowndns.info s t',
        'nyc-crwseed.crowndns.info s t',
        'ams-crwseed.crowndns.info s t',
        'tor-crwseed.crowndns.info s t',
        'lon-crwseed.crowndns.info s t',
        'fra-crwseed.crowndns.info s t',
    ]


class Fujicoin(Coin):
    NAME = "Fujicoin"
    SHORTNAME = "FJC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("24")
    P2SH_VERBYTES = (bytes.fromhex("10"),)
    WIF_BYTE = bytes.fromhex("a4")
    GENESIS_HASH = ('adb6d9cfd74075e7f91608add4bd2a2e'
                    'a636f70856183086842667a1597714a0')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 170478
    TX_COUNT_HEIGHT = 1521676
    TX_PER_BLOCK = 1
    RPC_PORT = 3776
    REORG_LIMIT = 1000


class Neblio(ScryptMixin, Coin):
    NAME = "Neblio"
    SHORTNAME = "NEBL"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("35")
    P2SH_VERBYTES = (bytes.fromhex("70"),)
    GENESIS_HASH = ('7286972be4dbc1463d256049b7471c25'
                    '2e6557e222cab9be73181d359cd28bcc')
    TX_COUNT = 23675
    TX_COUNT_HEIGHT = 22785
    TX_PER_BLOCK = 1
    RPC_PORT = 6326
    REORG_LIMIT = 1000


class Bitzeny(Coin):
    NAME = "Bitzeny"
    SHORTNAME = "ZNY"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("51")
    GENESIS_HASH = ('000009f7e55e9e3b4781e22bd87a7cfa'
                    '4acada9e4340d43ca738bf4e9fb8f5ce')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1408733
    TX_COUNT_HEIGHT = 1015115
    TX_PER_BLOCK = 1
    RPC_PORT = 9252
    REORG_LIMIT = 1000

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import zny_yespower_0_5
        return zny_yespower_0_5.getPoWHash(header)


class CanadaeCoin(AuxPowMixin, Coin):
    NAME = "CanadaeCoin"
    SHORTNAME = "CDN"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("1C")
    WIF_BYTE = bytes.fromhex("9c")
    GENESIS_HASH = ('863626dadaef221e2e2f30ff3dacae44'
                    'cabdae9e0028058072181b3fb675d94a')
    ESTIMATE_FEE = 0.0001
    RELAY_FEE = 0.0001
    DAEMON = daemon.FakeEstimateFeeDaemon
    TX_COUNT = 3455905
    TX_COUNT_HEIGHT = 3645419
    TX_PER_BLOCK = 1
    RPC_PORT = 34330
    REORG_LIMIT = 1000


class Denarius(Coin):
    NAME = "Denarius"
    SHORTNAME = "D"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("1E")  # Address starts with a D
    P2SH_VERBYTES = (bytes.fromhex("5A"),)
    WIF_BYTE = bytes.fromhex("9E")  # WIF starts with a 6
    GENESIS_HASH = ('00000d5dbbda01621cfc16bbc1f9bf32'
                    '64d641a5dbf0de89fd0182c2c4828fcd')
    DESERIALIZER = lib_tx.DeserializerTxTime
    TX_COUNT = 4230
    RPC_PORT = 32339
    ESTIMATE_FEE = 0.00001
    RELAY_FEE = 0.00001
    DAEMON = daemon.FakeEstimateFeeDaemon
    TX_COUNT_HEIGHT = 306187
    TX_PER_BLOCK = 4000

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import tribushashm
        return tribushashm.getPoWHash(header)


class DenariusTestnet(Denarius):
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("12")
    P2SH_VERBYTES = (bytes.fromhex("74"),)
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('000086bfe8264d241f7f8e5393f74778'
                    '4b8ca2aa98bdd066278d590462a4fdb4')
    RPC_PORT = 32338
    REORG_LIMIT = 2000


class Sibcoin(Dash):
    NAME = "Sibcoin"
    SHORTNAME = "SIB"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("3F")
    P2SH_VERBYTES = (bytes.fromhex("28"),)
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('00000c492bf73490420868bc577680bf'
                    'c4c60116e7e85343bc624787c21efa4c')
    DAEMON = daemon.DashDaemon
    TX_COUNT = 1000
    TX_COUNT_HEIGHT = 10000
    TX_PER_BLOCK = 1
    RPC_PORT = 1944
    REORG_LIMIT = 1000
    PEERS = []

    @classmethod
    def header_hash(cls, header):
        '''
        Given a header return the hash for sibcoin.
        Need to download `x11_gost_hash` module
        Source code: https://github.com/ivansib/x11_gost_hash
        '''
        import x11_gost_hash
        return x11_gost_hash.getPoWHash(header)


class SibcoinTestnet(Sibcoin):
    SHORTNAME = "tSIB"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    GENESIS_HASH = ('00000617791d0e19f524387f67e558b2'
                    'a928b670b9a3b387ae003ad7f9093017')

    RPC_PORT = 11944


class Chips(Coin):
    NAME = "Chips"
    SHORTNAME = "CHIPS"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("3c")
    P2SH_VERBYTES = (bytes.fromhex("55"),)
    WIF_BYTE = bytes.fromhex("bc")
    GENESIS_HASH = ('0000006e75f6aa0efdbf7db03132aa4e'
                    '4d0c84951537a6f5a7c39a0a9d30e1e7')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 145290
    TX_COUNT_HEIGHT = 318637
    TX_PER_BLOCK = 2
    RPC_PORT = 57776
    REORG_LIMIT = 800


class Feathercoin(Coin):
    NAME = "Feathercoin"
    SHORTNAME = "FTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488BC26")
    XPRV_VERBYTES = bytes.fromhex("0488DAEE")
    P2PKH_VERBYTE = bytes.fromhex("0E")
    WIF_BYTE = bytes.fromhex("8E")
    GENESIS_HASH = ('12a765e31ffd4059bada1e25190f6e98'
                    'c99d9714d334efa41a195a7e7e04bfe2')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 3170843
    TX_COUNT_HEIGHT = 1981777
    TX_PER_BLOCK = 2
    RPC_PORT = 9337
    REORG_LIMIT = 2000
    PEERS = [
        'electrumx-gb-1.feathercoin.network s t',
        'electrumx-gb-2.feathercoin.network s t',
        'electrumx-de-1.feathercoin.network s t',
    ]


class UFO(Coin):
    NAME = "UniformFiscalObject"
    SHORTNAME = "UFO"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("1B")
    P2SH_VERBYTES = (bytes.fromhex("44"),)
    WIF_BYTE = bytes.fromhex("9B")
    GENESIS_HASH = ('ba1d39b4928ab03d813d952daf65fb77'
                    '97fcf538a9c1b8274f4edc8557722d13')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1608926
    TX_COUNT_HEIGHT = 1300154
    TX_PER_BLOCK = 2
    RPC_PORT = 9888
    REORG_LIMIT = 2000
    PEERS = [
        'electrumx1.ufobject.com s t',
    ]


class Newyorkcoin(AuxPowMixin, Coin):
    NAME = "Newyorkcoin"
    SHORTNAME = "NYC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("3c")
    P2SH_VERBYTES = (bytes.fromhex("16"),)
    WIF_BYTE = bytes.fromhex("bc")
    GENESIS_HASH = ('5597f25c062a3038c7fd815fe46c67de'
                    'dfcb3c839fbc8e01ed4044540d08fe48')
    TX_COUNT = 5161944
    TX_COUNT_HEIGHT = 3948743
    TX_PER_BLOCK = 2
    REORG_LIMIT = 2000


class NewyorkcoinTestnet(Newyorkcoin):
    SHORTNAME = "tNYC"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("71")
    P2SH_VERBYTES = (bytes.fromhex("c4"),)
    WIF_BYTE = bytes.fromhex("f1")
    GENESIS_HASH = ('24463e4d3c625b0a9059f309044c2cf0'
                    'd7e196cf2a6ecce901f24f681be33c8f')
    TX_COUNT = 5161944
    TX_COUNT_HEIGHT = 3948743
    TX_PER_BLOCK = 2
    REORG_LIMIT = 2000


class Bitcore(BitcoinMixin, Coin):
    NAME = "Bitcore"
    SHORTNAME = "BTX"
    P2PKH_VERBYTE = bytes.fromhex("03")
    P2SH_VERBYTES = (bytes.fromhex("7D"),)
    DESERIALIZER = lib_tx.DeserializerSegWit
    GENESIS_HASH = ('604148281e5c4b7f2487e5d03cd60d8e'
                    '6f69411d613f6448034508cea52e9574')
    TX_COUNT = 126979
    TX_COUNT_HEIGHT = 126946
    TX_PER_BLOCK = 2
    RPC_PORT = 8556
    PEERS = [
        'ele1.bitcore.cc s t',
        'ele2.bitcore.cc s t',
        'ele3.bitcore.cc s t',
        'ele4.bitcore.cc s t'
    ]


class GameCredits(Coin):
    NAME = "GameCredits"
    SHORTNAME = "GAME"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("26")
    WIF_BYTE = bytes.fromhex("a6")
    GENESIS_HASH = ('91ec5f25ee9a0ffa1af7d4da4db9a552'
                    '228dd2dc77cdb15b738be4e1f55f30ee')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 316796
    TX_COUNT_HEIGHT = 2040250
    TX_PER_BLOCK = 2
    RPC_PORT = 40001
    REORG_LIMIT = 1000


class Machinecoin(Coin):
    NAME = "Machinecoin"
    SHORTNAME = "MAC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("32")
    P2SH_VERBYTES = (bytes.fromhex("26"), bytes.fromhex("05"))
    WIF_BYTE = bytes.fromhex("b2")
    GENESIS_HASH = ('6a1f879bcea5471cbfdee1fd0cb2ddcc'
                    '4fed569a500e352d41de967703e83172')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 137641
    TX_COUNT_HEIGHT = 513020
    TX_PER_BLOCK = 2
    RPC_PORT = 40332
    REORG_LIMIT = 800


class BitcoinAtom(Coin):
    NAME = "BitcoinAtom"
    SHORTNAME = "BCA"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("17")
    P2SH_VERBYTES = (bytes.fromhex("0a"),)
    STATIC_BLOCK_HEADERS = False
    DESERIALIZER = lib_tx.DeserializerBitcoinAtom
    HEADER_SIZE_POST_FORK = 84
    BLOCK_PROOF_OF_STAKE = 0x01
    BLOCK_PROOF_OF_STAKE_FLAGS = b'\x01\x00\x00\x00'
    TX_COUNT = 295158744
    TX_COUNT_HEIGHT = 589197
    TX_PER_BLOCK = 10
    RPC_PORT = 9136
    REORG_LIMIT = 5000

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        header_to_be_hashed = header[:cls.BASIC_HEADER_SIZE]
        # New block header format has some extra flags in the end
        if len(header) == cls.HEADER_SIZE_POST_FORK:
            flags, = util.unpack_le_uint32_from(header, len(header) - 4)
            # Proof of work blocks have special serialization
            if flags & cls.BLOCK_PROOF_OF_STAKE != 0:
                header_to_be_hashed += cls.BLOCK_PROOF_OF_STAKE_FLAGS

        return double_sha256(header_to_be_hashed)

    @classmethod
    def block_header(cls, block, height):
        '''Return the block header bytes'''
        deserializer = cls.DESERIALIZER(block)
        return deserializer.read_header(height, cls.BASIC_HEADER_SIZE)


class Decred(Coin):
    NAME = "Decred"
    SHORTNAME = "DCR"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("02fda926")
    XPRV_VERBYTES = bytes.fromhex("02fda4e8")
    P2PKH_VERBYTE = bytes.fromhex("073f")
    P2SH_VERBYTES = (bytes.fromhex("071a"),)
    WIF_BYTE = bytes.fromhex("22de")
    GENESIS_HASH = ('298e5cc3d985bfe7f81dc135f360abe0'
                    '89edd4396b86d2de66b0cef42b21d980')
    BASIC_HEADER_SIZE = 180
    HEADER_HASH = lib_tx.DeserializerDecred.blake256
    DESERIALIZER = lib_tx.DeserializerDecred
    DAEMON = daemon.DecredDaemon
    BLOCK_PROCESSOR = block_proc.DecredBlockProcessor
    ENCODE_CHECK = partial(Base58.encode_check,
                           hash_fn=lib_tx.DeserializerDecred.blake256d)
    DECODE_CHECK = partial(Base58.decode_check,
                           hash_fn=lib_tx.DeserializerDecred.blake256d)
    HEADER_VALUES = ('version', 'prev_block_hash', 'merkle_root', 'stake_root',
                     'vote_bits', 'final_state', 'voters', 'fresh_stake',
                     'revocations', 'pool_size', 'bits', 'sbits',
                     'block_height', 'size', 'timestamp', 'nonce',
                     'extra_data', 'stake_version')
    HEADER_UNPACK = struct.Struct(
        '< i 32s 32s 32s H 6s H B B I I Q I I I I 32s I').unpack_from
    TX_COUNT = 4629388
    TX_COUNT_HEIGHT = 260628
    TX_PER_BLOCK = 17
    REORG_LIMIT = 1000
    RPC_PORT = 9109

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        return cls.HEADER_HASH(header)

    @classmethod
    def block(cls, raw_block, height):
        '''Return a Block namedtuple given a raw block and its height.'''
        if height > 0:
            return super().block(raw_block, height)
        else:
            return Block(raw_block, cls.block_header(raw_block, height), [])


class DecredTestnet(Decred):
    SHORTNAME = "tDCR"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587d1")
    XPRV_VERBYTES = bytes.fromhex("04358397")
    P2PKH_VERBYTE = bytes.fromhex("0f21")
    P2SH_VERBYTES = (bytes.fromhex("0efc"),)
    WIF_BYTE = bytes.fromhex("230e")
    GENESIS_HASH = (
        'a649dce53918caf422e9c711c858837e08d626ecfcd198969b24f7b634a49bac')
    BASIC_HEADER_SIZE = 180
    ALLOW_ADVANCING_ERRORS = True
    TX_COUNT = 217380620
    TX_COUNT_HEIGHT = 464000
    TX_PER_BLOCK = 1800
    REORG_LIMIT = 1000
    RPC_PORT = 19109


class Axe(Dash):
    NAME = "Axe"
    SHORTNAME = "AXE"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("02fe52cc")
    XPRV_VERBYTES = bytes.fromhex("02fe52f8")
    P2PKH_VERBYTE = bytes.fromhex("37")
    P2SH_VERBYTES = (bytes.fromhex("10"),)
    WIF_BYTE = bytes.fromhex("cc")
    GENESIS_HASH = ('00000c33631ca6f2f61368991ce2dc03'
                    '306b5bb50bf7cede5cfbba6db38e52e6')
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon
    DESERIALIZER = lib_tx_axe.DeserializerAxe
    TX_COUNT = 18405
    TX_COUNT_HEIGHT = 30237
    TX_PER_BLOCK = 1
    RPC_PORT = 9337
    REORG_LIMIT = 1000
    PEERS = []

    @classmethod
    def header_hash(cls, header):
        '''
        Given a header return the hash for AXE.
        Need to download `axe_hash` module
        Source code: https://github.com/AXErunners/axe_hash
        '''
        import x11_hash
        return x11_hash.getPoWHash(header)


class AxeTestnet(Axe):
    SHORTNAME = "tAxe"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("3a805837")
    XPRV_VERBYTES = bytes.fromhex("3a8061a0")
    GENESIS_HASH = ('000005b709662e7bc5e89c71d3aba6c9'
                    'd4623b4bbf44ac205caec55f4cefb483')
    P2PKH_VERBYTE = bytes.fromhex("8c")
    P2SH_VERBYTES = (bytes.fromhex("13"),)
    WIF_BYTE = bytes.fromhex("ef")
    TX_COUNT_HEIGHT = 101619
    TX_COUNT = 132681
    TX_PER_BLOCK = 1
    RPC_PORT = 19937
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    PEERS = []


class AxeRegtest(AxeTestnet):
    NET = "regtest"
    GENESIS_HASH = ('2026b8850f3774a0536152ba868c4dcb'
                    'de9aef5ffc28a5d23f76f80e9b46e565')
    PEERS = []
    TX_COUNT_HEIGHT = 1
    RPC_PORT = 19869
    TX_COUNT = 1


class Xuez(Coin):
    NAME = "Xuez"
    SHORTNAME = "XUEZ"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("022d2533")
    XPRV_VERBYTES = bytes.fromhex("0221312b")
    P2PKH_VERBYTE = bytes.fromhex("48")
    P2SH_VERBYTES = (bytes.fromhex("12"),)
    WIF_BYTE = bytes.fromhex("d4")
    GENESIS_HASH = ('000000e1febc39965b055e8e0117179a'
                    '4d18e24e7aaa0c69864c4054b4f29445')
    TX_COUNT = 30000
    TX_COUNT_HEIGHT = 15000
    TX_PER_BLOCK = 1
    RPC_PORT = 41799
    REORG_LIMIT = 1000
    BASIC_HEADER_SIZE = 112
    PEERS = []

    @classmethod
    def header_hash(cls, header):
        '''
        Given a header return the hash for Xuez.
        Need to download `xevan_hash` module
        Source code: https://github.com/xuez/xuez
        '''
        version, = util.unpack_le_uint32_from(header)

        import xevan_hash

        if version == 1:
            return xevan_hash.getPoWHash(header[:80])
        else:
            return xevan_hash.getPoWHash(header)


# Source: https://github.com/odinblockchain/odin
class Odin(Coin):
    NAME = "ODIN"
    SHORTNAME = "ODIN"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("27561872")
    XPRV_VERBYTES = bytes.fromhex("27256746")
    P2PKH_VERBYTE = bytes.fromhex("73")
    P2SH_VERBYTES = (bytes.fromhex("39"),)
    WIF_BYTE = bytes.fromhex("8a")
    GENESIS_HASH = ('31ca29566549e444cf227a0e2e067aed'
                    '847c2acc541d3bbf9ca1ae89f4fd57d7')

    TX_COUNT = 340000
    TX_COUNT_HEIGHT = 340000
    TX_PER_BLOCK = 2
    RPC_PORT = 22101
    REORG_LIMIT = 100

    BASIC_HEADER_SIZE = 80
    HDR_V4_SIZE = 112
    HDR_V4_HEIGHT = 143447
    HDR_V4_START_OFFSET = HDR_V4_HEIGHT * BASIC_HEADER_SIZE

    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon
    DESERIALIZER = lib_tx.DeserializerSegWit

    @classmethod
    def static_header_offset(cls, height):
        assert cls.STATIC_BLOCK_HEADERS
        if height >= cls.HDR_V4_HEIGHT:
            relative_v4_offset = (height - cls.HDR_V4_HEIGHT) * cls.HDR_V4_SIZE
            return cls.HDR_V4_START_OFFSET + relative_v4_offset
        else:
            return height * cls.BASIC_HEADER_SIZE

    @classmethod
    def header_hash(cls, header):
        version, = util.unpack_le_uint32_from(header)
        if version >= 4:
            return super().header_hash(header)
        else:
            import quark_hash
            return quark_hash.getPoWHash(header)


class Pac(Coin):
    NAME = "PAC"
    SHORTNAME = "PAC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    GENESIS_HASH = ('00000354655ff039a51273fe61d3b493'
                    'bd2897fe6c16f732dbc4ae19f04b789e')
    P2PKH_VERBYTE = bytes.fromhex("37")
    P2SH_VERBYTES = (bytes.fromhex("0A"),)
    WIF_BYTE = bytes.fromhex("CC")
    TX_COUNT_HEIGHT = 14939
    TX_COUNT = 23708
    TX_PER_BLOCK = 2
    RPC_PORT = 7111
    PEERS = [
        'electrum.paccoin.io s t',
        'electro-pac.paccoin.io s t'
    ]
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon
    ESTIMATE_FEE = 0.00001
    RELAY_FEE = 0.00001

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x11_hash
        return x11_hash.getPoWHash(header)


class PacTestnet(Pac):
    SHORTNAME = "tPAC"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587CF")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    GENESIS_HASH = ('00000da63bd9478b655ef6bf1bf76cd9'
                    'af05202ab68643f9091e049b2b5280ed')
    P2PKH_VERBYTE = bytes.fromhex("78")
    P2SH_VERBYTES = (bytes.fromhex("0E"),)
    WIF_BYTE = bytes.fromhex("EF")
    TX_COUNT_HEIGHT = 16275
    TX_COUNT = 16275
    TX_PER_BLOCK = 1
    RPC_PORT = 17111


class Zcoin(Coin):
    NAME = "Zcoin"
    SHORTNAME = "XZC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("52")
    P2SH_VERBYTES = (bytes.fromhex("07"),)
    WIF_BYTE = bytes.fromhex("d2")
    GENESIS_HASH = ('4381deb85b1b2c9843c222944b616d99'
                    '7516dcbd6a964e1eaf0def0830695233')
    TX_COUNT = 667154
    TX_COUNT_HEIGHT = 100266
    TX_PER_BLOCK = 4000  # 2000 for 1MB block
    IRC_PREFIX = None
    RPC_PORT = 8888
    REORG_LIMIT = 5000
    PEER_DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    MTP_HEADER_EXTRA_SIZE = 100
    MTP_HEADER_DATA_SIZE = 198864
    MTP_HEADER_DATA_START = Coin.BASIC_HEADER_SIZE + MTP_HEADER_EXTRA_SIZE
    MTP_HEADER_DATA_END = MTP_HEADER_DATA_START + MTP_HEADER_DATA_SIZE
    STATIC_BLOCK_HEADERS = False
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.ZcoinMtpDaemon
    DESERIALIZER = lib_tx.DeserializerZcoin
    PEERS = [
        'electrum.polispay.com'
    ]

    @classmethod
    def is_mtp(cls, header):
        from electrumx.lib.util import unpack_le_uint32_from, hex_to_bytes
        if isinstance(header, str):
            nVersion, = unpack_le_uint32_from(hex_to_bytes(header[0:4*2]))
        elif isinstance(header, bytes):
            nVersion, = unpack_le_uint32_from(header[0:4])
        else:
            raise "Cannot handle the passed type"
        return nVersion & 0x1000

    @classmethod
    def block_header(cls, block, height):
        sz = cls.BASIC_HEADER_SIZE
        if cls.is_mtp(block):
            sz += cls.MTP_HEADER_EXTRA_SIZE
        return block[:sz]

    @classmethod
    def header_hash(cls, header):
        sz = cls.BASIC_HEADER_SIZE
        if cls.is_mtp(header):
            sz += cls.MTP_HEADER_EXTRA_SIZE
        return double_sha256(header[:sz])


class ZcoinTestnet(Zcoin):
    SHORTNAME = "tXZC"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("41")
    P2SH_VERBYTES = (bytes.fromhex("b2"),)
    WIF_BYTE = bytes.fromhex("b9")
    GENESIS_HASH = '1e3487fdb1a7d46dac3e8f3e58339c6e' \
                   'ff54abf6aef353485f3ed64250a35e89'
    REORG_LIMIT = 8000
    RPC_PORT = 18888


class Polis(Coin):
    NAME = "Polis"
    SHORTNAME = "POLIS"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("03E25D7E")
    XPRV_VERBYTES = bytes.fromhex("03E25945")
    GENESIS_HASH = ('000009701eb781a8113b1af1d814e2f0'
                    '60f6408a2c990db291bc5108a1345c1e')
    P2PKH_VERBYTE = bytes.fromhex("37")
    P2SH_VERBYTES = (bytes.fromhex("38"),)
    WIF_BYTE = bytes.fromhex("3c")
    TX_COUNT_HEIGHT = 280600
    TX_COUNT = 635415
    TX_PER_BLOCK = 4
    RPC_PORT = 24127
    PEERS = [
        'electrum.polispay.com'
    ]
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x11_hash
        return x11_hash.getPoWHash(header)


class MNPCoin(Coin):
    NAME = "MNPCoin"
    SHORTNAME = "MNP"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    GENESIS_HASH = ('00000924036c67d803ce606ded814312'
                    '7e62fa2111dd3b063880a1067c69ccb1')
    P2PKH_VERBYTE = bytes.fromhex("32")
    P2SH_VERBYTES = (bytes.fromhex("35"),)
    WIF_BYTE = bytes.fromhex("37")
    TX_COUNT_HEIGHT = 248000
    TX_COUNT = 506447
    TX_PER_BLOCK = 4
    RPC_PORT = 13373
    PEERS = [
        'electrum.polispay.com'
    ]
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import quark_hash
        return quark_hash.getPoWHash(header)


class ColossusXT(Coin):
    NAME = "ColossusXT"
    SHORTNAME = "COLX"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    GENESIS_HASH = ('a0ce8206c908357008c1b9a8ba2813af'
                    'f0989ca7f72d62b14e652c55f02b4f5c')
    P2PKH_VERBYTE = bytes.fromhex("1E")
    P2SH_VERBYTES = (bytes.fromhex("0D"),)
    WIF_BYTE = bytes.fromhex("D4")
    TX_COUNT_HEIGHT = 356500
    BASIC_HEADER_SIZE = 80
    HDR_V5_HEIGHT = 500000
    HDR_V5_SIZE = 112
    HDR_V5_START_OFFSET = HDR_V5_HEIGHT * BASIC_HEADER_SIZE
    TX_COUNT = 761041
    TX_PER_BLOCK = 4
    RPC_PORT = 51473
    PEERS = [
        'electrum.polispay.com'
    ]
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon

    @classmethod
    def static_header_offset(cls, height):
        assert cls.STATIC_BLOCK_HEADERS
        if height >= cls.HDR_V5_HEIGHT:
            relative_v4_offset = (height - cls.HDR_V5_HEIGHT) * cls.HDR_V5_SIZE
            return cls.HDR_V5_START_OFFSET + relative_v4_offset
        else:
            return height * cls.BASIC_HEADER_SIZE

    @classmethod
    def header_hash(cls, header):
        version, = util.unpack_le_uint32_from(header)
        if version >= 5:
            return super().header_hash(header)
        else:
            import quark_hash
            return quark_hash.getPoWHash(header)


class Minexcoin(EquihashMixin, Coin):
    NAME = "Minexcoin"
    SHORTNAME = "MNX"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("4b")
    GENESIS_HASH = ('490a36d9451a55ed197e34aca7414b35'
                    'd775baa4a8e896f1c577f65ce2d214cb')
    STATIC_BLOCK_HEADERS = True
    BASIC_HEADER_SIZE = 209
    HEADER_SIZE_NO_SOLUTION = 140
    TX_COUNT = 327963
    TX_COUNT_HEIGHT = 74495
    TX_PER_BLOCK = 5
    RPC_PORT = 8022
    CHUNK_SIZE = 960
    PEERS = [
        'electrumx.xpresit.net s t',
        'elex01-ams.turinex.eu s t',
        'eu.minexpool.nl s t'
    ]

    @classmethod
    def block_header(cls, block, height):
        '''Return the block header bytes'''
        deserializer = cls.DESERIALIZER(block)
        return deserializer.read_header(cls.HEADER_SIZE_NO_SOLUTION)


class Groestlcoin(Coin):
    NAME = "Groestlcoin"
    SHORTNAME = "GRS"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("24")
    GENESIS_HASH = ('00000ac5927c594d49cc0bdb81759d0d'
                    'a8297eb614683d3acb62f0703b639023')
    DESERIALIZER = lib_tx.DeserializerGroestlcoin
    TX_COUNT = 115900
    TX_COUNT_HEIGHT = 1601528
    TX_PER_BLOCK = 5
    RPC_PORT = 1441
    BLACKLIST_URL = 'https://groestlcoin.org/blacklist.json'
    PEERS = [
        'electrum1.groestlcoin.org s t',
        'electrum2.groestlcoin.org s t',
        'glzyzqiulwclsowniyjeg5tspdojfgiiizbpnepcxoswqkmsjzlkucqd.onion t',
        'jcv7kwu3gopzxp3r2ve43m6nahrxzc426hif4o3a2vt7wl4xq6tg3xqd.onion t',
    ]

    def grshash(data):
        import groestlcoin_hash
        return groestlcoin_hash.getHash(data, len(data))

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        return cls.grshash(header)

    ENCODE_CHECK = partial(Base58.encode_check, hash_fn=grshash)
    DECODE_CHECK = partial(Base58.decode_check, hash_fn=grshash)


class GroestlcoinTestnet(Groestlcoin):
    SHORTNAME = "TGRS"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = (bytes.fromhex("c4"),)
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('000000ffbb50fc9898cdd36ec163e6ba'
                    '23230164c0052a28876255b7dcf2cd36')
    RPC_PORT = 17766
    PEERS = [
        'electrum-test1.groestlcoin.org s t',
        'electrum-test2.groestlcoin.org s t',
        'v2wuvscywpli35kgolqrt2kw67rqfbfwfn4bv3pc6gtugkexqv675uqd.onion t',
        '75dycxl6lqxujplls3qkhkzffptzdfohv3y5um7s5nhyu6idayqmk7id.onion t',
    ]

class GroestlcoinRegtest(GroestlcoinTestnet):
    SHORTNAME = "GRSRT"
    NET = "regtest"
    RPC_PORT = 18443
    PEERS = []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1

class GroestlcoinSignet(GroestlcoinTestnet):
    SHORTNAME = "SGRS"
    NET = "signet"
    GENESIS_HASH = ('0000007fcaa2a27993c6cde9e7818c25'
                    '4357af517b876ceba2f23592bb14ab31')
    RPC_PORT = 31441
    PEERS = []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1

class Pivx(Coin):
    NAME = "PIVX"
    SHORTNAME = "PIVX"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("022D2533")
    XPRV_VERBYTES = bytes.fromhex("0221312B")
    GENESIS_HASH = '0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818'
    P2PKH_VERBYTE = bytes.fromhex("1e")
    P2SH_VERBYTE = bytes.fromhex("0d")
    WIF_BYTE = bytes.fromhex("d4")
    DESERIALIZER = lib_tx.DeserializerPIVX
    TX_COUNT_HEIGHT = 569399
    TX_COUNT = 2157510
    TX_PER_BLOCK = 1
    STATIC_BLOCK_HEADERS = False
    RPC_PORT = 51470
    REORG_LIMIT = 100
    EXPANDED_HEADER = 112
    ZEROCOIN_START_HEIGHT = 863787
    ZEROCOIN_END_HEIGHT = 2153200
    ZEROCOIN_BLOCK_VERSION = 4
    SAPLING_START_HEIGHT = 2700500

    @classmethod
    def static_header_len(cls, height):
        '''Given a header height return its length.'''
        if (height >= cls.ZEROCOIN_START_HEIGHT and height < cls.ZEROCOIN_END_HEIGHT) \
                or (height >= cls.SAPLING_START_HEIGHT):
            return cls.EXPANDED_HEADER
        else:
            return cls.BASIC_HEADER_SIZE

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        version, = struct.unpack('<I', header[:4])
        if version >= cls.ZEROCOIN_BLOCK_VERSION:
            return super().header_hash(header)
        else:
            import quark_hash
            return quark_hash.getPoWHash(header)


class PivxTestnet(Pivx):
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("3a8061a0")
    XPRV_VERBYTES = bytes.fromhex("3a805837")
    GENESIS_HASH = '0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818'
    P2PKH_VERBYTE = bytes.fromhex("8B")
    P2SH_VERBYTE = bytes.fromhex("13")
    WIF_BYTE = bytes.fromhex("EF")
    TX_PER_BLOCK = 4
    RPC_PORT = 51472
    ZEROCOIN_START_HEIGHT = 201
    ZEROCOIN_END_HEIGHT = 201
    ZEROCOIN_BLOCK_VERSION = 4
    SAPLING_START_HEIGHT = 201

    @classmethod
    def static_header_len(cls, height):
        '''Given a header height return its length.'''
        if (height >= cls.ZEROCOIN_START_HEIGHT and height < cls.ZEROCOIN_END_HEIGHT) or (
                height >= cls.SAPLING_START_HEIGHT):
            return cls.EXPANDED_HEADER
        else:
            return cls.BASIC_HEADER_SIZE


class Bitg(Coin):

    NAME = "BitcoinGreen"
    SHORTNAME = "BITG"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("26")
    P2SH_VERBYTES = (bytes.fromhex("06"),)
    WIF_BYTE = bytes.fromhex("2e")
    GENESIS_HASH = (
        '000008467c3a9c587533dea06ad9380cded3ed32f9742a6c0c1aebc21bf2bc9b')
    DAEMON = daemon.DashDaemon
    TX_COUNT = 1000
    TX_COUNT_HEIGHT = 10000
    TX_PER_BLOCK = 1
    RPC_PORT = 9332
    REORG_LIMIT = 1000
    SESSIONCLS = DashElectrumX

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import quark_hash
        return quark_hash.getPoWHash(header)


class tBitg(Bitg):
    SHORTNAME = "tBITG"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("62")
    P2SH_VERBYTES = (bytes.fromhex("0c"),)
    WIF_BYTE = bytes.fromhex("6c")
    GENESIS_HASH = (
        '000008467c3a9c587533dea06ad9380cded3ed32f9742a6c0c1aebc21bf2bc9b')
    RPC_PORT = 19332


class EXOS(Coin):
    NAME = "EXOS"
    SHORTNAME = "EXOS"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    GENESIS_HASH = ('00000036090a68c523471da7a4f0f958'
                    'c1b4403fef74a003be7f71877699cab7')
    P2PKH_VERBYTE = bytes.fromhex("1C")
    P2SH_VERBYTE = [bytes.fromhex("57")]
    WIF_BYTE = bytes.fromhex("9C")
    RPC_PORT = 4561
    TX_COUNT = 1000
    TX_COUNT_HEIGHT = 10000
    TX_PER_BLOCK = 4
    DAEMON = daemon.PreLegacyRPCDaemon
    DESERIALIZER = lib_tx.DeserializerTxTime

    @classmethod
    def header_hash(cls, header):
        version, = util.unpack_le_uint32_from(header)

        if version > 2:
            return double_sha256(header)
        else:
            return hex_str_to_hash(EXOS.GENESIS_HASH)


class EXOSTestnet(EXOS):
    SHORTNAME = "tEXOS"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    GENESIS_HASH = ('0000059bb2c2048493efcb0f1a034972'
                    'b3ce4089d54c93b69aaab212fb369887')
    P2PKH_VERBYTE = bytes.fromhex("4B")
    P2SH_VERBYTE = [bytes.fromhex("CE")]
    WIF_BYTE = bytes.fromhex("CB")
    RPC_PORT = 14561

    @classmethod
    def header_hash(cls, header):
        version, = util.unpack_le_uint32_from(header)

        if version > 2:
            return double_sha256(header)
        else:
            return hex_str_to_hash(EXOSTestnet.GENESIS_HASH)


class SmartCash(Coin):
    NAME = "SmartCash"
    SHORTNAME = "SMART"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("3f")
    P2SH_VERBYTES = (bytes.fromhex("12"),)
    WIF_BYTE = bytes.fromhex("bf")
    GENESIS_HASH = ('000007acc6970b812948d14ea5a0a13d'
                    'b0fdd07d5047c7e69101fa8b361e05a4')
    DESERIALIZER = lib_tx.DeserializerSmartCash
    RPC_PORT = 9679
    REORG_LIMIT = 5000
    TX_COUNT = 1115016
    TX_COUNT_HEIGHT = 541656
    TX_PER_BLOCK = 1
    ENCODE_CHECK = partial(Base58.encode_check,
                           hash_fn=lib_tx.DeserializerSmartCash.keccak)
    DECODE_CHECK = partial(Base58.decode_check,
                           hash_fn=lib_tx.DeserializerSmartCash.keccak)
    HEADER_HASH = lib_tx.DeserializerSmartCash.keccak
    DAEMON = daemon.SmartCashDaemon
    SESSIONCLS = SmartCashElectrumX

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        return cls.HEADER_HASH(header)


class NIX(Coin):
    NAME = "NIX"
    SHORTNAME = "NIX"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("26")
    P2SH_VERBYTES = (bytes.fromhex("35"),)
    GENESIS_HASH = ('dd28ad86def767c3cfc34267a950d871'
                    'fc7462bc57ea4a929fc3596d9b598e41')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 114240
    TX_COUNT_HEIGHT = 87846
    TX_PER_BLOCK = 3
    RPC_PORT = 6215
    REORG_LIMIT = 1000


class NIXTestnet(NIX):
    SHORTNAME = "tNIX"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    GENESIS_HASH = ('dd28ad86def767c3cfc34267a950d871'
                    'fc7462bc57ea4a929fc3596d9b598e41')
    P2PKH_VERBYTE = bytes.fromhex("01")
    P2SH_VERBYTE = [bytes.fromhex("03")]
    RPC_PORT = 16215
    DESERIALIZER = lib_tx.DeserializerSegWit


class Noir(Coin):
    NAME = "Noir"
    SHORTNAME = "NOR"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2SH_VERBYTES = (bytes.fromhex("07"),)
    WIF_BYTE = bytes.fromhex("D0")
    GENESIS_HASH = ('23911212a525e3d149fcad6c559c8b17'
                    'f1e8326a272a75ff9bb315c8d96433ef')
    RPC_PORT = 8825
    TX_COUNT = 586369
    TX_COUNT_HEIGHT = 379290
    TX_PER_BLOCK = 5


class BitcoinPlus(Coin):
    NAME = "BitcoinPlus"
    SHORTNAME = "XBC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = (bytes.fromhex("55"),)
    WIF_BYTE = bytes.fromhex("99")
    GENESIS_HASH = ('0000005f6a28e686f641c616e56182d1'
                    'b43afbe08a223f23bda23cdf9d55b882')
    DESERIALIZER = lib_tx.DeserializerTxTime
    DAEMON = daemon.LegacyRPCDaemon
    TX_COUNT = 1479247
    TX_COUNT_HEIGHT = 749740
    TX_PER_BLOCK = 2
    RPC_PORT = 8885
    REORG_LIMIT = 2000

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x13_hash
        return x13_hash.getPoWHash(header)


class Myriadcoin(AuxPowMixin, Coin):
    NAME = "Myriadcoin"
    SHORTNAME = "XMY"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("32")
    P2SH_VERBYTES = (bytes.fromhex("09"),)
    WIF_BYTE = bytes.fromhex("b2")
    GENESIS_HASH = ('00000ffde4c020b5938441a0ea3d314b'
                    'f619eff0b38f32f78f7583cffa1ea485')
    DESERIALIZER = lib_tx.DeserializerAuxPowSegWit
    TX_COUNT = 1976629
    TX_COUNT_HEIGHT = 2580356
    TX_PER_BLOCK = 20
    REORG_LIMIT = 2000
    RPC_PORT = 10889


class MyriadcoinTestnet(Myriadcoin):
    NAME = "Myriadcoin"
    SHORTNAME = "XMT"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("58")
    P2SH_VERBYTES = (bytes.fromhex("bc"),)
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('0000017ce2a79c8bddafbbe47c004aa9'
                    '2b20678c354b34085f62b762084b9788')


# Source: https://github.com/LIMXTEC/BitSend
class Bitsend(Coin):
    NAME = "Bitsend"
    SHORTNAME = "BSD"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("66")
    WIF_BYTE = bytes.fromhex("cc")
    GENESIS_HASH = ('0000012e1b8843ac9ce8c18603658eaf'
                    '8895f99d3f5e7e1b7b1686f35e3c087a')
    TX_COUNT = 974672
    TX_COUNT_HEIGHT = 586022
    TX_PER_BLOCK = 2
    RPC_PORT = 8800
    REORG_LIMIT = 1000
    DESERIALIZER = lib_tx.DeserializerSegWit
    XEVAN_TIMESTAMP = 1477958400
    PEERS = [
        'ele1.bitsend.cc s t',
        '51.15.121.233 s t'
    ]

    @classmethod
    def header_hash(cls, header):
        timestamp, = util.unpack_le_uint32_from(header, 68)
        if timestamp > cls.XEVAN_TIMESTAMP:
            import xevan_hash
            return xevan_hash.getPoWHash(header)
        else:
            import x11_hash
            return x11_hash.getPoWHash(header)

    @classmethod
    def genesis_block(cls, block):
        header = cls.block_header(block, 0)
        header_hex_hash = hash_to_hex_str(cls.header_hash(header))
        if header_hex_hash != cls.GENESIS_HASH:
            raise CoinError(f'genesis block has hash {header_hex_hash} '
                            f'expected {cls.GENESIS_HASH}')
        return header + b'\0'


class Ritocoin(Coin):
    NAME = "Ritocoin"
    SHORTNAME = "RITO"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0534E7CA")
    XPRV_VERBYTES = bytes.fromhex("05347EAC")
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = (bytes.fromhex("69"),)
    GENESIS_HASH = ('00000075e344bdf1c0e433f453764b18'
                    '30a7aa19b2a5213e707502a22b779c1b')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1188090
    TX_COUNT_HEIGHT = 296030
    TX_PER_BLOCK = 3
    RPC_PORT = 8766
    REORG_LIMIT = 55
    PEERS = [
        'electrum-rito.minermore.com s t'
    ]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x21s_hash
        return x21s_hash.getPoWHash(header)


class Ravencoin(Coin):
    NAME = "Ravencoin"
    SHORTNAME = "RVN"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("3C")
    P2SH_VERBYTES = (bytes.fromhex("7A"),)
    GENESIS_HASH = ('0000006b444bc2f2ffe627be9d9e7e7a'
                    '0730000870ef6eb6da46c8eae389df90')
    DESERIALIZER = lib_tx.DeserializerSegWit
    X16RV2_ACTIVATION_TIME = 1569945600   # algo switch to x16rv2 at this timestamp
    KAWPOW_ACTIVATION_TIME = 1588788000  # kawpow algo activation time
    KAWPOW_ACTIVATION_HEIGHT = 1219736
    KAWPOW_HEADER_SIZE = 120
    TX_COUNT = 5626682
    TX_COUNT_HEIGHT = 887000
    TX_PER_BLOCK = 6
    RPC_PORT = 8766
    REORG_LIMIT = 100
    PEERS = [
    ]

    @classmethod
    def static_header_offset(cls, height):
        '''Given a header height return its offset in the headers file.'''
        if cls.KAWPOW_ACTIVATION_HEIGHT < 0 or height <= cls.KAWPOW_ACTIVATION_HEIGHT:
            result = height * cls.BASIC_HEADER_SIZE
        else:  # RVN block header size increased with kawpow fork
            baseoffset = cls.KAWPOW_ACTIVATION_HEIGHT * cls.BASIC_HEADER_SIZE
            result = baseoffset + ((height-cls.KAWPOW_ACTIVATION_HEIGHT) * cls.KAWPOW_HEADER_SIZE)
        return result

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        timestamp = util.unpack_le_uint32_from(header, 68)[0]
        assert cls.KAWPOW_ACTIVATION_TIME > 0

        def reverse_bytes(data):
            b = bytearray(data)
            b.reverse()
            return bytes(b)

        if timestamp >= cls.KAWPOW_ACTIVATION_TIME:
            import kawpow
            nNonce64 = util.unpack_le_uint64_from(header, 80)[0]  # uint64_t
            mix_hash = reverse_bytes(header[88:120])  # uint256

            header_hash = reverse_bytes(double_sha256(header[:80]))

            final_hash = reverse_bytes(kawpow.light_verify(header_hash, mix_hash, nNonce64))
            return final_hash

        elif timestamp >= cls.X16RV2_ACTIVATION_TIME:
            import x16rv2_hash
            return x16rv2_hash.getPoWHash(header)
        else:
            import x16r_hash
            return x16r_hash.getPoWHash(header)


class RavencoinTestnet(Ravencoin):
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587CF")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6F")
    P2SH_VERBYTES = (bytes.fromhex("C4"),)
    WIF_BYTE = bytes.fromhex("EF")
    GENESIS_HASH = ('000000ecfc5e6324a079542221d00e10'
                    '362bdc894d56500c414060eea8a3ad5a')
    X16RV2_ACTIVATION_TIME = 1567533600
    KAWPOW_ACTIVATION_HEIGHT = 231544
    KAWPOW_ACTIVATION_TIME = 1585159200
    TX_COUNT = 496158
    TX_COUNT_HEIGHT = 420500
    TX_PER_BLOCK = 1
    RPC_PORT = 18766
    PEER_DEFAULT_PORTS = {'t': '50003', 's': '50004'}
    REORG_LIMIT = 100
    PEERS = [
    ]


class Bolivarcoin(Coin):
    NAME = "Bolivarcoin"
    SHORTNAME = "BOLI"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("55")
    P2SH_VERBYTES = (bytes.fromhex("05"),)
    WIF_BYTE = bytes.fromhex("D5")
    GENESIS_HASH = ('00000e4fc293a1912b9d73cbb8d8f727'
                    '0007a7d84382f1370661e65d5d57b1f6')
    TX_COUNT = 1082515
    TX_COUNT_HEIGHT = 540410
    TX_PER_BLOCK = 10
    RPC_PORT = 3563
    REORG_LIMIT = 800
    PEERS = []
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x11_hash
        return x11_hash.getPoWHash(header)


class Onixcoin(Coin):
    NAME = "Onixcoin"
    SHORTNAME = "ONX"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("4B")
    GENESIS_HASH = ('000007140b7a6ca0b64965824f5731f6'
                    'e86daadf19eb299033530b1e61236e43')
    TX_COUNT = 431808
    TX_COUNT_HEIGHT = 321132
    TX_PER_BLOCK = 10
    RPC_PORT = 41019
    REORG_LIMIT = 800
    PEERS = []
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x11_hash
        return x11_hash.getPoWHash(header)


class Electra(Coin):
    NAME = "Electra"
    SHORTNAME = "ECA"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("21")
    P2SH_VERBYTES = (bytes.fromhex("28"),)
    WIF_BYTE = bytes.fromhex("A1")
    GENESIS_HASH = ('00000f98da995de0ef1665c7d3338687'
                    '923c1199230a44ecbdb5cec9306e4f4e')
    RPC_PORT = 5788
    TX_COUNT = 615729
    TX_COUNT_HEIGHT = 205243
    TX_PER_BLOCK = 3
    REORG_LIMIT = 100
    DESERIALIZER = lib_tx.DeserializerElectra

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        version, = util.unpack_le_uint32_from(header)
        import nist5_hash

        if version != 8:
            return nist5_hash.getPoWHash(header)
        else:
            return double_sha256(header)


class ECCoin(Coin):
    NAME = "ECCoin"
    SHORTNAME = "ECC"
    NET = "mainnet"
    DESERIALIZER = lib_tx.DeserializerECCoin
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("21")
    P2SH_VERBYTES = (bytes.fromhex("08"),)
    GENESIS_HASH = 'a60ac43c88dbc44b826cf315352a8a7b373d2af8b6e1c4c4a0638859c5e9ecd1'
    TX_COUNT = 4661197
    TX_COUNT_HEIGHT = 2114846
    TX_PER_BLOCK = 10
    VALUE_PER_COIN = 1000000
    RPC_PORT = 19119

    @classmethod
    def header_hash(cls, header):
        # Requires OpenSSL 1.1.0+
        from hashlib import scrypt
        return scrypt(header, salt=header, n=1024, r=1, p=1, dklen=32)


class Bellcoin(Coin):
    NAME = "Bellcoin"
    SHORTNAME = "BELL"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = (bytes.fromhex("55"),)
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('000008f3b6bd10c2d03b06674a006b8d'
                    '9731f6cb58179ef1eee008cee2209603')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 264129
    TX_COUNT_HEIGHT = 219574
    TX_PER_BLOCK = 5
    RPC_PORT = 25252
    REORG_LIMIT = 1000
    PEERS = [
        'bell.electrumx.japanesecoin-pool.work s t',
        'bell.streetcrypto7.com s t',
    ]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import bell_yespower
        return bell_yespower.getPoWHash(header)


class CPUchain(Coin):
    NAME = "CPUchain"
    SHORTNAME = "CPU"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1C")
    P2SH_VERBYTES = (bytes.fromhex("1E"),)
    GENESIS_HASH = ('000024d8766043ea0e1c9ad42e7ea4b5'
                    'fdb459887bd80b8f9756f3d87e128f12')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 4471
    TX_COUNT_HEIGHT = 3491
    TX_PER_BLOCK = 2
    RPC_PORT = 19707
    REORG_LIMIT = 1000
    PEERS = [
        'electrumx.cpuchain.org s t',
    ]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import cpupower
        return cpupower.getPoWHash(header)


class Xaya(NameIndexMixin, AuxPowMixin, Coin):
    NAME = "Xaya"
    SHORTNAME = "CHI"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("1c")
    P2SH_VERBYTES = (bytes.fromhex("1e"),)
    WIF_BYTE = bytes.fromhex("82")
    GENESIS_HASH = ('e5062d76e5f50c42f493826ac9920b63'
                    'a8def2626fd70a5cec707ec47a4c4651')
    TX_COUNT = 1147749
    TX_COUNT_HEIGHT = 1030000
    TX_PER_BLOCK = 2
    DESERIALIZER = lib_tx.DeserializerXaya
    TRUNCATED_HEADER_SIZE = 80 + 5
    RPC_PORT = 8396
    PEERS = [
        'seeder.xaya.io s50002',
        'xaya.domob.eu s50002',
    ]

    # Op-codes for name operations
    OP_NAME_REGISTER = OpCodes.OP_1
    OP_NAME_UPDATE = OpCodes.OP_2

    # Valid name prefixes.
    NAME_REGISTER_OPS = [OP_NAME_REGISTER, "name", -1, OpCodes.OP_2DROP,
                         OpCodes.OP_DROP]
    NAME_UPDATE_OPS = [OP_NAME_UPDATE, "name", -1, OpCodes.OP_2DROP,
                       OpCodes.OP_DROP]
    NAME_OPERATIONS = (
        NAME_REGISTER_OPS,
        NAME_UPDATE_OPS,
    )

    @classmethod
    def genesis_block(cls, block):
        super().genesis_block(block)

        # In Xaya, the genesis block's coinbase is spendable.  Thus unlike
        # the generic genesis_block() method, we return the full block here.
        return block


class XayaTestnet(Xaya):
    SHORTNAME = "XCH"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("58")
    P2SH_VERBYTES = (bytes.fromhex("5a"),)
    WIF_BYTE = bytes.fromhex("e6")
    GENESIS_HASH = ('5195fc01d0e23d70d1f929f21ec55f47'
                    'e1c6ea1e66fae98ee44cbbc994509bba')
    TX_COUNT = 51557
    TX_COUNT_HEIGHT = 49000
    TX_PER_BLOCK = 1
    RPC_PORT = 18396
    PEERS = []


class XayaRegtest(XayaTestnet):
    NET = "regtest"
    GENESIS_HASH = ('6f750b36d22f1dc3d0a6e483af453010'
                    '22646dfc3b3ba2187865f5a7d6d83ab1')
    RPC_PORT = 18493

# Source: https://github.com/GZR0/GRZ0


class GravityZeroCoin(ScryptMixin, Coin):
    NAME = "GravityZeroCoin"
    SHORTNAME = "GZRO"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("26")
    WIF_BYTE = bytes.fromhex("26")
    GENESIS_HASH = '0000028bfbf9ccaed8f28b3ca6b3ffe6b65e29490ab0e4430679bf41cc7c164f'
    DAEMON = daemon.FakeEstimateLegacyRPCDaemon
    TX_COUNT = 100
    TX_COUNT_HEIGHT = 747635
    TX_PER_BLOCK = 2
    RPC_PORT = 36442
    ESTIMATE_FEE = 0.01
    RELAY_FEE = 0.01


class Simplicity(Coin):
    NAME = "Simplicity"
    SHORTNAME = "SPL"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0444d5bc")
    XPRV_VERBYTES = bytes.fromhex("0444f0a3")
    P2PKH_VERBYTE = bytes.fromhex("12")
    P2SH_VERBYTE = bytes.fromhex("3b")
    WIF_BYTE = bytes.fromhex("5d")
    GENESIS_HASH = 'f4bbfc518aa3622dbeb8d2818a606b82c2b8b1ac2f28553ebdb6fc04d7abaccf'
    RPC_PORT = 11958
    TX_COUNT = 1726548
    TX_COUNT_HEIGHT = 1040000
    TX_PER_BLOCK = 5
    REORG_LIMIT = 100
    DESERIALIZER = lib_tx.DeserializerSimplicity

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        version, = util.unpack_le_uint32_from(header)

        if version < 2:
            import quark_hash
            return quark_hash.getPoWHash(header)
        else:
            return double_sha256(header)


class ElectraProtocol(Coin):
    NAME = 'ElectraProtocol'
    SHORTNAME = 'XEP'
    NET = 'mainnet'
    XPUB_VERBYTES = bytes.fromhex('0488b21e')
    XPRV_VERBYTES = bytes.fromhex('0488ade4')
    P2PKH_VERBYTE = bytes.fromhex('37')
    P2SH_VERBYTE = bytes.fromhex('89')
    WIF_BYTE = bytes.fromhex('a2')
    GENESIS_HASH = '000000954c02f260a6db02c712557adcb5a7a8a0a9acfd3d3c2b3a427376c56f'
    RPC_PORT = 16816
    TX_COUNT = 264299
    TX_COUNT_HEIGHT = 130000
    TX_PER_BLOCK = 5
    REORG_LIMIT = 1080
    DESERIALIZER = lib_tx.DeserializerSegWit
    PEERS = [
        'electrumx1.electraprotocol.eu s t',
        'electrumx2.electraprotocol.eu s t',
        'electrumx3.electraprotocol.eu s t',
        'electrumx4.electraprotocol.eu s t',
        'electrumx5.electraprotocol.eu s t',
    ]

    @classmethod
    def genesis_block(cls, block):
        super().genesis_block(block)

        # XEP has spendable genesis outputs, so we return the full block here.
        return block


class Myce(Coin):
    NAME = "Myce"
    SHORTNAME = "YCE"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("32")
    P2SH_VERBYTE = bytes.fromhex("55")
    WIF_BYTE = bytes.fromhex("99")
    GENESIS_HASH = '0000c74cc66c72cb1a327c5c1d4893ae5276aa50be49fb23cec21df1a2f20d87'
    RPC_PORT = 23512
    TX_COUNT = 1568977
    TX_COUNT_HEIGHT = 774450
    TX_PER_BLOCK = 3
    REORG_LIMIT = 100
    DESERIALIZER = lib_tx.DeserializerSimplicity

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        version, = util.unpack_le_uint32_from(header)

        if version < 7:
            # Requires OpenSSL 1.1.0+
            from hashlib import scrypt
            return scrypt(header, salt=header, n=1024, r=1, p=1, dklen=32)
        else:
            return double_sha256(header)


class Navcoin(Coin):
    NAME = "Navcoin"
    SHORTNAME = "NAV"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("35")
    P2SH_VERBYTES = (bytes.fromhex("55"),)
    WIF_BYTE = bytes.fromhex("96")
    GENESIS_HASH = ('00006a4e3e18c71c6d48ad6c261e2254'
                    'fa764cf29607a4357c99b712dfbb8e6a')
    DESERIALIZER = lib_tx.DeserializerTxTimeSegWitNavCoin
    TX_COUNT = 137641
    TX_COUNT_HEIGHT = 3649662
    TX_PER_BLOCK = 2
    RPC_PORT = 44444
    REORG_LIMIT = 1000

    @classmethod
    def header_hash(cls, header):
        if int.from_bytes(header[:4], "little") > 6:
            return double_sha256(header)
        else:
            import x13_hash
            return x13_hash.getPoWHash(header)


class Primecoin(PrimeChainPowMixin, Coin):
    NAME = "Primecoin"
    SHORTNAME = "XPM"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("17")
    P2SH_VERBYTES = (bytes.fromhex("53"),)
    WIF_BYTE = bytes.fromhex("97")
    GENESIS_HASH = ('963d17ba4dc753138078a2f56afb3af9'
                    '674e2546822badff26837db9a0152106')
    DAEMON = daemon.FakeEstimateFeeDaemon
    ESTIMATE_FEE = 1.
    TX_COUNT = 7138730
    TX_COUNT_HEIGHT = 3639500
    TX_PER_BLOCK = 2
    RPC_PORT = 9912
    REORG_LIMIT = 5000
    PEERS = [
        'electrumx.primecoin.org s t',
    ]


class PrimecoinTestnet(Primecoin):
    NAME = "PrimecoinTestnet"
    SHORTNAME = "tXPM"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = (bytes.fromhex("c4"),)
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('221156cf301bc3585e72de34fe1efdb6'
                    'fbd703bc27cfc468faa1cdd889d0efa0')
    RPC_PORT = 9914
    PEERS = [
        'electrumx.testnet.primecoin.org t',
    ]


class Unobtanium(AuxPowMixin, Coin):
    NAME = "Unobtanium"
    SHORTNAME = "UNO"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("82")
    P2SH_VERBYTES = (bytes.fromhex("1e"),)
    WIF_BYTE = bytes.fromhex("e0")
    GENESIS_HASH = ('000004c2fc5fffb810dccc197d603690'
                    '099a68305232e552d96ccbe8e2c52b75')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 65535
    REORG_LIMIT = 5000


class Linx(Coin):
    NAME = "Linx"
    SHORTNAME = "LINX"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("4b")
    P2SH_VERBYTES = (bytes.fromhex("05"),)
    WIF_BYTE = bytes.fromhex("cb")
    GENESIS_HASH = ('3bafea350a70f75e7a1cd279999faed7'
                    '1a51852aae88fed3c38553cecc810a92')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9381
    REORG_LIMIT = 5000


class Flashcoin(Coin):
    NAME = "Flashcoin"
    SHORTNAME = "FLASH"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("44")
    P2SH_VERBYTES = (bytes.fromhex("82"),)
    WIF_BYTE = bytes.fromhex("c4")
    GENESIS_HASH = ('aa0cf4f5ce0a3c550ce5674c1e808c41'
                    '7cf5077b4e95bda1d6fbaeaf4258972b')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9385
    REORG_LIMIT = 5000


class Defcoin(Coin):
    NAME = "Defcoin"
    SHORTNAME = "DEFC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1e")
    P2SH_VERBYTES = bytes.fromhex("05")
    WIF_BYTE = bytes.fromhex("9e")
    GENESIS_HASH = ('192047379f33ffd2bbbab3d53b9c4b9e'
                    '9b72e48f888eadb3dcf57de95a6038ad')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9386
    REORG_LIMIT = 5000
    DESERIALIZER = lib_tx.DeserializerAuxPowSegWit


class Auroracoin(Coin):
    NAME = "Auroracoin"
    SHORTNAME = "AUR"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("17")
    P2SH_VERBYTES = bytes.fromhex("05")
    WIF_BYTE = bytes.fromhex("b0")
    GENESIS_HASH = ('2a8e100939494904af825b488596ddd5'
                    '36b3a96226ad02e0f7ab7ae472b27a8e')
    TX_COUNT = 2800000
    TX_COUNT_HEIGHT = 2778987
    TX_PER_BLOCK = 1
    RPC_PORT = 12341
    REORG_LIMIT = 5000


class Smileycoin(Coin):
    NAME = "Smileycoin"
    SHORTNAME = "SMLY"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = bytes.fromhex("05")
    WIF_BYTE = bytes.fromhex("b0")
    GENESIS_HASH = ('660f734cf6c6d16111bde201bbd21228'
                    '73f2f2c078b969779b9d4c99732354fd')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9388
    REORG_LIMIT = 5000


class Iop(Coin):
    NAME = "Iop"
    SHORTNAME = "IOP"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("75")
    P2SH_VERBYTES = (bytes.fromhex("AE"),)
    WIF_BYTE = bytes.fromhex("31")
    GENESIS_HASH = ('00000000bf5f2ee556cb9be8be64e077'
                    '6af14933438dbb1af72c41bfb6c82db3')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 8337
    REORG_LIMIT = 5000


class Egulden(Coin):
    NAME = "Egulden"
    SHORTNAME = "EFL"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("30")
    P2SH_VERBYTES = (bytes.fromhex("05"),)
    WIF_BYTE = bytes.fromhex("b0")
    GENESIS_HASH = ('6d39f28ad01a7edd3e2374b355cf8c7f'
                    '8dbc1c5e4596ad3642fa6d10c2599217')
    TX_COUNT = 13336629
    TX_COUNT_HEIGHT = 1268206
    TX_PER_BLOCK = 10
    RPC_PORT = 9402
    REORG_LIMIT = 5000


class Ixcoin(AuxPowMixin, Coin):
    NAME = "ixcoin"
    SHORTNAME = "IXC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("8a")
    P2SH_VERBYTES = (bytes.fromhex("05"),)
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('0000000001534ef8893b025b9c1da672'
                    '50285e35c9f76cae36a4904fdf72c591')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9406
    REORG_LIMIT = 5000


class Batacoin(Coin):
    NAME = "bata"
    SHORTNAME = "BTA"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = (bytes.fromhex("05"),)
    WIF_BYTE = bytes.fromhex("99")
    GENESIS_HASH = ('b4bee36fd54a6176fd832f462641415c'
                    '142d50e4b378f71c041870c2b1186bc8')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9412
    REORG_LIMIT = 5000


class Digitalcoin(Coin):
    NAME = "digitalcoin"
    SHORTNAME = "DGC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1e")
    P2SH_VERBYTES = (bytes.fromhex("05"),)
    WIF_BYTE = bytes.fromhex("9e")
    GENESIS_HASH = ('5e039e1ca1dbf128973bf6cff98169e4'
                    '0a1b194c3b91463ab74956f413b2f9c8')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9413
    REORG_LIMIT = 5000


class Cannacoin(Coin):
    NAME = "cannacoin"
    SHORTNAME = "CCN"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1C")
    P2SH_VERBYTES = (bytes.fromhex("05"),)
    WIF_BYTE = bytes.fromhex("bd")
    GENESIS_HASH = ('f1b4cdf03c86099a0758f1c018d1a10b'
                    'f05afab436c92b93b42bb88970de9821')
    DESERIALIZER = lib_tx.DeserializerReddcoin
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 1234
    REORG_LIMIT = 5000


class Europecoin(Coin):
    NAME = "europecoin"
    SHORTNAME = "ERC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("21")
    P2SH_VERBYTES = (bytes.fromhex("05"),)
    WIF_BYTE = bytes.fromhex("a8")
    GENESIS_HASH = ('000d0da26987ead011c5d568e627f7e3'
                    'd4a4f83a0b280b1134d8e7e366377f9a')
    BASIC_HEADER_SIZE = 88
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9412
    REORG_LIMIT = 5000


class Adcoin(Coin):
    NAME = "Adcoin"
    SHORTNAME = "ACC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1e")
    P2SH_VERBYTES = (bytes.fromhex("0d"),)
    WIF_BYTE = bytes.fromhex("97")
    GENESIS_HASH = ('000000fc5276647fd959f718c9526f87'
                    'f4858c4ef62f2e29d3772e4e37040a25')

    BASIC_HEADER_SIZE = 112
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9416
    REORG_LIMIT = 5000


class Lynx(Coin):
    NAME = "Lynx"
    SHORTNAME = "LYNX"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("2d")
    P2SH_VERBYTES = (bytes.fromhex("16"),)
    WIF_BYTE = bytes.fromhex("ad")
    GENESIS_HASH = ('984b30fc9bb5e5ff424ad7f4ec193053'
                    '8a7b14a2d93e58ad7976c23154ea4a76')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9139
    REORG_LIMIT = 5000


class LitecoinCash(Coin):
    NAME = "LitecoinCash"
    SHORTNAME = "LCC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1c")
    P2SH_VERBYTES = (bytes.fromhex("32"), bytes.fromhex("05"))
    WIF_BYTE = bytes.fromhex("b0")
    GENESIS_HASH = ('12a765e31ffd4059bada1e25190f6e98'
                    'c99d9714d334efa41a195a7e7e04bfe2')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9140
    REORG_LIMIT = 5000


class BitcoinPrivate(EquihashMixin, Coin):
    NAME = "BitcoinPrivate"
    SHORTNAME = "BTCP"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1325")
    P2SH_VERBYTES = (bytes.fromhex("13AF"),)
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('0007104ccda289427919efc39dc9e4d4'
                    '99804b7bebc22df55f8b834301260602')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 329196
    TX_COUNT_HEIGHT = 68379
    TX_PER_BLOCK = 5
    RPC_PORT = 9335
    REORG_LIMIT = 5000


class Aryacoin(Coin):
    NAME = "aryacoin"
    SHORTNAME = "AYA"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("019d9cfe")
    XPRV_VERBYTES = bytes.fromhex("019da462")
    P2PKH_VERBYTE = bytes.fromhex("17")
    P2SH_VERBYTES = (bytes.fromhex("6f"),)
    WIF_BYTE = bytes.fromhex("b0")
    GENESIS_HASH = ('b553727635006d7faade229d152482df'
                    'b9da7822d41cf0cad9ffa82a54f67803')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 10
    RPC_PORT = 9151
    REORG_LIMIT = 800


class Donu(Coin):
    NAME = "donu"
    SHORTNAME = "DONU"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("35")
    P2SH_VERBYTES = (bytes.fromhex("05"),)
    WIF_BYTE = bytes.fromhex("b1")
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    GENESIS_HASH = ('5f7f26e24291f5be2351e1dcdab18bf9'
                    '4cee718940e6b9f2fbb46227434c3f12')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 10
    RPC_PORT = 26381
    REORG_LIMIT = 800


class Quebecoin(AuxPowMixin, Coin):
    NAME = "Quebecoin"
    SHORTNAME = "QBC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("3a")
    P2SH_VERBYTES = (bytes.fromhex("05"),)
    WIF_BYTE = bytes.fromhex("ba")
    GENESIS_HASH = ('000008c2d57759af6462352ee9f4923d'
                    '97401cb599a9318e6595a2a74c26ea74')
    DESERIALIZER = lib_tx.DeserializerAuxPowSegWit
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 20
    REORG_LIMIT = 2000
    RPC_PORT = 10890


class Beyondcoin(Coin):
    NAME = "Beyondcoin"
    SHORTNAME = "BYND"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("ff88b21e")
    XPRV_VERBYTES = bytes.fromhex("ff88ade4")
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = [bytes.fromhex("1a"), bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("b0")
    GENESIS_HASH = ('0a9e3b5fce3aee6e04f06dfd6ad380a6'
                    'c0f9d8420f53a4ca97845756ee5d56e7')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 287000
    TX_COUNT_HEIGHT = 133700
    TX_PER_BLOCK = 2
    RPC_PORT = 10332
    REORG_LIMIT = 5000


class Syscoin(AuxPowMixin, Coin):
    NAME = "Syscoin"
    SHORTNAME = "SYS"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("3f")
    P2SH_VERBYTES = (bytes.fromhex("05"),)
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('0000022642db0346b6e01c2a397471f4'
                    'f12e65d4f4251ec96c1f85367a61a7ab')
    DESERIALIZER = lib_tx.DeserializerAuxPowSegWit
    TX_COUNT = 911232
    TX_COUNT_HEIGHT = 954572
    TX_PER_BLOCK = 1
    RPC_PORT = 8370
    REORG_LIMIT = 2000
    CHUNK_SIZE = 360


'''


def ocv_new_hash_block(block_data):


    #24*24 24bit bmp
    init_image_bytes = bytearray(b'\x42\x4D\xF6\x06\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00\x18\x00\x00\x00\x18\x00\x00\x00\x01\x00\x18\x00\x00\x00\x00\x00\xC0\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')


    start_hash = block_data[0:76]

    i = 0
    while i < 27:
        start_hash = hashlib.sha512(start_hash).digest()
        init_image_bytes = init_image_bytes + start_hash
        i += 1
        
   


    nonce_bytes = block_data[76:80]




    i = 54 #first 54byte bmp header
    j = 0
    while i < 1782:        
        init_image_bytes[i] = init_image_bytes[i] ^ nonce_bytes[j]
        j += 1
        i += 1        
        if j == 4:
            j = 0


    nparr = np.asarray(init_image_bytes, dtype="uint8")
    img_src = cv2.imdecode(nparr, cv2.IMREAD_COLOR)



    img_src = cv2.bilateralFilter(img_src, 15, 75, 75)

    kernel = np.array(
                  [
                    [0.0, -1.0, 0.0], 
                    [-1.0, 5.0, -1.0],
                    [0.0, -1.0, 0.0]
                  ]
                  )

    kernel = kernel/(np.sum(kernel) if np.sum(kernel)!=0 else 1)
    
    img_src = cv2.filter2D(img_src,-1,kernel)

    img_src = cv2.blur(img_src, (5, 5))

    img_src = cv2.GaussianBlur(img_src, (5, 5),cv2.BORDER_DEFAULT)

    img_src = cv2.medianBlur(img_src, 5)



    is_success, im_buf_arr = cv2.imencode(".bmp", img_src)
    byte_im = im_buf_arr.tobytes()


    return hashlib.sha256(byte_im+block_data).digest()


def ocv_hash_block(block_data):


    #32*32 24bit randomized bmp
    init_image_bytes = bytearray(b'\x42\x4d\x36\x0c\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00\x20\x00\x00\x00\x20\x00\x00\x00\x01\x00\x18\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x37\xec\x6a\xf6\x1a\xd3\x9f\xa5\xc4\x0b\x0c\x36\x65\xff\x6e\x2c\x2e\x54\xd0\x7d\xa8\xae\xa1\x1a\xbd\x61\x75\x0a\x6f\x02\xfd\x4e\x3b\x2f\x6d\xf5\x28\x8c\x62\x44\x5c\x01\x70\x69\xce\xc2\xb8\x7b\x19\xcb\x31\xba\x1e\x85\xbc\x91\xfd\xab\xf9\x46\x73\x55\x2b\x53\x09\xfd\x79\x7f\x00\xd0\x21\x20\x31\x9a\xff\x4f\x8b\x93\x45\x27\xe1\xd0\x92\x29\x41\x7c\x1b\xd9\xe0\xe4\x0c\xc4\x75\xb5\x45\xdc\x22\x4d\x38\xef\xf3\x24\x6c\xa3\x5a\x8f\x82\xa6\x2e\x1a\x44\xe3\x76\xa4\xd3\x9d\xd3\x95\x11\x36\x7e\x9f\xb4\x09\x08\x1a\xe8\x43\x8a\x50\xbf\x5f\xa7\x48\xb0\x88\xed\xcb\x4e\xb6\x3d\x24\xf0\x07\xc0\xb7\x75\x84\x87\x8c\xe5\x9d\x82\x06\x3d\x78\x07\xa7\x65\x37\x62\x98\xb0\xb2\x6a\x24\xcf\x43\x75\x3f\xd4\xaa\xf4\x48\xf9\xe9\x71\x16\x81\xd2\x4a\xe9\x39\x90\xbe\x63\x3b\xb7\x23\x5d\x82\x5d\x1d\x44\x6a\xd0\x3d\xbd\x05\xb0\x37\x63\x9d\x42\x4a\xcf\x1c\xf2\x17\x31\xec\x21\xc8\x44\xcb\x1a\x6b\xd4\x9f\xa9\xfc\x16\x26\xce\x48\xd5\xbd\xe4\xaa\xef\x82\xf4\xea\x3b\xd1\x22\xa5\xa2\xc9\x95\x51\x3f\x24\xea\xc0\xfb\x13\x68\x77\x36\x16\x88\x96\xe0\x21\xe9\x85\x14\x96\x2c\x8c\x86\xa2\x12\xea\xea\xde\xa0\x97\x24\x32\xe5\xf8\x98\xd1\x9e\x1d\x1e\xe2\xff\x1d\xee\x52\x2d\x46\x04\x6b\x69\x56\x09\xe9\xcd\xb8\xa2\x43\x88\x09\xa3\x38\xc0\xbc\x41\x19\x52\x04\x3b\xe9\x7d\xe4\x9a\x55\xe7\x66\x51\xbb\x4e\x5e\xbc\x3f\x67\xfe\xa2\xb9\xda\xaf\x46\xa9\xc7\xdd\x9b\xc6\xa2\x14\xc8\xe7\x3a\x47\x99\x5a\x28\x4d\x58\x09\x30\xb3\x0d\xe7\x19\xa8\x33\x44\xef\x60\x1a\x3c\xb5\x27\x54\x56\xda\x3d\xec\x58\xfb\x68\x4e\xb4\x10\xde\x32\x66\x1a\x55\x65\x2b\xa9\xd7\x76\xa9\xf9\x9f\xd4\x7e\x85\xc9\xdb\x5d\xe6\x4f\xa9\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xf9\xba\xf0\x67\x0f\xc2\x40\x80\x47\xff\xff\xff\x44\xe8\x44\xc3\xff\x23\x0e\x90\x68\xee\xa5\x66\x4f\x36\x0d\xe1\x8e\xe9\x6c\xd0\xfc\x10\x50\xca\xdf\x30\xa3\x5f\x35\xbf\x16\xbc\xc0\xf1\x9d\x6b\xc9\xf7\x39\x30\x52\x39\xd3\xbe\xd3\x79\x59\x47\x99\xa3\x8d\x01\xb3\x68\x87\x2d\x98\x6c\x09\x64\x93\xac\xe1\x8a\x1a\xc1\x06\x8b\xcd\xb1\x8f\x64\x6a\x6f\x4b\x6d\x50\x54\x54\x49\xc1\x16\x08\x67\x42\x9f\x9b\x31\x0c\xef\x58\xb2\x88\x3a\x86\x4e\x24\x66\x42\x4e\x6f\x10\x04\x2a\xb8\xf3\x3f\xef\xd0\xe7\x84\x80\x1e\x02\x95\x0c\x6e\xd0\x69\x59\xbd\x36\xc5\x2c\x1a\xc2\x31\xbe\xad\xa7\xb1\x8b\x51\xfc\x82\x7e\x77\x44\x6a\x88\x7f\xe0\x05\x5e\x59\x2f\x3a\x95\x63\x80\xd0\x3a\x51\x5b\xad\x7a\xab\x65\x92\xcb\xcc\x8f\xca\x0e\x94\x6c\x4b\xa9\xae\x59\x40\xe3\x45\x7c\x1c\xeb\x9e\x2a\xe5\x85\x3d\xcf\xd7\x0a\x15\x2e\x97\xc9\xac\x18\xda\x3d\x34\x9d\xc8\x37\xde\xbf\x64\xc1\x2c\xba\xf0\x96\xd0\x0f\x87\xb7\xa7\x24\xe8\x60\xae\xa5\xb7\x44\xd3\x35\x99\x2a\xb6\x22\x3e\xd6\x2d\x05\xcc\xc2\xdd\x5d\x18\xc8\x45\xa2\x01\x83\x59\x3c\xf0\xcb\xbb\xf2\xf9\x19\x79\xb5\xd4\x06\xf6\x9f\x13\xfa\x2f\x35\x17\x2b\x51\x3a\xb6\x25\xa3\x06\x22\x01\xff\x2b\xde\x14\xcd\xca\x32\x16\xbc\xa4\x36\x71\xdf\x2f\xe0\x75\x10\x24\x1f\x03\x3a\x66\x78\xd1\x16\x81\xb5\xe2\xe1\x5d\x0e\x30\x05\x49\xd9\xdb\xcc\xde\xd7\x83\xe1\xb1\x48\xaf\x7d\x4a\x11\xbc\xb5\x9f\x71\x26\x8d\x47\x9d\x2c\xe7\x1b\x05\x0f\x5e\x3d\x17\x0f\x78\x2e\xd6\x03\x8e\x47\x62\x7e\x10\x56\xf2\xad\x95\x42\x6a\x9a\xab\xae\xc8\x71\x7f\xc0\xde\x94\xbf\x17\x0a\x27\xb3\x2b\x85\x11\x15\x47\x6b\xd5\xf8\x67\x38\xdf\xd6\xff\xff\xff\x6f\xd2\x0c\x1d\x3d\x2c\xde\xf2\xe7\xff\xff\xff\x44\xc2\x9d\xd3\x42\xe2\x3f\x27\x3e\xd8\x39\xbb\xa9\xcc\x86\x64\x7b\xc2\x36\x90\xcb\x43\x38\x2e\x2b\x7d\xd6\xc4\xab\x0d\x65\xdf\x16\x25\x53\x86\x67\x30\x2e\x9f\xe9\x4a\x17\xf8\xaf\x49\xc2\x3e\xb2\xa4\x6d\xf2\x01\xfb\x28\x3c\xf8\xf2\x3a\x22\xd9\x42\x85\xbc\x0b\xd6\x93\x04\x99\xd1\x6f\x98\x3a\x57\x96\x2e\x65\x3b\xc1\x25\x9d\x95\xa2\x9a\x9e\x89\x84\xa8\xf6\x32\x19\xa2\x80\xd0\x88\x47\xbb\xdb\x2c\x52\x4d\x75\x6b\x20\x65\x48\x37\x53\x9a\xe8\xfd\x03\xe0\x3c\x22\xac\x8c\xfe\x29\xa0\xd9\xda\x6d\xee\xbe\x45\x32\x42\xf6\x91\x0f\xdc\x54\x5e\xdd\x83\x93\x67\xdd\x2d\x44\xb2\x91\x3e\xdb\xcd\xeb\xd4\x5a\xb2\x81\xa7\x80\x53\xdd\xcf\x44\x46\x29\x18\x3c\x62\x5a\x30\x7b\x3f\xfa\x59\x15\x4d\xbc\x44\x46\x41\xa7\x28\xa5\xed\xc2\xa1\x55\xa6\xe9\x39\xc5\x2a\x79\x8f\xba\xa5\x21\x55\x6c\x53\x1b\x2e\x5d\x9b\x21\x2a\x96\xab\xa0\xf6\x64\x45\xfb\xcc\x46\xb6\x9a\xdc\x6e\xe3\x04\x46\x11\x80\xde\xde\xc3\x6a\xc8\xf1\xc0\x3b\x6a\x1f\xf9\x2b\xbb\xf6\x54\x04\xac\x59\x45\x1b\x32\x80\xdf\xbc\x32\x53\x00\xfb\x3a\x7a\x0c\xd2\xbc\xd1\x88\xe7\x72\x49\x62\x50\xa2\x67\x4d\xaa\xa9\x7b\xe7\xbc\xc6\xea\x70\xe8\x43\xa2\x7f\xdf\x22\x98\xce\x82\x7d\x09\x55\x58\x1e\x7c\xa7\x39\xee\xa3\xa8\x7d\x19\xec\x84\x7f\xbf\x84\xf1\x85\x83\x13\xb2\x6f\x70\x8d\xda\x25\xbf\x3b\xe5\xf7\x89\x03\x07\xcc\x06\x98\x0e\xeb\x3b\x1c\x84\xfe\x4d\x7b\xbb\x5d\x8e\x11\x1e\x05\x9c\x0a\xc0\x21\xd2\x6c\x58\x11\x0a\xb2\x44\xd7\x5c\xff\x06\x3c\x14\x7d\xa1\x9f\xee\x9a\x45\x04\xac\x9b\x40\x82\xb6\x1f\x57\xe3\x80\x64\xe2\x8f\x81\x8e\xee\xff\xff\xff\x2e\xe9\x2b\xe9\x0c\x65\x47\xf8\x6a\xff\xff\xff\x43\x64\x27\xfb\xf7\xe9\x8e\x7e\x9d\x8f\xed\x2c\xef\xb3\x0a\x83\x6c\x07\x17\x64\x7c\x7a\xd0\x93\xa8\x74\xb6\x13\x89\x3e\x74\xe3\xdc\xc8\xdb\x15\xf5\xf2\x7c\xdf\xc8\x36\xc8\x6f\x6a\xba\x65\x21\x0d\xad\xae\x62\xda\xc4\x67\x79\x8c\x54\x9f\x66\x8c\x84\xc3\xc7\x29\x0e\x13\x53\xc5\x89\x94\x25\x12\x6c\xac\x3c\x48\x90\x49\xb0\x43\xec\x42\xdd\x0b\x7b\xa6\x23\xdb\x00\x4e\xfc\x4e\x62\x85\x7e\x7a\xa7\x86\x25\x24\x3d\x8a\x2d\x4a\x01\x50\xeb\xb5\x84\x8d\x2f\x64\xe4\xe8\xcd\x66\x00\xa3\x67\x94\x9e\xcf\x27\x97\x4d\x83\x3f\x9b\xba\x3b\x84\x86\x45\xfe\x12\x0e\x14\x25\x46\x6e\x7a\x3c\x5a\x5e\x53\x2a\xd3\x4a\x9c\xf5\x67\xef\x7f\xdc\x54\x41\x30\x08\xf5\x66\xf1\x03\xcc\x75\xfc\x47\x2d\x1f\xfc\x42\xf9\x4f\x27\xd1\x1d\x0e\xb5\x99\x0f\x82\x08\xc6\xe9\x35\x9c\xce\xca\xc1\x65\xe6\xdb\x28\xdf\xcc\xbf\x49\x57\xa3\x10\x1f\x23\xa6\xce\xd5\x00\x51\xbe\xf1\x94\x69\xbc\xe7\xef\x34\xc7\x0e\xb2\x9b\x51\xec\x00\xf0\xb4\xa3\x7b\xdc\xac\x07\x9e\x7a\xc3\xa9\x0a\xd3\xfc\x51\xac\xb4\x03\x93\x72\x46\xdd\xd9\x02\x36\x4a\xbd\x8b\x79\x0a\xdc\x01\x4d\xa1\x83\x68\x57\x31\x21\x46\x10\x39\xe3\x39\x42\x5b\x77\xcd\x24\x69\x9c\x03\x22\xba\xf2\xeb\xb9\x1a\x04\x74\x4b\x64\x0b\x71\x8f\xe9\x96\x14\x11\x6e\xd7\xc0\x5b\x30\xb1\xc9\x78\xd1\x85\xd7\x51\xd3\xce\x54\x53\xab\xd2\x6d\xf6\xd2\x12\xed\xf0\x0c\x5a\x9a\xa1\x62\x3e\x75\xd6\x78\xbd\x5d\xbc\xa8\xa4\x21\x1c\xae\x6e\xdf\x41\x4e\x4e\xae\x24\x6b\xef\x9f\x64\xbc\x45\xf8\x92\xf0\xe0\x09\x7f\x41\x70\x59\x1f\x47\x8e\x00\xba\xcb\x4a\x98\xf2\xe9\x8f\xe2\x16\x64\x09\xff\xff\xff\x1d\xce\x98\x56\x70\x00\xf3\x13\xdf\xff\xff\xff\x9a\xf0\x3c\x39\x3c\xf0\x7b\x8f\xfc\xb4\xfd\x8a\xe4\x2a\x0b\x81\x72\xb2\xd6\xcf\xdb\x94\x6f\x45\xd9\xa2\xaa\xfb\xf5\x44\xab\x81\xfa\xd2\x28\xd9\x9e\x41\xa3\xec\x1c\x4c\xaf\xdc\x4f\x44\x25\x7a\xae\x59\x1c\x7a\xab\x5e\xb3\xb7\x38\xb5\xd7\xf1\x93\xad\xa0\x21\x2a\x98\x69\x74\xb6\x21\x9d\x52\x69\xbf\x0d\xfa\x7e\x0f\x02\x68\x95\xfe\xb5\xdf\x63\x84\x80\x24\xd9\x59\x23\xb9\xc7\x04\x1e\x12\xe0\xda\xc1\x83\x5f\x62\x77\x9c\xb0\x54\x99\x87\x54\x89\x69\xd2\x48\x82\x54\x8b\x5f\x8f\x1c\xd9\xa5\x5e\x08\x9a\x03\xa3\x6d\x96\xb3\x9a\x2a\x96\xa0\xd5\x59\xbd\xa7\xa5\xe8\x17\xac\xcb\x30\x51\xd8\xcf\xf3\x3a\x57\x59\x8a\x7e\x8d\xc2\x22\x2f\x0d\xff\x24\x32\xae\xf2\xbe\xa8\x23\x92\xb3\x3d\x81\x95\x93\x98\xdc\xd1\x85\xb6\xea\xbf\x91\x27\xb2\xf0\x62\x0e\x26\xe0\xf7\x6b\x4d\xcb\xac\xa2\xd0\x8e\x23\x41\x1d\xd8\x2f\xb1\x9b\x03\x76\x3f\x88\xac\x56\xa2\x91\x8d\xfb\x2d\x53\xa1\x5e\x8a\xb8\x12\x77\x43\xc9\x4f\xb7\xbd\x2a\x10\xee\x58\xdd\xc4\xe4\x1e\xa3\x09\x8f\x20\x14\xb0\x40\xd3\x44\x52\x07\x4d\x69\xb6\x20\x8e\xcb\x60\x51\xfd\x92\x5b\x39\x18\xec\x50\xc0\x40\x2e\x19\x7b\xd7\x05\x06\x7f\x90\x34\x92\xdd\x0c\x98\xd0\x77\xca\x3b\x47\x1d\x64\x9c\x97\x2c\x40\x2b\x02\x99\x28\x9c\x46\x78\xe6\x24\xa7\x00\x0a\x07\x43\xde\x21\xac\xe5\xbd\x70\x67\xc3\x39\x6e\xff\xa7\xcf\x64\xdd\xd2\x6e\xb8\xa6\xbd\xe4\xd7\xb8\x24\x48\x89\xb9\xc4\x42\x66\xd4\xb8\xd4\xa3\xab\xf3\x67\x28\x1e\xc2\x48\x90\x1a\xfe\xa8\xa9\x9f\x1f\x17\xda\x61\x61\x55\x70\x3a\x11\x87\x41\x01\xee\x9a\xe9\x74\x17\x81\x76\x4b\xf0\x17\x8a\x65\xff\xff\xff\xa3\x3d\xf9\x31\x6d\x35\x5f\xc8\x8c\xff\xff\xff\x1e\xa6\x67\xda\x5f\x9a\xdd\x9c\xe1\x34\x32\x96\xc2\xb3\x49\x4a\xa3\x55\x84\x56\xfe\x91\x28\xbf\x55\x24\xb0\x8e\x88\x49\x41\x0c\x27\x43\x96\xe7\xd1\xb2\x15\xa8\x3f\x50\x60\xa5\x7e\x26\x32\xfb\x01\xe5\xb4\xcd\x33\x00\xdf\x5f\xc9\xd1\x32\x0a\x83\xb4\xab\x42\x01\xa5\x37\x43\x61\x9e\x80\x52\x1f\x76\xc2\x51\xcf\x20\x93\xcd\x00\x52\x16\xb1\x11\xad\xac\x15\xda\xab\x6f\xdd\x32\x30\x42\x3c\x2f\x9a\xd3\x8d\x65\x9a\xb5\x11\xda\x6e\x18\x49\x52\x17\x8b\xc0\x9a\x37\xbc\x7d\x0e\xd7\xfc\xb1\xe0\xa9\xd1\xed\xf0\x4c\x8c\xd9\x02\xd0\x94\x63\x5a\x24\xa7\xe0\x4c\x53\x95\xea\xfe\x87\x7e\x4e\x62\xc2\xdd\x72\x75\x7e\xad\xd8\x63\xf8\xe6\x1a\x57\x62\x92\xfb\xb1\x4a\x9e\xaf\x05\x0c\x0e\x9f\x75\x61\xeb\xa4\xd9\xc6\x4b\x05\x54\x7e\x9c\xda\x4e\x09\xbb\x82\x43\x1f\x0c\x0b\x19\x70\xfa\x98\xce\x5d\xd8\x12\xa7\xb4\x1c\x2b\xc1\x6f\xf2\xd2\xdb\x49\xf9\x7d\x97\xd4\xe7\xbc\x1b\x65\x01\xbc\x22\xed\xfe\xf9\x6c\xa2\x61\x50\x99\x54\x98\x4c\xe5\x27\x98\x9e\x75\x91\x6f\x3e\x4f\xf9\x7e\xfd\xe4\x28\x0a\x85\x99\xf9\xe6\xa6\x8b\x36\x11\xca\x74\x32\xba\x0e\x99\x4e\x0e\x53\xcd\xce\xaf\x05\x78\x23\xc4\x3c\xf6\x77\x08\xb8\x3b\xc2\x53\x51\x92\x5d\x8b\xb1\x27\x63\xa7\xc7\xe3\x81\x85\x7c\x29\xb0\xe8\xeb\x43\x43\xfe\xc8\xef\x5a\xdd\x73\xdf\xed\x3b\x5a\x5c\x2e\x00\x35\xbe\xa8\x2c\x2b\x19\x1f\x08\xb1\x94\xb1\xae\xdb\x27\x9a\xe4\x69\x88\xcd\xd9\xb1\xc6\x9e\x9e\xe4\xa3\x58\xe8\xd1\xc8\x74\xd3\xba\x58\x67\x69\x79\xf7\x19\x4a\x49\xb5\xd3\x71\x4f\xe1\x68\x1c\x7c\x8a\xb1\x05\x31\x19\x32\xd1\xc7\x71\xc0\xe2\x12\xe0\xff\xff\xff\x81\x08\x7c\xb7\xb6\xc6\x3a\x38\xc3\xff\xff\xff\xea\x85\x88\x62\x3c\xf0\x6c\x99\xbd\xb1\xe5\x0f\xc2\x4c\x7b\x16\x5a\xc5\xc3\x0f\xa5\xcb\x3d\x02\xff\xb1\x09\x38\x00\xf8\xab\x2f\xbd\x0d\x75\xf7\x9a\xeb\x20\x60\xe0\xbe\xe2\xe2\x5c\x15\xfc\x30\x81\x27\xd9\x99\x91\x47\xe3\x3c\x1a\x06\xcd\xa7\xc9\x06\x38\xe6\x5e\xcb\xaa\x71\xdb\x93\xaf\x23\xe1\x8a\xfe\x77\xc8\xd8\x2f\xfa\x6f\xfb\x32\x7c\x83\x15\x0d\xe9\x5b\xea\xc7\xfc\x6e\x23\x9e\x51\xc5\xa8\x4a\x94\x5e\xf4\xbb\x41\x92\xda\x08\x77\x75\x93\xa2\x25\x58\x3c\xa9\xb4\x1b\xff\xe1\x56\xf8\xe2\x2c\x5b\x62\xf3\xd3\xc2\x76\xcd\x80\x30\xdc\x60\xd0\xf7\xc5\x58\x41\x90\xe0\xb4\xc0\x67\x47\xdc\x70\xff\xff\xff\xff\xff\xff\xff\xff\xff\xbc\x43\x6e\xad\x6f\xc5\x8b\x1f\x53\x47\x2d\x4b\x32\x04\x93\xb2\x20\x78\xd7\xf9\x0c\x5b\x24\x69\x91\x73\xcd\x24\x99\x0d\x1a\x7d\x63\xd7\x06\x9b\x0e\x1c\xf3\xdd\x84\x5c\x66\xd6\x3f\x8f\x32\xf7\x50\x42\x37\x1b\x3f\x8d\xd1\xc4\x56\x9d\x97\xbc\xe7\x46\xb5\x9b\xc3\x05\x0a\xc4\xbd\xdd\xca\xfe\xcf\xbf\x67\x14\xbb\xb0\x1d\xbc\x33\xd4\x6b\x9c\xf1\xac\xac\x60\x48\x02\xf1\xd1\xf9\xd8\xdb\x97\xae\x02\x41\x2d\x1c\xc3\x6d\x1b\xce\xf1\x33\x40\xbe\x0d\x0c\x55\x94\x8b\x8a\x83\xae\xbd\x12\x00\x13\xe0\xe0\xb5\x60\xaf\x5f\x3d\xc2\x14\x21\xbe\xc9\x99\x68\xbf\x5d\xdb\x0d\x2f\x5c\x03\x7d\xfd\x66\xff\x1f\x80\xc8\xa8\x53\x05\x95\x9d\x5d\x88\x9e\x10\xe5\x58\x39\x19\xbf\x12\x49\xe3\x75\x0d\x9b\x92\xc6\xf9\xe5\x6f\x84\x65\x5a\x44\xe7\x32\x05\xe5\xd0\xa6\xd4\xa9\x48\xdf\xbc\x32\x3a\x7a\xb1\x99\x61\x33\x16\xa3\xdd\x94\x26\x56\x5c\x35\xc8\x5a\x18\x03\x75\xe8\xc9\x55\x81\xff\xff\xff\x9a\x16\x99')



 


    block_data_len = len(block_data)






    i = 54 #first 54byte bmp header

    

 
    j = 0
    while i < 3126 and j < block_data_len:
        init_image_bytes[i] = block_data[j]
        i += 1
        j += 1


    j = 0
    while i < 3126:
        if init_image_bytes[i] != 0xff:
            init_image_bytes[i] = init_image_bytes[i] ^ block_data[j]
            j += 1
        i += 1
        
        if j == block_data_len:
            j = 0

    
    nparr = np.asarray(init_image_bytes, dtype="uint8")


    img_src = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    algo_selector = (block_data[5] % 6) #from hashPrevBlock second byte
    #print(algo_selector)
    if algo_selector == 0:
        img_src = cv2.bilateralFilter(img_src, 15, 75, 75)
    elif algo_selector == 1:
        img_src = cv2.fastNlMeansDenoisingColored(img_src)

    elif algo_selector == 2:
        kernel = np.array(
                      [
                        [0.0, -1.0, 0.0], 
                        [-1.0, 5.0, -1.0],
                        [0.0, -1.0, 0.0]
                      ]
                      )

        kernel = kernel/(np.sum(kernel) if np.sum(kernel)!=0 else 1)
        img_src = cv2.filter2D(img_src,-1,kernel)

    elif algo_selector == 3:
        img_src = cv2.blur(img_src, (5, 5))


    elif algo_selector == 4:
        img_src = cv2.GaussianBlur(img_src, (5, 5),cv2.BORDER_DEFAULT)


    elif algo_selector == 5:
        img_src = cv2.medianBlur(img_src, 5)


    is_success, im_buf_arr = cv2.imencode(".bmp", img_src)
    byte_im = im_buf_arr.tobytes()


    return hashlib.sha256(byte_im+block_data).digest()
    
    
'''   






class Ocvcoin(BitcoinMixin, Coin):
    NAME = "Ocvcoin"
    SHORTNAME = "OCV"
    NET = "mainnet"

    P2PKH_VERBYTE = bytes.fromhex("73")
    P2SH_VERBYTES = (bytes.fromhex("6E"),)

    GENESIS_HASH = ('62eca3d9086ab1cac7f63e5c0a80a893'
                    'e8b1b65cca7b1b2bc2470a0f99d89689')

######


    DESERIALIZER = lib_tx.DeserializerSegWit
    MEMPOOL_HISTOGRAM_REFRESH_SECS = 120
    TX_COUNT = 2
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    CRASH_CLIENT_VER = (3, 2, 3)
    BLACKLIST_URL = 'https://ocvcoin.com/electrum-server-blacklist.json'
    PEERS = [
        'electrum.ocvcoin.com s t'
    ]

    @classmethod
    def warn_old_client_on_tx_broadcast(cls, client_ver):
        if client_ver < (3, 3, 3):
            return ('<br/><br/>'
                    'Your transaction was successfully broadcast.<br/><br/>'
                    'However, you are using a VULNERABLE version of Electrum.<br/>'
                    'Download the new version from the usual place:<br/>'
                    'https://electrum.org/'
                    '<br/><br/>')
        return False

######

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        
        '''
        new_algo_time = int.from_bytes(header[68:72], "little", signed=False)    
        if new_algo_time >= 1636416000:
            ret_data_hash = ocv_new_hash_block(header)[::-1]
        else:
            ret_data_hash = ocv_hash_block(header)
        '''
        
        block_header = bytes(header)
        output = ctypes.create_string_buffer(32)
        p1 = ctypes.c_char_p(block_header)
        libocv2.ocv2_hash(p1,output)
        
        #return ret_data_hash
        return output.raw
