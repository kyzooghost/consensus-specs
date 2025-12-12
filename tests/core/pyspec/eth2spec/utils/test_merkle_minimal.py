import pytest

from .hash_function import hash
from .merkle_minimal import get_merkle_root, merkleize_chunks, zerohashes


def h(a: bytes, b: bytes) -> bytes:
    return hash(a + b)


def e(v: int) -> bytes:
    # Use 32-byte little-endian encoding
    return v.to_bytes(length=32, byteorder="little")


def z(i: int) -> bytes:
    return zerohashes[i]


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string (with or without 0x prefix) to bytes."""
    hex_str = hex_str.removeprefix("0x")
    return bytes.fromhex(hex_str)


def mix_in_length(root: bytes, length: int) -> bytes:
    """
    mix_in_length: Given a Merkle root and a length (uint256 little-endian serialization),
    return hash(root, length).
    """
    length_bytes = length.to_bytes(length=32, byteorder="little")
    return hash(root + length_bytes)


# PENDING_PARTIAL_WITHDRAWALS_LIMIT = 2**27 = 134,217,728
PENDING_PARTIAL_WITHDRAWALS_LIMIT = 134217728


cases = [
    # limit 0: always zero hash
    (0, 0, z(0)),
    (1, 0, None),  # cut-off due to limit
    (2, 0, None),  # cut-off due to limit
    # limit 1: padded to 1 element if not already. Returned (like identity func)
    (0, 1, z(0)),
    (1, 1, e(0)),
    (2, 1, None),  # cut-off due to limit
    (1, 1, e(0)),
    (0, 2, h(z(0), z(0))),
    (1, 2, h(e(0), z(0))),
    (2, 2, h(e(0), e(1))),
    (3, 2, None),  # cut-off due to limit
    (16, 2, None),  # bigger cut-off due to limit
    (0, 4, h(h(z(0), z(0)), z(1))),
    (1, 4, h(h(e(0), z(0)), z(1))),
    (2, 4, h(h(e(0), e(1)), z(1))),
    (3, 4, h(h(e(0), e(1)), h(e(2), z(0)))),
    (4, 4, h(h(e(0), e(1)), h(e(2), e(3)))),
    (5, 4, None),  # cut-off due to limit
    (0, 8, h(h(h(z(0), z(0)), z(1)), z(2))),
    (1, 8, h(h(h(e(0), z(0)), z(1)), z(2))),
    (2, 8, h(h(h(e(0), e(1)), z(1)), z(2))),
    (3, 8, h(h(h(e(0), e(1)), h(e(2), z(0))), z(2))),
    (4, 8, h(h(h(e(0), e(1)), h(e(2), e(3))), z(2))),
    (5, 8, h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), z(0)), z(1)))),
    (6, 8, h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(z(0), z(0))))),
    (7, 8, h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), z(0))))),
    (8, 8, h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), e(7))))),
    (9, 8, None),  # cut-off due to limit
    (0, 16, h(h(h(h(z(0), z(0)), z(1)), z(2)), z(3))),
    (1, 16, h(h(h(h(e(0), z(0)), z(1)), z(2)), z(3))),
    (2, 16, h(h(h(h(e(0), e(1)), z(1)), z(2)), z(3))),
    (3, 16, h(h(h(h(e(0), e(1)), h(e(2), z(0))), z(2)), z(3))),
    (4, 16, h(h(h(h(e(0), e(1)), h(e(2), e(3))), z(2)), z(3))),
    (5, 16, h(h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), z(0)), z(1))), z(3))),
    (6, 16, h(h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(z(0), z(0)))), z(3))),
    (7, 16, h(h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), z(0)))), z(3))),
    (8, 16, h(h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), e(7)))), z(3))),
    (
        9,
        16,
        h(
            h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), e(7)))),
            h(h(h(e(8), z(0)), z(1)), z(2)),
        ),
    ),
]


@pytest.mark.parametrize(
    "count,limit,value",
    cases,
)
def test_merkleize_chunks_and_get_merkle_root(count, limit, value):
    chunks = [e(i) for i in range(count)]
    if value is None:
        bad = False
        try:
            merkleize_chunks(chunks, limit=limit)
            bad = True
        except AssertionError:
            pass
        if bad:
            assert False, "expected merkleization to be invalid"
    else:
        # Log input parameters
        print(f"\n=== Test Case: count={count}, limit={limit} ===")
        
        # Log input chunks
        print(f"Input chunks ({len(chunks)}):")
        for i, chunk in enumerate(chunks):
            print(f"  chunk[{i}]: 0x{chunk.hex()}")
        
        # Compute hash and log results
        computed_hash = merkleize_chunks(chunks, limit=limit)
        expected_hash = value
        
        print(f"Computed hash: 0x{computed_hash.hex()}")
        print(f"Expected hash: 0x{expected_hash.hex()}")
        print("=" * 50)
        
        assert computed_hash == expected_hash
        assert get_merkle_root(chunks, pad_to=limit) == expected_hash


# Test cases with chunks provided and mix_in_length applied
mix_in_length_test_cases = [
    # (chunks_list, description)
    ([], "empty chunks array"),
    ([hex_to_bytes("0x4a07d56213d62b2d194a3cc1f19bec40364540bdf3d45eb0d6fe82094d21b4dc")], "single chunk"),
    ([
        hex_to_bytes("0x4a07d56213d62b2d194a3cc1f19bec40364540bdf3d45eb0d6fe82094d21b4dc"),
        hex_to_bytes("0x4833912e1264aef8a18392d795f3f2eed17cf5c0e8471cb0c0db2ec5aca10231"),
    ], "two chunks"),
    ([
        hex_to_bytes("0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71"),
        hex_to_bytes("0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71"),
        hex_to_bytes("0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71"),
    ], "three chunks"),
    ([
        hex_to_bytes("0xfee5527172fd2af098adcdfa5d4108ffc52d19b4cb03fcdb186685a11147fe7b"),
        hex_to_bytes("0xd4c8a4e38ed4d4d09d3b74df1d825d244243218fa2ce1878eeb3d0356ec7fcab"),
        hex_to_bytes("0x3548a86db6940952e5ab87b50e46cfbdb2324603ccfac73836834a87f160181a"),
        hex_to_bytes("0x8ceb740b26a61041ea7dc2d6b1372686cf3381150bd9d9a19cfafeb9e0335c04"),
    ], "four chunks"),
    ([
        hex_to_bytes("0xfee5527172fd2af098adcdfa5d4108ffc52d19b4cb03fcdb186685a11147fe7b"),
        hex_to_bytes("0xd4c8a4e38ed4d4d09d3b74df1d825d244243218fa2ce1878eeb3d0356ec7fcab"),
        hex_to_bytes("0x3548a86db6940952e5ab87b50e46cfbdb2324603ccfac73836834a87f160181a"),
        hex_to_bytes("0x8ceb740b26a61041ea7dc2d6b1372686cf3381150bd9d9a19cfafeb9e0335c04"),
        hex_to_bytes("0xde460e5b596f11e6791d4b658544351a44e8bfc86b0952b8ac655354b399adad"),
    ], "five chunks"),
]


@pytest.mark.parametrize(
    "chunks,description",
    mix_in_length_test_cases,
)
def test_merkleize_chunks_with_mix_in_length(chunks, description):
    """
    Test merkleize_chunks with PENDING_PARTIAL_WITHDRAWALS_LIMIT as limit,
    then apply mix_in_length with actual chunk count.
    """
    limit = PENDING_PARTIAL_WITHDRAWALS_LIMIT
    
    # Verify chunks don't exceed limit
    assert len(chunks) <= limit
    
    # Step 1: Merkleize chunks with limit
    merkle_root = merkleize_chunks(chunks, limit=limit)
    
    # Step 2: Apply mix_in_length with actual chunk count
    actual_length = len(chunks)
    result = mix_in_length(merkle_root, actual_length)
    
    # Verify result is a valid 32-byte hash
    assert len(result) == 32, f"Result should be 32 bytes, got {len(result)}"
    
    # Log results
    print(f"\n=== Test Case: {description} ===")
    print(f"Chunks count: {len(chunks)}")
    print(f"Limit: {limit}")
    print(f"Merkle root: 0x{merkle_root.hex()}")
    print(f"Final result (with mix_in_length): 0x{result.hex()}")
    print("=" * 50)
