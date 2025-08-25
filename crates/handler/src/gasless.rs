use primitives::{Address, B256, U256, b256, keccak256, address, TxKind};
use crate::EvmTr;
use context_interface::ContextTr;
use context_interface::JournalTr;
use context_interface::Transaction;

// pub const CREDITS_USED_TOPIC0: B256 = keccak256(b"CreditsUsed(address,address,uint256,uint256)");

/// Topic0 for CreditsUsed event.
pub fn credits_used_topic0() -> B256 {
    // GUESS WE CAN PRECOMPUTE THIS AND HAVE IT A CONSTANT
    keccak256(b"CreditsUsed(address,address,uint256,uint256)")
}


/// predeploy local for GasStation by default
pub const GAS_STATION_PREDEPLOY: Address = address!("0x4300000000000000000000000000000000000001");


/// Result of keccak256(abi.encode(uint256(keccak256("gasstation.main")) - 1)) & ~bytes32(uint256(0xff));
pub const GAS_STATION_STORAGE_LOCATION: B256 =
    b256!("0x64d1d9a8a451551a9514a2c08ad4e1552ed316d7dd2778a4b9494de741d8e000");

/// Storage slots used by the GasStation contract for a given `to` (recipient)
/// and optional `from`.
#[derive(Clone, Debug)]
pub struct GasStationStorageSlots {
    /// Struct base slot (has registered/active packed).
    pub registered_slot: B256,
    /// TODO REMOVE THIS.
    pub active_slot: B256,
    /// Slot for `credits` balance.
    pub credits_slot: B256,
    /// Base slot for nested `whitelist` mapping.
    pub nested_whitelist_map_base_slot: B256,
    /// Slot for `whitelistEnabled` flag.
    pub whitelist_enabled_slot: B256,
    /// Slot for `singleUseEnabled` flag.
    pub single_use_enabled_slot: B256,
    /// Base slot for nested `usedAddresses` mapping.
    pub used_addresses_map_base_slot: B256,
}

/// calculates the storage slot hashes for a specific registered contract within the GasStation's `contracts` mapping.
/// it returns the base slot for the struct (holding packed fields), the slot for credits,
/// the slot for whitelistEnabled, and the base slot for the nested whitelist mapping.
pub fn calculate_gas_station_slots(registered_contract_address: Address) -> GasStationStorageSlots {
	// The 'contracts' mapping is at offset 1 from the storage location
	// (dao is at offset 0, contracts is at offset 1)
    let contracts_map_slot = U256::from_be_bytes(GAS_STATION_STORAGE_LOCATION.0) + U256::from(1);

    // Calculate the base slot for the struct entry in the mapping
    // - left pad the address to 32 bytes
    let mut key_padded = [0u8; 32];
    key_padded[12..].copy_from_slice(registered_contract_address.as_slice()); // Left-pad 20-byte address to 32 bytes
    // - I expect this is left padded because big endian etc
    let map_slot_padded = contracts_map_slot.to_be_bytes::<32>();
    // - keccak256(append(keyPadded, mapSlotPadded...))
    let combined = [key_padded, map_slot_padded].concat();
    let struct_base_slot_hash = keccak256(combined);

	// Calculate subsequent slots by adding offsets to the base slot hash
	// New struct layout: bool registered, bool active, address admin (all packed in slot 0)
	// uint256 credits (slot 1), bool whitelistEnabled (slot 2), mapping whitelist (slot 3)
	// bool singleUseEnabled (slot 4), mapping usedAddresses (slot 5)
    let struct_base_slot_u256 = U256::from_be_bytes(struct_base_slot_hash.0);

    // Slot for 'credits' (offset 1 from base - after the packed bools and address)
    let credits_slot_u256 = struct_base_slot_u256 + U256::from(1);
    let credit_slot_hash = B256::from_slice(&credits_slot_u256.to_be_bytes::<32>());

    // Slot for 'whitelistEnabled' (offset 2 from base)
    let whitelist_enabled_slot_u256 = struct_base_slot_u256 + U256::from(2);
    let whitelist_enabled_slot_hash = B256::from_slice(&whitelist_enabled_slot_u256.to_be_bytes::<32>());

    // Base slot for the nested 'whitelist' mapping (offset 3 from base)
    let nested_whitelist_map_base_slot_u256 = struct_base_slot_u256 + U256::from(3);
    let nested_whitelist_map_base_slot_hash = B256::from_slice(&nested_whitelist_map_base_slot_u256.to_be_bytes::<32>());

    // Slot for 'singleUseEnabled' (offset 4 from base)
    let single_use_enabled_slot_u256 = struct_base_slot_u256 + U256::from(4);
    let single_use_enabled_slot_hash = B256::from_slice(&single_use_enabled_slot_u256.to_be_bytes::<32>());

    // Base slot for the nested 'usedAddresses' mapping (offset 5 from base)
    let used_addresses_map_base_slot_u256 = struct_base_slot_u256 + U256::from(5);
    let used_addresses_map_base_slot_hash = B256::from_slice(&used_addresses_map_base_slot_u256.to_be_bytes::<32>());

    GasStationStorageSlots {
        registered_slot: struct_base_slot_hash,
        active_slot: struct_base_slot_hash,  
        credits_slot: credit_slot_hash,
        whitelist_enabled_slot: whitelist_enabled_slot_hash,
        single_use_enabled_slot: single_use_enabled_slot_hash,
        nested_whitelist_map_base_slot: nested_whitelist_map_base_slot_hash,
        used_addresses_map_base_slot: used_addresses_map_base_slot_hash,
    }
}

/// Computes the storage slot hash for a nested mapping
pub fn calculate_nested_mapping_slot(key: Address, base_slot: B256) -> B256 {
    // Left-pad the address to 32 bytes
    let mut key_padded = [0u8; 32];
    key_padded[12..].copy_from_slice(key.as_slice()); // Left-pad 20-byte address to 32 bytes
    
    // The base_slot is already 32 bytes (B256)
    let map_base_slot_padded = base_slot.0;
    
    // Combine: key first, then base slot
    let combined = [key_padded, map_base_slot_padded].concat();
    keccak256(combined)
}



/// Applies gasless accounting after execution if the transaction is marked gasless and is a call.
/// Updates credits and single-use flag as needed. Returns an error string on failure.
pub fn apply_gasless_post_execution<EVM: EvmTr>(
    evm: &mut EVM,
    gas_used: u64,
) -> Result<(), String> {
    #[cfg(feature = "optional_gasless")]
    let is_gasless_tx = context_interface::transaction::is_gasless(&evm.ctx().tx());
    #[cfg(not(feature = "optional_gasless"))]
    let is_gasless_tx = false;

    if !is_gasless_tx {
        return Ok(());
    }

    if let TxKind::Call(target_address) = evm.ctx().tx().kind() {
        let gas_station_storage_slots = calculate_gas_station_slots(target_address);
        let (tx, journal) = evm.ctx().tx_journal_mut();
        let caller = tx.caller();

        // Load gas station account and mark as touched
        if journal.load_account(GAS_STATION_PREDEPLOY).is_err() {
            return Err("Failed to load gas station account".to_string());
        }
        journal.touch_account(GAS_STATION_PREDEPLOY);

        // Load available credits and update them based on gas used
        let credits_slot = gas_station_storage_slots.credits_slot.into();
        let available_credits = journal
            .sload(GAS_STATION_PREDEPLOY, credits_slot)
            .unwrap_or_default()
            .data;
        let gas_used_u256 = U256::from(gas_used);
        let new_credits = available_credits.saturating_sub(gas_used_u256);

        if journal
            .sstore(GAS_STATION_PREDEPLOY, credits_slot, new_credits)
            .is_err()
        {
            return Err("Failed to update credits slot".to_string());
        }

        // Check if the contract is single-use and mark caller as used if so
        let single_use_slot = gas_station_storage_slots.single_use_enabled_slot.into();
        let is_single_use = !journal
            .sload(GAS_STATION_PREDEPLOY, single_use_slot)
            .unwrap_or_default()
            .data
            .is_zero();

        if is_single_use {
            // Mark caller as used in the usedAddresses mapping
            let used_slot_b256 = calculate_nested_mapping_slot(
                caller,
                gas_station_storage_slots.used_addresses_map_base_slot,
            );
            let used_slot = used_slot_b256.into();
            if journal
                .sstore(GAS_STATION_PREDEPLOY, used_slot, U256::ONE)
                .is_err()
            {
                return Err("Failed to update usedAddresses slot".to_string());
            }
        }
    }

    Ok(())
}