Zcash ledger, first connect:
- Address generation
- Sharing address with host
- Sharing IVK with host
//TODO: change to APDU API
```mermaid
  sequenceDiagram
  participant LF as Ledger flash storage
  participant LC as Ledger computation 
  participant H as Host (JS)
  participant Z as Zcashtools
  participant N as Network
  H ->> LC: compute_address(path: u32)
  activate LC
  LC -->> LF: store_ivk(ivk) ?
  Note over LF: potentially store (path, IVK)
  LC ->> H: address: (diversifier, pk_d)
  LC ->> H: incoming viewing key: ivk
  deactivate LC
  Note over H,LC: show address on both screens?
```

Zcash ledger, syncing
- Sharing IVK with host
- Decrypt incoming notes and verification note commitments
- TODO: what to do with matching notes?
```mermaid
  sequenceDiagram
  participant LF as Ledger flash storage
  participant LC as Ledger computation 
  participant H as Host (JS)
  participant Z as Zcashtools
  participant N as Network
  H ->> LC: get_ivk(path: u32)
  #add minor confirmation
  activate LC
  LC -->> LF: retrieve_ivk(path) ?
  LF -->> LC: ivk ?
  Note over LC: compute_ivk(path)
  LC ->> H: ivk
  deactivate LC
  activate H
  H ->> N: get_unspend_notes()
  N ->> H: [unspend_notes]
  Note over H: [matching_notes] = decrypt_all_unspend_notes(ivk, [unspend_notes])
  Note over H: store [matching_notes] (d, pk_d, v, rcm)
  deactivate H
```

Zcash ledger, make shielded transaction phase 1
- Verify outputs on screen
- Verify enough balance
- Put relevant data in flash storage

```mermaid
  sequenceDiagram
  participant LF as Ledger flash storage
  participant LC as Ledger computation 
  participant H as Host (JS)
  participant Z as Zcashtools
  participant N as Network

  Note over H: show amount, address, memo-fields per output
  Note over H: Shuffle shielded spends/outputs
  Note over H: Treat change address as regular output
  Note over H: Make sure amount_in - amount_out = tx-fee
  H ->> LC: TX_INPUT_LENGTHS 
  H ->> LC: T_INPUT_DATA 
  H ->> LC: T_OUTPUT_DATA
  H ->> LC: S_SPEND_DATA
  H ->> LC: S_OUTPUT_DATA
  Note over LC,H: check input/outputdata on screen and verify
  Note over LC: Continue if approved
  loop Every transparent input
  LC ->> LF: T_INPUT_DATA
  end

  loop Every transparent output
  LC ->> LF: T_OUTPUT_DATA
  end

  loop Every shielded spend
  Note over LC: Random numbers rcv/alpha
  LC ->> LF: S_SPEND_DATA, RND_DATA
  end

  loop Every shielded output
  Note over LC: Random numbers rcv/rcm/esk
  LC ->> LF: S_OUTPUT_DATA, RND_DATA
  end
```

  Zcash ledger, make shielded transaction phase 2
- Host processes everything, uses zcashtools builder
- Host asks ledger for random values to use
- Host initiates builder

```mermaid
  sequenceDiagram
  participant LF as Ledger flash storage
  participant LC as Ledger computation 
  participant H as Host (JS)
  participant Z as Zcashtools
  participant N as Network
  H ->> Z: builder_init()
  H ->> Z: add_transparent_inputs(txdata)
  H ->> Z: add_transparent_outputs(txdata)
  loop Every shielded spend
  H ->> LC: get_spend_data ()
  LF ->> LC: spend_data
  LC ->> H: proofkey, rnd (rcv/alpha)
  H ->> Z: add_sapling_spend(txdata, proofkey, rnd)
  end

  loop Every shielded output
  H ->> LC: get_output_data ()
  LF ->> LC: output_data
  LC ->> H: rnd (rcv/rcm/esk)
  H ->> Z: add_sapling_output(txdata, rnd)
  end
```


Zcash ledger, make shielded transaction phase 4
- Host gives all remaining transaction data
- Ledger does the complete TX_HASH_ALL
- Ledger signs the necessary parts and shares with host
- Host sends transaction blob to network

```mermaid
  sequenceDiagram
  participant LF as Ledger flash storage
  participant LC as Ledger computation 
  participant H as Host (JS)
  participant Z as Zcashtools
  participant N as Network
  
  H -->> N: retrieve meta_data from network?
  N -->> H: meta_data
  H ->> Z: build()
  Z ->> H: raw_tx_blob

  H ->> LC: t_in_script_data
  H ->> LC: spend_data
  H ->> LC: output_data
  H ->> LC: sighash_data
  
  LF ->> LC: t_output_data
  Note over LC: outputshash = hash(t_output_data)
  Note over LC: check outputshash == sighash_data[outputshash]

  LF ->> LC: valuebalance
  Note over LC: check valuebalance

  Note over LC: check joinsplits (empty)

  loop Every shielded spend
  LF ->> LC: S_SPEND_DATA, RND_DATA
  Note over LC: check spend data (CV, RK, NF)
  end

  loop Every shielded output
  LF ->> LC: S_OUTPUT_DATA, RND_DATA
  Note over LC: check output data (CV, CMU, (ENC_C, ENC_OUT))
  end

  loop Every transparent input
  LF ->> LC: T_INPUT_DATA
  Note over LC: check t_input data (script, script_from_pk, value)
  Note over LC: sighash_all_script = hash_sigall(sighash_data, t_in_script_data)
  Note over LC: secp256k1_sign (sighash_all_script)
  LC ->> LF: transparent_signature
  end

  loop Every shielded spend
  LF ->> LC: S_SPEND_DATA, RND_DATA
  Note over LC: sighash_all (sighash_data)
  Note over LC: jubjub_sign(ask, alpha, sighash_all)
  LC ->> LF: spend_signature
  end
LC ->> H: all_ok

```

Zcash ledger, make shielded transaction phase 5
- Finalize tx

```mermaid
  sequenceDiagram
  participant LF as Ledger flash storage
  participant LC as Ledger computation 
  participant H as Host (JS)
  participant Z as Zcashtools
  participant N as Network
  
  loop Every transparent input
  H ->> LC: next_transparent_signature
  LF ->> LC: transparent_signature
  LC ->> H: transparent_signature
  end
  H ->> Z: add_transparent_signatures(t_signatures)

  loop Every shielded spend
  H ->> LC: next_spend_signature
  LF ->> LC: spend_signature
  LC ->> H: spend_signature
  end
  H ->> Z: add_spend_signatures(s_signatures)

  Z ->> N: send_raw_tx

```