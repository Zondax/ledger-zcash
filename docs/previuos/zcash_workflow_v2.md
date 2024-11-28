Zcash ledger, first connect:
- Address generation
- Sharing address with host
- Sharing IVK with host

```mermaid
  sequenceDiagram
  participant LF as Ledger flash storage
  participant LC as Ledger computation 
  participant H as Host
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

```mermaid
  sequenceDiagram
  participant LF as Ledger flash storage
  participant LC as Ledger computation 
  participant H as Host
  participant N as Network
  H ->> LC: get_ivk(path: u32)
  activate LC
  LC -->> LF: retrieve_ivk(oath) ?
  LF -->> LC: ivk ?
  Note over LC: compute_ivk(path)
  LC ->> H: ivk
  deactivate LC
  activate H
  H ->> N: get_unspend_notes()
  N ->> H: [unspend_notes]
  Note over H: [matching_notes] = decrypt_all_unspend_notes(ivk, [unspend_notes])
  Note over H: store [matching_notes] (d, pk_d, v, rcm)
  H -->> LC: decrypt_and_verify(ivk, [matching_notes])
  deactivate H
  activate LC
  Note over H,LC: show validation on both screens?
  LC -->> LF: [matching notes] ?
  deactivate LC
```

Zcash ledger, make shielded transaction phase 1
- Verify outputs on screen

```mermaid
  sequenceDiagram
  participant LF as Ledger flash storage
  participant LC as Ledger computation 
  participant H as Host
  participant N as Network

  Note over H: show amount, address, memo-fields per output
  Note over H: validate amount <= total_amount
  H ->> LC: initiate_transaction()


  activate LC
  loop Every output note
  H ->> LC: verify_output(d, pk_d, value, memo)
  Note over H,LC: approve amount and address and verify on screens
  Note over H,LC: approve hash of memo and verify on screens
  LC ->> H: approval of output
  LC ->> LF: store_output_data(d,pk_d,value,memo)
  end
  deactivate LC
  Note over LC,H: continue if all approved
```

  Zcash ledger, make shielded transaction phase 2
- Process outputs and store in flash
- Compute hash of all outputs

```mermaid
  sequenceDiagram
  participant LF as Ledger flash storage
  participant LC as Ledger computation 
  participant H as Host
  participant N as Network
  activate LC
  loop Every output note
  H ->> LC: make_transaction(path)
  Note over LC: compute random rcm
  LC ->> LF: update_rcmnew(rcm)
  LF ->> LC: (d,pk_d,value)
  Note over LC: compute value/note commitments
  LC ->> LF: update_valuecommitsum(vc)
  LC ->> LF: value/note commitments
  LC ->> H: value/note commitments
  LF ->> LC: d,pk_d, value, memo
  Note over LC: compute eph, c_out, c_enc 
  LC ->> LF: eph, c_out, c_enc 
  LC ->> H: eph, c_out, c_enc 
  deactivate LC
  activate H
  H -->> LC: get_proof_key(path) #is this necessary?
  LC -->> H: proof_key
  Note over H: ZK proof of output note
  H ->> LC: zk_proof
  deactivate H
  activate LC
  LC ->> LF: zk_proof
  end
  Note over LC: perform shieldedoutput_hash
  LC ->> H: shielded_output_hash
  LC ->> LF: shielded_output_hash
  deactivate LC
```

Zcash ledger, make shielded transaction phase 3
- Process spends and store in flash
- Store RCM values in flash
- Compute hash of all outputs

```mermaid
  sequenceDiagram
  participant LF as Ledger flash storage
  participant LC as Ledger computation 
  participant H as Host
  participant N as Network
  loop Every spend note
  H ->> LC: spend_this_note(path, valuecommit, rcm, anchor)  # Do we need to verify here that rcm is correct? Is the zkproof of the spend the old one in the blockchain?
  LC ->> LF: (path, valuecommit, anchor)
  LC -->> H: proof_gen_key(path) ? #is this needed

  activate LC
  LC ->> LF: update_rcmvalue(rcm)
  LC ->> LF: update_valuecommitsum(vc)

  note over LC: compute nullifier
  LC ->> H: nullifier
  LC ->> LF: nullifier

  note over LC: compute randomized verification key
  LC ->> H: randomized verification key
  LC ->> LF: (path, randomizer value, randomized verification key)
  deactivate LC

  Note over H: ZK proof of spend note
  H ->> LC: zk_proof
  LC ->> LF: zk_proof

  end
  Note over LC: perform shieldedspend_hash
  LC ->> LF: shieldedspend_hash
  LC ->> H: shieldedspend_hash
```

Zcash ledger, make shielded transaction phase 4
- Host gives all remaining transaction (meta) data
- Ledger does the complete TX_HASH_ALL
- Final approval of transaction?
- Ledger signs the necessary parts and shares with host
- Host sends transaction blob to network

```mermaid
  sequenceDiagram
  participant LF as Ledger flash storage
  participant LC as Ledger computation 
  participant H as Host
  participant N as Network
  
  H -->> N: retrieve meta_data from network?
  N -->> H: meta_data

  H ->> LC: meta_data transaction
  LC ->> LF: meta_data transaction

  Note over LC: compute valuebalance and commitment
  LC ->> LF: valuebalance and commitment
  Note over LF,LC: verify rcm_secretkey/publickey

  Note over LF,LC: perform_tx_hash_all over all data in flash

  LC ->> H: tx_hash_all

  Note over LC,H: final verification/approval of tx before signing?

  LC ->> H: sign(rcm_secretkey, tx_hash_all)
  loop Every spend note
  LF ->> LC: randomized value
  Note over LC: get_secret_key(path)
  Note over LC: sign(sk, randomized value, tx_hash_all)
  LC ->> H: spend_auth_sign
  end

  Note over H: make raw transaction blob
  H ->> N: raw_transaction_blob

```